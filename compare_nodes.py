#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点配置对比工具
用于对比转换前后的代理节点配置差异
参照 mihomo 官方文档规范进行验证: https://wiki.metacubex.one/config/
对比所有字段值以及层级结构，并区分合法差异与潜在问题
"""

import yaml
import json
import re
from typing import Dict, List, Any, Set, Tuple, Union
from collections import defaultdict
from pathlib import Path


def is_legitimate_difference(path: str, before_val: Any, after_val: Any, node_type: str) -> Tuple[bool, str]:
    """
    判断是否为合法差异 (根据 mihomo 官方文档规范)
    path: 差异字段路径，例如 'ws-opts.headers.Host'
    返回: (是否合法, 说明)
    """
    
    # 忽略 None 与 空字符串/空字典/空列表 的差异 (通常视为等价)
    if (before_val is None or before_val == "" or before_val == {} or before_val == []) and \
       (after_val is None or after_val == "" or after_val == {} or after_val == []):
        return (True, "None/空值 视为等价")

    # 类型宽松比较 (int vs str) - 比如 port: 443 vs "443", alterId: 0 vs "0"
    if str(before_val) == str(after_val) and \
       isinstance(before_val, (int, str, float)) and isinstance(after_val, (int, str, float)):
        return (True, f"类型差异但值相同 ({type(before_val).__name__} vs {type(after_val).__name__})")

    # VLESS flow 规范化: xtls-rprx-vision-udp443 -> xtls-rprx-vision
    if path == 'flow' and node_type == 'vless':
        if isinstance(before_val, str) and isinstance(after_val, str):
            if before_val.endswith('-udp443') and after_val == before_val.replace('-udp443', ''):
                return (True, "mihomo 中 xtls-rprx-vision 等效于 xray 的 xtls-rprx-vision-udp443")
    
    # 转换后补充字段 (功能增强) 或 默认值变更
    if (before_val is None or before_val == "") and after_val:
        if 'client-fingerprint' in path: 
            return (True, f"转换后补充 TLS 指纹配置: {after_val}")
        if path == 'servername' and node_type == 'vless':
            return (True, f"转换后补充 SNI 配置: {after_val}")
        if path == 'udp' and after_val is True:
             return (True, "转换后显式开启 UDP")
        if 'skip-cert-verify' in path and after_val is False:
             return (True, "转换后显式设置 skip-cert-verify: false")
        
        # ws-opts 相关
        if 'ws-opts' in path:
             if path.endswith('headers.Host'):
                 return (True, f"转换后补充 WebSocket Host 头")
             if path.endswith('max-early-data'):
                 return (True, f"转换后补充 early-data 配置")
        
        # reality-opts 自动补充
        if 'reality-opts' in path:
             if path.endswith('short-id') or path.endswith('fingerprint'):
                  return (True, "补充 Reality 可选参数")

    # 从路径参数 ?ed=N 解析为 early-data
    if 'max-early-data' in path and isinstance(after_val, int):
        # 无法直接访问 ws-opts.path 来验证，但通常这是合法的解析行为
        return (True, "可能从路径参数解析出的 max-early-data")

    # VMess ws-opts 空 headers 差异 (之前脚本的逻辑迁移到路径判断)
    if 'ws-opts.headers' in path:
         if before_val == {} and after_val is None:
             return (True, "空 headers 字典与 None 等价")

    # port 字段
    if path == 'port':
        # 有时候 int 转 str
        if str(before_val) == str(after_val):
            return (True, "端口格式差异")

    # alpn 列表顺序差异或包含关系 (mihomo 可能会重排 alpn)
    if 'alpn' in path and isinstance(before_val, list) and isinstance(after_val, list):
         if set(before_val) == set(after_val):
             return (True, "ALPN 列表顺序差异")

    # 默认值处理
    # encryption: None/empty vs 'none'
    if 'encryption' in path: 
        if (before_val in [None, ""]) and (after_val == 'none'):
             return (True, "加密方式显式设为 none")
        if (before_val == 'none') and (after_val in [None, ""]):
             return (True, "加密方式隐式为 none")

    # network: None/empty vs 'tcp'
    if 'network' in path:
         if (before_val in [None, ""]) and (after_val == 'tcp'):
             return (True, "默认网络类型 tcp")

    # tls: False vs None
    if 'tls' in path:
         if (before_val is False and after_val is None) or (before_val is None and after_val is False):
              return (True, "TLS 默认关闭 (None 等同 False)")
              
    # reality servername 结构调整 (Legacy 模式 -> Standard 模式)
    if path == 'servername' and node_type == 'vless' and after_val is None:
         return (True, "Reality servername 可能已移动至 reality-opts")
    if 'reality-opts.servername' in path and before_val is None:
         return (True, "Reality servername 移动至 reality-opts")

    return (False, "")


def deep_compare(obj1: Any, obj2: Any, path: str = "") -> List[Dict]:
    """
    递归对比两个对象，返回差异列表
    """
    diffs = []
    
    # 类型不一致且不能安全转换为字符串相等的情况
    if type(obj1) != type(obj2):
         is_safe_type_diff = False
         if isinstance(obj1, (int, str, float)) and isinstance(obj2, (int, str, float)):
             if str(obj1) == str(obj2):
                 is_safe_type_diff = True
         
         if not is_safe_type_diff and obj1 is not None and obj2 is not None:
            # 如果一个是 None，后面会在 missing/added 处理，或者这里也可以捕获
            # 这里专门捕获非空的类型差异
             pass # 继续往下走，会作为 modified 捕获

    if isinstance(obj1, dict) and isinstance(obj2, dict):
        keys1 = set(obj1.keys())
        keys2 = set(obj2.keys())
        
        # 转换前有，转换后没有
        for k in keys1 - keys2:
            # 忽略空值
            if obj1[k] in [None, "", [], {}]:
                continue
            new_path = f"{path}.{k}" if path else k
            diffs.append({
                'path': new_path,
                'type': 'missing',
                'before': obj1[k],
                'after': None
            })
            
        # 转换后有，转换前没有
        for k in keys2 - keys1:
            # 忽略空值
            if obj2[k] in [None, "", [], {}]:
                continue
            new_path = f"{path}.{k}" if path else k
            diffs.append({
                'path': new_path,
                'type': 'added',
                'before': None,
                'after': obj2[k]
            })
            
        # 都有，递归对比
        for k in keys1 & keys2:
            new_path = f"{path}.{k}" if path else k
            diffs.extend(deep_compare(obj1[k], obj2[k], new_path))
            
    elif isinstance(obj1, list) and isinstance(obj2, list):
        # 列表对比策略：
        # 简单处理：如果内容不同，报差异
        if obj1 != obj2:
             # 尝试检查是否只是顺序不同 (针对简单类型)
            try:
                if set(obj1) == set(obj2):
                    # 虽然相等但顺序不同，如果不严格要求顺序，可以在 is_legitimate 中处理
                    # 这里先报 diff
                    pass
            except TypeError:
                pass # 不可哈希

            diffs.append({
                'path': path,
                'type': 'modified',
                'before': obj1,
                'after': obj2
            })
            
    else:
        # 标量对比
        vals_are_equal = (obj1 == obj2)
        if not vals_are_equal and isinstance(obj1, (int, str, float)) and isinstance(obj2, (int, str, float)):
             if str(obj1) == str(obj2):
                 vals_are_equal = True
        
        # 忽略 None vs "" 等价
        if not vals_are_equal:
             if (obj1 is None or obj1 == "") and (obj2 is None or obj2 == ""):
                 vals_are_equal = True

        if not vals_are_equal:
            diffs.append({
                'path': path,
                'type': 'modified',
                'before': obj1,
                'after': obj2
            })
            
    return diffs


def load_file(filepath: str) -> Dict:
    """加载YAML文件"""
    import re
    if not Path(filepath).exists():
        raise FileNotFoundError(f"文件未找到: {filepath}")
        
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        # 将 !<str> 和 !str 标签都转换为标准的 !!str
        content = re.sub(r'!\s*<?\s*str\s*>?', '!!str', content)
        return yaml.safe_load(content)


def compare_nodes(before: Dict, after: Dict) -> Dict:
    """对比节点差异"""
    before_nodes = before.get('proxies', [])
    after_nodes = after.get('proxies', [])
    
    # 检测重复节点名称
    before_names_count = {}
    for node in before_nodes:
        name = node.get('name', 'UNKNOWN')
        before_names_count[name] = before_names_count.get(name, 0) + 1
    
    after_names_count = {}
    for node in after_nodes:
        name = node.get('name', 'UNKNOWN')
        after_names_count[name] = after_names_count.get(name, 0) + 1
    
    # 报告重复节点
    duplicates_before = [name for name, count in before_names_count.items() if count > 1]
    duplicates_after = [name for name, count in after_names_count.items() if count > 1]
    
    if duplicates_before:
        print(f"\n⚠️  警告: 转换前文件中发现 {len(duplicates_before)} 个重复节点名称:")
        for name in duplicates_before[:5]:
            print(f"  - {name} (出现 {before_names_count[name]} 次)")
    
    if duplicates_after:
        print(f"\n⚠️  警告: 转换后文件中发现 {len(duplicates_after)} 个重复节点名称:")
        for name in duplicates_after[:5]:
            print(f"  - {name} (出现 {after_names_count[name]} 次)")
    
    # 按名称索引 (对于重复节点,使用 name_type_index 作为唯一key)
    def make_node_map(nodes):
        node_map = {}
        name_counters = {}
        for node in nodes:
            name = node.get('name', 'UNKNOWN')
            node_type = node.get('type', 'unknown')
            counter = name_counters.get(name, 0)
            name_counters[name] = counter + 1
            
            if counter == 0:
                key = name
            else:
                key = f"{name}###{node_type}###{counter}"
            node_map[key] = node
        return node_map

    before_dict = make_node_map(before_nodes)
    after_dict = make_node_map(after_nodes)
    
    before_keys = set(before_dict.keys())
    after_keys = set(after_dict.keys())
    
    stats = {
        'total_before': len(before_nodes),
        'total_after': len(after_nodes),
        'missing': list(before_keys - after_keys),
        'new': list(after_keys - before_keys),
        'common': list(before_keys & after_keys),
    }
    
    # 对比公共节点的差异
    differences = defaultdict(list)
    field_diffs = defaultdict(int)
    type_issues = defaultdict(list)
    legitimate_diffs = defaultdict(list)
    actual_issues = defaultdict(list)
    
    for key in stats['common']:
        before_node = before_dict[key]
        after_node = after_dict[key]
        node_name = before_node.get('name', key)
        node_type = before_node.get('type', 'unknown')
        
        # 使用 Deep Compare
        diffs = deep_compare(before_node, after_node)
        
        if diffs:
            node_diff_record = {
                'name': node_name,
                'type': node_type,
                'diffs': {},
                'legitimate': {},
                'issues': {}
            }
            
            for d in diffs:
                path = d['path']
                before_val = d['before']
                after_val = d['after']
                
                is_legit, reason = is_legitimate_difference(path, before_val, after_val, node_type)
                
                record = {
                    'path': path,
                    'before': before_val,
                    'after': after_val,
                    'type': d['type']
                }
                
                if is_legit:
                     record['reason'] = reason
                     node_diff_record['legitimate'][path] = record
                     legitimate_diffs[node_type].append({
                         'name': node_name,
                         'field': path,
                         'before': before_val,
                         'after': after_val,
                         'reason': reason
                     })
                else:
                     node_diff_record['issues'][path] = record
                     actual_issues[node_type].append({
                         'name': node_name,
                         'field': path,
                         'before': before_val,
                         'after': after_val
                     })
                
                # 统计
                field_diffs[path] += 1
                type_issues[node_type].append({
                    'name': node_name,
                    'field': path,
                    'before': before_val,
                    'after': after_val,
                    'is_legitimate': is_legit,
                    'reason': reason if is_legit else ''
                })
                
                node_diff_record['diffs'][path] = record

            differences[node_type].append(node_diff_record)
    
    return {
        'stats': stats,
        'differences': dict(differences),
        'field_diffs': dict(field_diffs),
        'type_issues': dict(type_issues),
        'legitimate_diffs': dict(legitimate_diffs),
        'actual_issues': dict(actual_issues)
    }


def print_report(result: Dict):
    """打印对比报告"""
    stats = result['stats']
    
    print("=" * 80)
    print("节点转换前后对比报告 (深度对比模式)")
    print("=" * 80)
    print(f"转换前节点总数: {stats['total_before']}")
    print(f"转换后节点总数: {stats['total_after']}")
    print(f"公共节点数量: {len(stats['common'])}")
    print(f"缺失节点数量: {len(stats['missing'])}")
    print(f"新增节点数量: {len(stats['new'])}")
    print()
    
    total_legitimate = sum(len(diffs) for diffs in result.get('legitimate_diffs', {}).values())
    total_actual = sum(len(issues) for issues in result.get('actual_issues', {}).values())
    total_diffs = sum(result['field_diffs'].values())
    
    print("=" * 80)
    print("差异分类汇总")
    print("=" * 80)
    print(f"总差异数量: {total_diffs}")
    print(f"  ✅ 合法差异 (符合 mihomo 规范/预期): {total_legitimate}")
    print(f"  ⚠️  需要关注的差异: {total_actual}")
    print()
    
    # 字段差异统计 (Top 10)
    print("=" * 80)
    print("Top 20 字段差异统计")
    print("=" * 80)
    sorted_fields = sorted(result['field_diffs'].items(), key=lambda x: x[1], reverse=True)
    for field, count in sorted_fields[:20]:
        print(f"{field:50s}: {count:5d} 次")
    if len(sorted_fields) > 20:
        print(f"... 还有 {len(sorted_fields) - 20} 个字段存在差异")
    print()

    # 实际问题展示
    if result.get('actual_issues'):
        print("=" * 80)
        print("⚠️  需要关注的差异详情 (可能需要修复)")
        print("=" * 80)
        for node_type, issues in sorted(result['actual_issues'].items()):
            if issues:
                print(f"\n【{node_type}】类型节点 - {len(issues)} 个差异")
                print("-" * 80)
                
                # 仅展示前 5 个
                for i, issue in enumerate(issues[:5], 1):
                    print(f"\n  {i}. 节点: {issue['name']}")
                    print(f"     路径: {issue['field']}")
                    print(f"     前: {issue['before']}")
                    print(f"     后: {issue['after']}")
                
                if len(issues) > 5:
                    print(f"\n  ... (隐藏其余 {len(issues)-5} 个差异)")
    else:
        print("\n🎉 未发现需要关注的差异 (所有差异均判断为合法)")

    # 质量评估
    print("\n" + "=" * 80)
    print("📊 转换质量评估")
    print("=" * 80)
    if total_diffs > 0:
        quality_score = (total_legitimate / total_diffs) * 100
        print(f"一致性得分: {quality_score:.1f}%")
        if quality_score == 100:
            print("评价: 完美转换")
        elif quality_score >= 90:
             print("评价: 优秀")
        elif quality_score >= 70:
             print("评价: 良好")
        else:
             print("评价: 需注意")
    else:
        print("完美一致！(无任何差异)")

    # mihomo 文档参考
    print("\n" + "=" * 80)
    print("📚 参考文档")
    print("=" * 80)
    print("\nmihomo 官方文档: https://wiki.metacubex.one/config/")
    print("  - 传输层配置: https://wiki.metacubex.one/config/proxies/transport/")

def main():
    base = Path(__file__).resolve().parent
    before_file = base / '转换前'
    after_file = base / '转换后'
    
    print(f"工作目录: {base}")
    if not before_file.exists() or not after_file.exists():
        print("错误: 找不到 '转换前' 或 '转换后' 文件，请确保它们在脚本同目录下。")
        return

    print("正在加载文件...")
    try:
        before = load_file(str(before_file))
        after = load_file(str(after_file))
        
        print("正在进行深度对比...")
        result = compare_nodes(before, after)
        
        print_report(result)
        
        report_file = base / 'comparison_report.json'
        # Convert non-serializable objects if any (usually basic types handled by json)
        with open(str(report_file), 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n详细 JSON 报告已保存到: {report_file}")
        
    except Exception as e:
        print(f"运行出错: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
