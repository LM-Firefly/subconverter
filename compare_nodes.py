#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点配置对比工具
用于对比转换前后的代理节点配置差异
参照 mihomo 官方文档规范进行验证
"""

import yaml
import json
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
from pathlib import Path


def is_legitimate_difference(field: str, before_val: Any, after_val: Any, node_type: str) -> Tuple[bool, str]:
    """
    判断是否为合法差异 (根据 mihomo 官方文档规范)
    返回: (是否合法, 说明)
    """
    
    # VMess ws-opts 空 headers 差异
    if field == 'ws-opts' and node_type == 'vmess':
        if isinstance(before_val, dict) and isinstance(after_val, dict):
            before_headers = before_val.get('headers', None)
            after_headers = after_val.get('headers', None)
            # 空字典 {} 和 不存在字段 功能相同
            if before_headers == {} and after_headers is None:
                before_copy = before_val.copy()
                after_copy = after_val.copy()
                before_copy.pop('headers', None)
                after_copy.pop('headers', None)
                if before_copy == after_copy:
                    return (True, "ws-opts.headers: {} 与省略该字段功能相同")
    
    # VLESS flow 规范化: xtls-rprx-vision-udp443 -> xtls-rprx-vision
    if field == 'flow' and node_type == 'vless':
        if isinstance(before_val, str) and isinstance(after_val, str):
            if before_val.endswith('-udp443') and after_val == before_val.replace('-udp443', ''):
                return (True, "mihomo 中 xtls-rprx-vision 等效于 xray 的 xtls-rprx-vision-udp443")
    
    # 转换后补充字段 (功能增强)
    if not before_val and after_val:
        if field == 'client-fingerprint' and node_type in ['vless', 'vmess', 'trojan']:
            return (True, f"转换后补充 TLS 指纹配置: {after_val}")
        if field == 'servername' and node_type == 'vless':
            return (True, f"转换后补充 SNI 配置: {after_val}")
        if field == 'ws-opts' and isinstance(after_val, dict):
            # 检查是否只是补充了 headers.Host
            if 'headers' in after_val and 'Host' in after_val.get('headers', {}):
                return (True, f"转换后补充 WebSocket Host 头")
            # 检查是否补充了 early-data 配置
            if 'max-early-data' in after_val:
                return (True, f"转换后补充 early-data 配置")

    # 从路径参数 ?ed=N 解析为 early-data (例如 /path?ed=2048 -> max-early-data:2048)
    if field == 'ws-opts' and isinstance(before_val, dict) and isinstance(after_val, dict):
        try:
            import re
            path = (before_val.get('path') or '') if isinstance(before_val.get('path'), str) else ''
            m = re.search(r'[?&]ed=(\d+)', path)
            if m and 'max-early-data' in after_val:
                try:
                    ed_val = int(m.group(1))
                except Exception:
                    ed_val = None
                # 如果解析出的值与转换后字段一致或转换后字段存在，则视为合法
                if ed_val is None or after_val.get('max-early-data') == ed_val:
                    return (True, "从路径参数 ?ed=N 正确解析为标准的 max-early-data 配置")
        except Exception:
            pass
    
    return (False, "")


def load_file(filepath: str) -> Dict:
    """加载YAML文件"""
    import re
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        # 将 !<str> 和 !str 标签都转换为标准的 !!str
        content = re.sub(r'!\s*<?\s*str\s*>?', '!!str', content)
        return yaml.safe_load(content)


def normalize_node(node: Dict) -> Dict:
    """标准化节点字段"""
    # 提取核心字段
    normalized = {
        'name': node.get('name', ''),
        'type': node.get('type', ''),
        'server': node.get('server', ''),
        'port': node.get('port', 0),
    }
    
    # 添加协议特定字段
    if node.get('type') == 'vless':
        normalized.update({
            'uuid': node.get('uuid', ''),
            'tls': node.get('tls', False),
            'network': node.get('network', ''),
            'flow': node.get('flow', ''),
            'client-fingerprint': node.get('client-fingerprint', ''),
            'skip-cert-verify': node.get('skip-cert-verify', None),
        })
        if node.get('network') == 'ws':
            normalized['ws-opts'] = node.get('ws-opts', {})
        if node.get('tls'):
            # Reality节点特殊处理: servername应该在reality-opts内
            if 'reality-opts' in node:
                reality_opts = node.get('reality-opts', {}).copy()
                # 如果顶层有servername但reality-opts内没有,迁移过去
                if 'servername' not in reality_opts and node.get('servername'):
                    reality_opts['servername'] = node.get('servername')
                normalized['reality-opts'] = reality_opts
            else:
                # 非Reality节点,正常处理servername
                normalized['servername'] = node.get('servername', '')
            if 'alpn' in node:
                normalized['alpn'] = node.get('alpn', [])
    
    elif node.get('type') == 'vmess':
        normalized.update({
            'uuid': node.get('uuid', ''),
            'alterId': node.get('alterId', 0),
            'cipher': node.get('cipher', ''),
            'tls': node.get('tls', False),
            'network': node.get('network', ''),
            'skip-cert-verify': node.get('skip-cert-verify', None),
        })
        if node.get('network') == 'ws':
            normalized['ws-opts'] = node.get('ws-opts', {})
        if node.get('tls'):
            normalized['servername'] = node.get('servername', '')
    
    elif node.get('type') == 'trojan':
        normalized.update({
            'password': node.get('password', ''),
            'sni': node.get('sni', ''),
            'skip-cert-verify': node.get('skip-cert-verify', None),
            'network': node.get('network', ''),
            'udp': node.get('udp', None),
        })
        if node.get('network') == 'ws':
            normalized['ws-opts'] = node.get('ws-opts', {})
        if 'alpn' in node:
            normalized['alpn'] = node.get('alpn', [])
    
    elif node.get('type') == 'ss':
        normalized.update({
            'cipher': node.get('cipher', ''),
            'password': node.get('password', ''),
        })
    
    elif node.get('type') == 'ssr':
        normalized.update({
            'cipher': node.get('cipher', ''),
            'password': node.get('password', ''),
            'protocol': node.get('protocol', ''),
            'obfs': node.get('obfs', ''),
            'protocol-param': node.get('protocol-param', ''),
            'obfs-param': node.get('obfs-param', ''),
        })
    
    elif node.get('type') == 'hysteria2':
        normalized.update({
            'password': node.get('password', ''),
            'auth': node.get('auth', ''),
            'sni': node.get('sni', ''),
            'skip-cert-verify': node.get('skip-cert-verify', None),
        })
    
    elif node.get('type') == 'http':
        normalized.update({
            'username': node.get('username', ''),
            'password': node.get('password', ''),
            'tls': node.get('tls', False),
            'skip-cert-verify': node.get('skip-cert-verify', None),
            'dialer-proxy': node.get('dialer-proxy', ''),
        })
    
    return normalized


def compare_nodes(before: Dict, after: Dict) -> Dict:
    """对比节点差异"""
    before_nodes = before.get('proxies', [])
    after_nodes = after.get('proxies', [])
    
    # 检测重复节点名称
    before_names_count = {}
    for node in before_nodes:
        name = node['name']
        before_names_count[name] = before_names_count.get(name, 0) + 1
    
    after_names_count = {}
    for node in after_nodes:
        name = node['name']
        after_names_count[name] = after_names_count.get(name, 0) + 1
    
    # 报告重复节点
    duplicates_before = [name for name, count in before_names_count.items() if count > 1]
    duplicates_after = [name for name, count in after_names_count.items() if count > 1]
    
    if duplicates_before:
        print(f"\n⚠️  警告: 转换前文件中发现 {len(duplicates_before)} 个重复节点名称:")
        for name in duplicates_before[:5]:
            print(f"  - {name} (出现 {before_names_count[name]} 次)")
        if len(duplicates_before) > 5:
            print(f"  ... 还有 {len(duplicates_before) - 5} 个重复节点")
    
    if duplicates_after:
        print(f"\n⚠️  警告: 转换后文件中发现 {len(duplicates_after)} 个重复节点名称:")
        for name in duplicates_after[:5]:
            print(f"  - {name} (出现 {after_names_count[name]} 次)")
        if len(duplicates_after) > 5:
            print(f"  ... 还有 {len(duplicates_after) - 5} 个重复节点")
    
    # 按名称索引 (对于重复节点,使用 name_type_index 作为唯一key)
    before_dict = {}
    before_name_counters = {}
    for node in before_nodes:
        name = node['name']
        node_type = node.get('type', 'unknown')
        counter = before_name_counters.get(name, 0)
        before_name_counters[name] = counter + 1
        
        if counter == 0:
            key = name
        else:
            key = f"{name}###{node_type}###{counter}"
        before_dict[key] = node
    
    after_dict = {}
    after_name_counters = {}
    for node in after_nodes:
        name = node['name']
        node_type = node.get('type', 'unknown')
        counter = after_name_counters.get(name, 0)
        after_name_counters[name] = counter + 1
        
        if counter == 0:
            key = name
        else:
            key = f"{name}###{node_type}###{counter}"
        after_dict[key] = node
    
    before_names = set(before_dict.keys())
    after_names = set(after_dict.keys())
    
    # 统计
    stats = {
        'total_before': len(before_nodes),
        'total_after': len(after_nodes),
        'missing': list(before_names - after_names),
        'new': list(after_names - before_names),
        'common': list(before_names & after_names),
    }
    
    # 对比公共节点的差异
    differences = defaultdict(list)
    field_diffs = defaultdict(int)
    type_issues = defaultdict(list)
    legitimate_diffs = defaultdict(list)  # 合法差异
    actual_issues = defaultdict(list)      # 实际问题
    
    for name in stats['common']:
        before_node = normalize_node(before_dict[name])
        after_node = normalize_node(after_dict[name])
        
        node_diff = {
            'name': name,
            'type': before_node.get('type'),
            'diffs': {},
            'legitimate': {},
            'issues': {}
        }
        
        # 对比每个字段
        all_keys = set(before_node.keys()) | set(after_node.keys())
        for key in all_keys:
            before_val = before_node.get(key)
            after_val = after_node.get(key)
            
            if before_val != after_val:
                node_type = before_node.get('type', 'unknown')
                is_legit, reason = is_legitimate_difference(key, before_val, after_val, node_type)
                
                diff_info = {
                    'before': before_val,
                    'after': after_val
                }
                
                if is_legit:
                    node_diff['legitimate'][key] = diff_info
                    diff_info['reason'] = reason
                    legitimate_diffs[node_type].append({
                        'name': name,
                        'field': key,
                        'before': before_val,
                        'after': after_val,
                        'reason': reason
                    })
                else:
                    node_diff['issues'][key] = diff_info
                    actual_issues[node_type].append({
                        'name': name,
                        'field': key,
                        'before': before_val,
                        'after': after_val
                    })
                
                node_diff['diffs'][key] = diff_info
                field_diffs[key] += 1
                
                # 按节点类型分类 (保持向后兼容)
                type_issues[node_type].append({
                    'name': name,
                    'field': key,
                    'before': before_val,
                    'after': after_val,
                    'is_legitimate': is_legit,
                    'reason': reason if is_legit else ''
                })
        
        if node_diff['diffs']:
            differences[before_node.get('type', 'unknown')].append(node_diff)
    
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
    print("节点转换前后对比报告")
    print("=" * 80)
    print()
    
    print(f"转换前节点总数: {stats['total_before']}")
    print(f"转换后节点总数: {stats['total_after']}")
    print(f"公共节点数量: {len(stats['common'])}")
    print(f"缺失节点数量: {len(stats['missing'])}")
    print(f"新增节点数量: {len(stats['new'])}")
    print()
    
    # 统计合法差异和实际问题
    total_legitimate = sum(len(diffs) for diffs in result.get('legitimate_diffs', {}).values())
    total_actual = sum(len(issues) for issues in result.get('actual_issues', {}).values())
    total_diffs = sum(result['field_diffs'].values())
    
    print("=" * 80)
    print("差异分类汇总")
    print("=" * 80)
    print(f"总差异数量: {total_diffs}")
    print(f"  ✅ 合法差异 (符合 mihomo 规范): {total_legitimate}")
    print(f"  ⚠️  需要关注的差异: {total_actual}")
    print()
    
    # 字段差异统计
    print("=" * 80)
    print("字段差异统计 (出现次数)")
    print("=" * 80)
    for field, count in sorted(result['field_diffs'].items(), key=lambda x: x[1], reverse=True):
        print(f"{field:30s}: {count:5d} 次")
    print()
    
    # 合法差异说明
    if result.get('legitimate_diffs'):
        print("=" * 80)
        print("✅ 合法差异说明 (符合 mihomo 官方规范)")
        print("=" * 80)
        for node_type, diffs in sorted(result['legitimate_diffs'].items()):
            if diffs:
                print(f"\n【{node_type}】类型 - {len(diffs)} 个合法差异")
                print("-" * 80)
                
                # 按原因分组
                reason_groups = defaultdict(list)
                for diff in diffs:
                    reason_groups[diff['reason']].append(diff)
                
                for reason, items in reason_groups.items():
                    print(f"\n  📌 {reason}")
                    print(f"     影响节点: {len(items)} 个")
                    if len(items) <= 3:
                        for item in items:
                            print(f"       - {item['name']}")
                    else:
                        for item in items[:2]:
                            print(f"       - {item['name']}")
                        print(f"       ... 还有 {len(items) - 2} 个节点")
        print()
    
    # 按节点类型分类的实际问题
    if result.get('actual_issues'):
        print("=" * 80)
        print("⚠️  需要关注的差异 (可能需要修复)")
        print("=" * 80)
        for node_type, issues in sorted(result['actual_issues'].items()):
            if issues:
                print(f"\n【{node_type}】类型节点 - {len(issues)} 个需要关注的差异")
                print("-" * 80)
                
                # 统计字段
                field_counts = defaultdict(int)
                for issue in issues:
                    field_counts[issue['field']] += 1
                
                print(f"  差异字段: {dict(field_counts)}")
                
                # 显示示例
                print(f"\n  示例 (最多显示3个):")
                for i, issue in enumerate(issues[:3], 1):
                    print(f"\n  {i}. 节点: {issue['name']}")
                    print(f"     字段: {issue['field']}")
                    print(f"     转换前: {issue['before']}")
                    print(f"     转换后: {issue['after']}")
        print()
    
    # 按节点类型分类的所有差异 (详细列表)
    print("=" * 80)
    print("按节点类型分类的所有差异 (详细)")
    print("=" * 80)
    for node_type, issues in sorted(result['type_issues'].items()):
        print(f"\n【{node_type}】类型节点 - {len(issues)} 个差异")
        print("-" * 80)
        
        # 统计这个类型中哪些字段出现问题
        field_counts = defaultdict(int)
        for issue in issues:
            field_counts[issue['field']] += 1
        
        print(f"  差异字段: {dict(field_counts)}")
        
        # 显示前5个示例
        print(f"\n  示例 (最多显示5个):")
        for i, issue in enumerate(issues[:5], 1):
            is_legit = issue.get('is_legitimate', False)
            status = "✅" if is_legit else "⚠️"
            print(f"\n  {i}. {status} 节点: {issue['name']}")
            print(f"     字段: {issue['field']}")
            print(f"     转换前: {issue['before']}")
            print(f"     转换后: {issue['after']}")
            if is_legit and issue.get('reason'):
                print(f"     说明: {issue['reason']}")
    
    print("\n" + "=" * 80)
    print("📊 转换质量评估")
    print("=" * 80)
    
    # 计算转换质量
    if total_diffs > 0:
        quality_score = (total_legitimate / total_diffs) * 100
        print(f"\n转换质量得分: {quality_score:.1f}%")
        print(f"  - 合法差异 (符合规范): {total_legitimate} 项")
        print(f"  - 需要关注: {total_actual} 项")
        
        if quality_score >= 95:
            print("\n✅ 转换质量: 优秀")
            print("   绝大部分差异都符合 mihomo 官方规范,转换逻辑正确")
        elif quality_score >= 80:
            print("\n✅ 转换质量: 良好")
            print("   大部分差异符合规范,少量需要确认的差异")
        elif quality_score >= 60:
            print("\n⚠️  转换质量: 一般")
            print("   存在较多需要关注的差异,建议检查转换逻辑")
        else:
            print("\n❌ 转换质量: 需要改进")
            print("   存在大量差异,需要仔细检查转换逻辑")
    
    print("\n" + "=" * 80)
    print("🔍 针对性建议")
    print("=" * 80)
    
    # 基于实际问题给出建议
    actual_issues = result.get('actual_issues', {})
    
    if not actual_issues or all(len(issues) == 0 for issues in actual_issues.values()):
        print("\n🎉 太好了! 所有差异都是合法的,无需修复!")
        print("   所有转换后的节点都符合 mihomo 官方文档规范。")
    else:
        suggestions = []
        
        # 针对实际问题给建议
        for node_type, issues in actual_issues.items():
            if not issues:
                continue
                
            field_counts = defaultdict(int)
            for issue in issues:
                field_counts[issue['field']] += 1
            
            for field, count in field_counts.items():
                if field == 'ws-opts':
                    if node_type == 'trojan':
                        suggestions.append(f"⚠️  Trojan WebSocket 配置: {count} 个节点的 ws-opts 差异")
                        suggestions.append(f"   建议: 检查转换前是否缺失 headers.Host,转换后补充是否正确")
                    elif node_type == 'vmess':
                        suggestions.append(f"⚠️  VMess Early-Data 配置: {count} 个节点")
                        suggestions.append(f"   建议: 确认 early-data 参数解析是否符合预期")
                elif field == 'port':
                    suggestions.append(f"⚠️  {node_type} 端口字段: {count} 个节点存在差异")
                    suggestions.append(f"   建议: 检查端口号解析和导出逻辑")
                elif field == 'uuid':
                    suggestions.append(f"⚠️  {node_type} UUID 字段: {count} 个节点存在差异")
                    suggestions.append(f"   建议: 检查 UUID 格式化处理")
                elif field == 'password':
                    suggestions.append(f"⚠️  {node_type} 密码字段: {count} 个节点存在差异")
                    suggestions.append(f"   建议: 检查密码编码和特殊字符处理")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"\n{suggestion}")
        else:
            print("\n💡 发现少量差异,建议人工确认是否为预期行为")
    
    # mihomo 文档参考
    print("\n" + "=" * 80)
    print("📚 参考文档")
    print("=" * 80)
    print("\nmihomo 官方文档: https://wiki.metacubex.one/config/")
    print("  - 出站代理配置: https://wiki.metacubex.one/config/proxies/")
    print("  - VLESS 协议: https://wiki.metacubex.one/config/proxies/vless/")
    print("  - VMess 协议: https://wiki.metacubex.one/config/proxies/vmess/")
    print("  - Trojan 协议: https://wiki.metacubex.one/config/proxies/trojan/")
    print("  - TLS 配置: https://wiki.metacubex.one/config/proxies/tls/")
    print("  - 传输层配置: https://wiki.metacubex.one/config/proxies/transport/")
    
    print("\n" + "=" * 80)


def main():
    # 使用相对路径 (相对于本脚本文件所在目录)
    base = Path(__file__).resolve().parent
    before_file = base / '转换前'
    after_file = base / '转换后'
    
    print("正在加载文件...")
    try:
        before = load_file(str(before_file))
        after = load_file(str(after_file))
        
        print("正在对比节点...")
        result = compare_nodes(before, after)
        
        print_report(result)
        
        # 保存详细报告到 JSON 文件 (相对于脚本目录)
        report_file = base / 'comparison_report.json'
        with open(str(report_file), 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n详细报告已保存到: {report_file}")
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
