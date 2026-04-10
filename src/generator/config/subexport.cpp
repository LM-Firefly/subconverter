#include <algorithm>
#include <iostream>
#include <numeric>
#include <cmath>
#include <climits>
#include <cctype>
#include <unordered_set>

#include "config/regmatch.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "handler/settings.h"
#include "parser/config/proxy.h"
#include "script/script_quickjs.h"
#include "utils/bitwise.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "nodemanip.h"
#include "ruleconvert.h"

extern string_array ss_ciphers, ssr_ciphers;

const string_array clashr_protocols = {"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"};
const string_array clashr_obfs = {"plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"};
const string_array clash_ssr_ciphers = {"rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "chacha20-ietf", "xchacha20", "none"};

static void applyEncodedHeaders(const std::string &encoded, YAML::Node headersNode)
{
    if(encoded.empty())
        return;
    const auto pairs = split(encoded, ";");
    for(const auto &pair : pairs)
    {
        if(pair.empty())
            continue;
        const auto pos = pair.find('=');
        if(pos == std::string::npos)
            continue;
        const auto key = urlDecode(pair.substr(0, pos));
        const auto value = urlDecode(pair.substr(pos + 1));
        if(key.empty())
            continue;
        headersNode[key] = value;
    }
}

static void applyEncodedHeadersMultiValue(const std::string &encoded, YAML::Node headersNode)
{
    if(encoded.empty())
        return;
    const auto pairs = split(encoded, ";");
    for(const auto &pair : pairs)
    {
        if(pair.empty())
            continue;
        const auto pos = pair.find('=');
        if(pos == std::string::npos)
            continue;
        const auto key = urlDecode(pair.substr(0, pos));
        const auto value = urlDecode(pair.substr(pos + 1));
        if(key.empty())
            continue;
        headersNode[key].push_back(value);
    }
}

std::string vmessLinkConstruct(const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &path, const std::string &host, const std::string &tls, const std::string &sni = "", const std::string &alpn = "", const std::string &fp = "", const std::string &skip_cert_verify = "", const std::string &udp = "", const std::string &tfo = "", const std::string &ip_version = "", const std::string &packet_encoding = "", const std::string &authenticated_length = "", const std::string &global_padding = "", const std::string &ech_enable = "", const std::string &ech_config = "", const std::string &client_fingerprint = "")
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.Key("v");
    writer.String("2");
    writer.Key("ps");
    writer.String(remarks.data());
    writer.Key("add");
    writer.String(add.data());
    writer.Key("port");
    writer.String(port.data());
    writer.Key("type");
    writer.String(type.empty() ? "none" : type.data());
    writer.Key("id");
    writer.String(id.data());
    writer.Key("aid");
    writer.String(aid.data());
    writer.Key("net");
    writer.String(net.empty() ? "tcp" : net.data());
    writer.Key("path");
    writer.String(path.data());
    writer.Key("host");
    writer.String(host.data());
    writer.Key("tls");
    writer.String(tls.data());
    if(!sni.empty())
    {
        writer.Key("sni");
        writer.String(sni.data());
    }
    if(!alpn.empty())
    {
        writer.Key("alpn");
        writer.String(alpn.data());
    }
    if(!fp.empty())
    {
        writer.Key("fp");
        writer.String(fp.data());
    }
    if(!skip_cert_verify.empty())
    {
        writer.Key("skip-cert-verify");
        writer.String(skip_cert_verify.data());
    }
    if(!udp.empty())
    {
        writer.Key("udp");
        writer.String(udp.data());
    }
    if(!tfo.empty())
    {
        writer.Key("tfo");
        writer.String(tfo.data());
    }
    if(!ip_version.empty())
    {
        writer.Key("ip-version");
        writer.String(ip_version.data());
    }
    if(!packet_encoding.empty())
    {
        writer.Key("packet-encoding");
        writer.String(packet_encoding.data());
    }
    if(!authenticated_length.empty())
    {
        writer.Key("authenticated-length");
        writer.String(authenticated_length.data());
    }
    if(!global_padding.empty())
    {
        writer.Key("global-padding");
        writer.String(global_padding.data());
    }
    if(!ech_enable.empty())
    {
        writer.Key("ech-enable");
        writer.String(ech_enable.data());
    }
    if(!ech_config.empty())
    {
        writer.Key("ech-config");
        writer.String(ech_config.data());
    }
    if(!client_fingerprint.empty())
    {
        writer.Key("client-fingerprint");
        writer.String(client_fingerprint.data());
    }
    writer.EndObject();
    return sb.GetString();
}

bool matchRange(const std::string &range, int target)
{
    string_array vArray = split(range, ",");
    bool match = false;
    std::string range_begin_str, range_end_str;
    int range_begin, range_end;
    static const std::string reg_num = "-?\\d+", reg_range = "(\\d+)-(\\d+)", reg_not = "\\!-?(\\d+)", reg_not_range = "\\!(\\d+)-(\\d+)", reg_less = "(\\d+)-", reg_more = "(\\d+)\\+";
    for(std::string &x : vArray)
    {
        if(regMatch(x, reg_num))
        {
            if(to_int(x, INT_MAX) == target)
                match = true;
        }
        else if(regMatch(x, reg_range))
        {
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if(target >= range_begin && target <= range_end)
                match = true;
        }
        else if(regMatch(x, reg_not))
        {
            match = true;
            if(to_int(regReplace(x, reg_not, "$1"), INT_MAX) == target)
                match = false;
        }
        else if(regMatch(x, reg_not_range))
        {
            match = true;
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if(target >= range_begin && target <= range_end)
                match = false;
        }
        else if(regMatch(x, reg_less))
        {
            if(to_int(regReplace(x, reg_less, "$1"), INT_MAX) >= target)
                match = true;
        }
        else if(regMatch(x, reg_more))
        {
            if(to_int(regReplace(x, reg_more, "$1"), INT_MIN) <= target)
                match = true;
        }
    }
    return match;
}

bool applyMatcher(const std::string &rule, std::string &real_rule, const Proxy &node)
{
    std::string target, ret_real_rule;
    static const std::string groupid_regex = R"(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)", group_regex = R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
    static const std::string type_regex = R"(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)", port_regex = R"(^!!(?:PORT)=(.+?)(?:!!(.*))?$)", server_regex = R"(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)";
    static const std::map<ProxyType, const char *> types = {
        {ProxyType::Shadowsocks,  "SS"},
        {ProxyType::ShadowsocksR, "SSR"},
        {ProxyType::VMess,        "VMESS"},
        {ProxyType::Trojan,       "TROJAN"},
        {ProxyType::Snell,        "SNELL"},
        {ProxyType::HTTP,         "HTTP"},
        {ProxyType::HTTPS,        "HTTPS"},
        {ProxyType::SOCKS5,       "SOCKS5"},
        {ProxyType::WireGuard,    "WIREGUARD"},
        {ProxyType::Hysteria,     "HYSTERIA"},
        {ProxyType::Hysteria2,   "HYSTERIA2"},
        {ProxyType::Masque,       "MASQUE"},
        {ProxyType::TUIC, "TUIC"},
        {ProxyType::AnyTLS, "ANYTLS"},
        {ProxyType::OpenVPN, "OPENVPN"},
        {ProxyType::Tailscale, "TAILSCALE"},
        {ProxyType::VLESS, "VLESS"},
        {ProxyType::Mieru, "MIERU"},
        {ProxyType::Sudoku, "SUDOKU"},
        {ProxyType::TrustTunnel,  "TRUSTTUNNEL"}
    };
    if(startsWith(rule, "!!GROUP="))
    {
        regGetMatch(rule, group_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Group, target);
    }
    else if(startsWith(rule, "!!GROUPID=") || startsWith(rule, "!!INSERT="))
    {
        int dir = startsWith(rule, "!!INSERT=") ? -1 : 1;
        regGetMatch(rule, groupid_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, dir * node.GroupId);
    }
    else if(startsWith(rule, "!!TYPE="))
    {
        regGetMatch(rule, type_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        if(node.Type == ProxyType::Unknown)
            return false;
        return regMatch(types.at(node.Type), target);
    }
    else if(startsWith(rule, "!!PORT="))
    {
        regGetMatch(rule, port_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, node.Port);
    }
    else if(startsWith(rule, "!!SERVER="))
    {
        regGetMatch(rule, server_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Hostname, target);
    }
    else
        real_rule = rule;
    return true;
}

void processRemark(std::string &remark, const string_array &remarks_list, bool proc_comma = true)
{
    // Replace every '=' with '-' in the remark string to avoid parse errors from the clients.
    //     Surge is tested to yield an error when handling '=' in the remark string,
    //     not sure if other clients have the same problem.
    std::replace(remark.begin(), remark.end(), '=', '-');

    if(proc_comma)
    {
        if(remark.find(',') != std::string::npos)
        {
            remark.insert(0, "\"");
            remark.append("\"");
        }
    }
    std::string tempRemark = remark;
    int cnt = 2;
    while(std::find(remarks_list.cbegin(), remarks_list.cend(), tempRemark) != remarks_list.cend())
    {
        tempRemark = remark + " " + std::to_string(cnt);
        cnt++;
    }
    remark = tempRemark;
}

void groupGenerate(const std::string &rule, std::vector<Proxy> &nodelist, string_array &filtered_nodelist, bool add_direct, extra_settings &ext)
{
    std::string real_rule;
    if(startsWith(rule, "[]") && add_direct)
    {
        filtered_nodelist.emplace_back(rule.substr(2));
    }
#ifndef NO_JS_RUNTIME
    else if(startsWith(rule, "script:") && ext.authorized)
    {
        script_safe_runner(ext.js_runtime, ext.js_context, [&](qjs::Context &ctx){
            std::string script = fileGet(rule.substr(7), true);
            try
            {
                ctx.eval(script);
                auto filter = (std::function<std::string(const std::vector<Proxy>&)>) ctx.eval("filter");
                std::string result_list = filter(nodelist);
                filtered_nodelist = split(regTrim(result_list), "\n");
            }
            catch (qjs::exception)
            {
                script_print_stack(ctx);
            }
        }, global.scriptCleanContext);
    }
#endif // NO_JS_RUNTIME
    else
    {
        for(Proxy &x : nodelist)
        {
            if(applyMatcher(rule, real_rule, x) && (real_rule.empty() || regFind(x.Remark, real_rule)) && std::find(filtered_nodelist.begin(), filtered_nodelist.end(), x.Remark) == filtered_nodelist.end())
                filtered_nodelist.emplace_back(x.Remark);
        }
    }
}

void proxyToClash(std::vector<Proxy> &nodes, YAML::Node &yamlnode, const ProxyGroupConfigs &extra_proxy_group, bool clashR, extra_settings &ext)
{
    YAML::Node proxies, original_groups;
    std::vector<Proxy> nodelist;
    string_array remarks_list;
    /// proxies style
    bool proxy_block = false, proxy_compact = false, group_block = false, group_compact = false;
    switch(hash_(ext.clash_proxies_style))
    {
    case "block"_hash:
        proxy_block = true;
        break;
    default:
    case "flow"_hash:
        break;
    case "compact"_hash:
        proxy_compact = true;
        break;
    }
    switch(hash_(ext.clash_proxy_groups_style))
    {
        case "block"_hash:
            group_block = true;
            break;
        default:
        case "flow"_hash:
            break;
        case "compact"_hash:
            group_compact = true;
            break;
    }

    for(Proxy &x : nodes)
    {
        YAML::Node singleproxy;

        std::string type = getProxyTypeName(x.Type);
        std::string pluginopts = replaceAllDistinct(x.PluginOption, ";", "&");
        if(ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, xudp = ext.xudp;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        xudp.define(x.XUDP);

        if(!x.UnderlyingProxy.empty())
            singleproxy["dialer-proxy"] = x.UnderlyingProxy;
        singleproxy["name"] = x.Remark;
        singleproxy["server"] = x.Hostname;
        singleproxy["port"] = x.Port;
        YAML::Node smuxNode;
        std::string sni, fingerprint, clientFingerprint, headers_v2ray, headers_gost;
        std::string v2ray_http_upgrade, v2ray_http_upgrade_fast_open;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            //latest clash core removed support for chacha20 encryption
            if(ext.filter_deprecated && x.EncryptMethod == "chacha20")
                continue;
            singleproxy["type"] = "ss";
            singleproxy["cipher"] = x.EncryptMethod;
            singleproxy["password"] = x.Password;
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            switch(hash_(x.Plugin))
            {
            case "simple-obfs"_hash:
            case "obfs-local"_hash:
                singleproxy["plugin"] = "obfs";
                singleproxy["plugin-opts"]["mode"] = urlDecode(getUrlArg(pluginopts, "obfs"));
                singleproxy["plugin-opts"]["host"] = urlDecode(getUrlArg(pluginopts, "obfs-host"));
                break;
            case "v2ray-plugin"_hash:
                singleproxy["plugin"] = "v2ray-plugin";
                singleproxy["plugin-opts"]["mode"] = getUrlArg(pluginopts, "mode");
                singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                singleproxy["plugin-opts"]["path"] = getUrlArg(pluginopts, "path");
                singleproxy["plugin-opts"]["tls"] = pluginopts.find("tls") != std::string::npos;
                singleproxy["plugin-opts"]["mux"] = pluginopts.find("mux") != std::string::npos;
                if(!x.AllowInsecure.is_undef())
                    singleproxy["plugin-opts"]["skip-cert-verify"] = x.AllowInsecure.get();
                else if(!scv.is_undef())
                    singleproxy["plugin-opts"]["skip-cert-verify"] = scv.get();
                if(!x.Fingerprint.empty())
                    singleproxy["plugin-opts"]["fingerprint"] = x.Fingerprint;
                if(!x.ServerName.empty())
                    singleproxy["plugin-opts"]["server_name"] = x.ServerName;
                if(!x.Certificate.empty())
                    singleproxy["plugin-opts"]["certificate"] = x.Certificate;
                if(!x.CertificateKey.empty())
                    singleproxy["plugin-opts"]["private-key"] = x.CertificateKey;
                {
                    std::string certificate = getUrlArg(pluginopts, "certificate");
                    if(!certificate.empty())
                        singleproxy["plugin-opts"]["certificate"] = certificate;
                    std::string private_key = getUrlArg(pluginopts, "private-key");
                    if(!private_key.empty())
                        singleproxy["plugin-opts"]["private-key"] = private_key;
                }
                v2ray_http_upgrade = getUrlArg(pluginopts, "v2ray-http-upgrade");
                if(!v2ray_http_upgrade.empty())
                    singleproxy["plugin-opts"]["v2ray-http-upgrade"] = v2ray_http_upgrade != "false" && v2ray_http_upgrade != "0";
                v2ray_http_upgrade_fast_open = getUrlArg(pluginopts, "v2ray-http-upgrade-fast-open");
                if(!v2ray_http_upgrade_fast_open.empty())
                    singleproxy["plugin-opts"]["v2ray-http-upgrade-fast-open"] = v2ray_http_upgrade_fast_open != "false" && v2ray_http_upgrade_fast_open != "0";
                if(!x.EchConfig.empty() || !x.EchEnable.is_undef())
                {
                    if(!x.EchEnable.is_undef())
                        singleproxy["plugin-opts"]["ech-opts"]["enable"] = x.EchEnable.get();
                    if(!x.EchConfig.empty())
                        singleproxy["plugin-opts"]["ech-opts"]["config"] = x.EchConfig;
                    if(!x.EchQueryServerName.empty())
                        singleproxy["plugin-opts"]["ech-opts"]["query-server-name"] = x.EchQueryServerName;
                }
                {
                    std::string query_server_name = getUrlArg(pluginopts, "ech-query-server-name");
                    if(!query_server_name.empty())
                        singleproxy["plugin-opts"]["ech-opts"]["query-server-name"] = query_server_name;
                }
                {
                    std::string headers_str = getUrlArg(pluginopts, "headers");
                    if(!headers_str.empty())
                    {
                        rapidjson::Document d;
                        d.Parse(urlDecode(headers_str).c_str());
                        if(!d.HasParseError() && d.IsObject())
                        {
                            for (auto& m : d.GetObject())
                            {
                                if (m.value.IsString())
                                {
                                    singleproxy["plugin-opts"]["headers"][m.name.GetString()] = m.value.GetString();
                                }
                            }
                        }
                    }
                }
                if(!x.V2rayHttpUpgrade.is_undef())
                    singleproxy["plugin-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                if(!x.V2rayHttpUpgradeFastOpen.is_undef())
                    singleproxy["plugin-opts"]["v2ray-http-upgrade-fast-open"] = x.V2rayHttpUpgradeFastOpen.get();
                if(!x.ClientFingerprint.empty())
                    singleproxy["client-fingerprint"] = x.ClientFingerprint;
                else if(!x.Fingerprint.empty() && singleproxy["plugin-opts"]["tls"].IsDefined() && singleproxy["plugin-opts"]["tls"].as<bool>())
                    singleproxy["client-fingerprint"] = x.Fingerprint;
                break;
            case "shadow-tls"_hash:
                singleproxy["plugin"] = "shadow-tls";
                singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                singleproxy["plugin-opts"]["password"] = getUrlArg(pluginopts, "password");
                singleproxy["plugin-opts"]["version"] = getUrlArg(pluginopts, "version");
                {
                    std::string alpn = getUrlArg(pluginopts, "alpn");
                    if(!alpn.empty())
                    {
                        string_size pos = 0, next_pos = 0;
                        int index = 0;
                        while((next_pos = alpn.find(",", pos)) != std::string::npos)
                        {
                            std::string value = alpn.substr(pos, next_pos - pos);
                            singleproxy["plugin-opts"]["alpn"][index] = trim(value);
                            pos = next_pos + 1;
                            index++;
                        }
                        std::string value = alpn.substr(pos);
                        singleproxy["plugin-opts"]["alpn"][index] = trim(value);
                    }
                }
                sni = getUrlArg(pluginopts, "sni");
                if(!sni.empty())
                    singleproxy["plugin-opts"]["sni"] = sni;
                fingerprint = getUrlArg(pluginopts, "fingerprint");
                if(!fingerprint.empty())
                    singleproxy["plugin-opts"]["fingerprint"] = fingerprint;
                clientFingerprint = getUrlArg(pluginopts, "client-fingerprint");
                if(!clientFingerprint.empty())
                    singleproxy["plugin-opts"]["client-fingerprint"] = clientFingerprint;
                break;
            case "gost-plugin"_hash:
                singleproxy["plugin"] = "gost-plugin";
                singleproxy["plugin-opts"]["mode"] = getUrlArg(pluginopts, "mode");
                singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                singleproxy["plugin-opts"]["path"] = getUrlArg(pluginopts, "path");
                singleproxy["plugin-opts"]["tls"] = pluginopts.find("tls") != std::string::npos;
                singleproxy["plugin-opts"]["mux"] = pluginopts.find("mux") != std::string::npos;
                if(!scv.is_undef())
                    singleproxy["plugin-opts"]["skip-cert-verify"] = scv.get();
                fingerprint = getUrlArg(pluginopts, "fingerprint");
                if(!fingerprint.empty())
                    singleproxy["plugin-opts"]["fingerprint"] = fingerprint;
                if(!x.Fingerprint.empty())
                    singleproxy["plugin-opts"]["fingerprint"] = x.Fingerprint;
                if(!x.ServerName.empty())
                    singleproxy["plugin-opts"]["server_name"] = x.ServerName;
                if(!x.Certificate.empty())
                    singleproxy["plugin-opts"]["certificate"] = x.Certificate;
                if(!x.CertificateKey.empty())
                    singleproxy["plugin-opts"]["private-key"] = x.CertificateKey;
                {
                    std::string certificate = getUrlArg(pluginopts, "certificate");
                    if(!certificate.empty())
                        singleproxy["plugin-opts"]["certificate"] = certificate;
                    std::string private_key = getUrlArg(pluginopts, "private-key");
                    if(!private_key.empty())
                        singleproxy["plugin-opts"]["private-key"] = private_key;
                }
                headers_gost = getUrlArg(pluginopts, "headers");
                if(!headers_gost.empty())
                {
                    string_size pos = 0, next_pos = 0;
                    while((next_pos = headers_gost.find(";", pos)) != std::string::npos)
                    {
                        std::string header = headers_gost.substr(pos, next_pos - pos);
                        string_size sep_pos = header.find("=");
                        if(sep_pos != std::string::npos)
                        {
                            std::string key = header.substr(0, sep_pos);
                            std::string value = header.substr(sep_pos + 1);
                            singleproxy["plugin-opts"]["headers"][key] = value;
                        }
                        pos = next_pos + 1;
                    }
                    std::string header = headers_gost.substr(pos);
                    string_size sep_pos = header.find("=");
                    if(sep_pos != std::string::npos)
                    {
                        std::string key = header.substr(0, sep_pos);
                        std::string value = header.substr(sep_pos + 1);
                        singleproxy["plugin-opts"]["headers"][key] = value;
                    }
                }
                break;
            case "restls"_hash:
                singleproxy["plugin"] = "restls";
                singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                singleproxy["plugin-opts"]["password"] = getUrlArg(pluginopts, "password");
                {
                    std::string version_hint = getUrlArg(pluginopts, "version-hint");
                    if(!version_hint.empty())
                        singleproxy["plugin-opts"]["version-hint"] = version_hint;
                    std::string restls_script = getUrlArg(pluginopts, "restls-script");
                    if(!restls_script.empty())
                        singleproxy["plugin-opts"]["restls-script"] = restls_script;
                }
                break;
            case "kcptun"_hash:
                singleproxy["plugin"] = "kcptun";
                if(!x.KCPKey.empty())
                    singleproxy["plugin-opts"]["key"] = x.KCPKey;
                if(!x.KCPCrypt.empty())
                    singleproxy["plugin-opts"]["crypt"] = x.KCPCrypt;
                if(!x.KCPMode.empty())
                    singleproxy["plugin-opts"]["mode"] = x.KCPMode;
                if(x.KCPConn > 0)
                    singleproxy["plugin-opts"]["conn"] = x.KCPConn;
                if(x.KCPAutoExpire > 0)
                    singleproxy["plugin-opts"]["autoexpire"] = x.KCPAutoExpire;
                if(x.KCPScavengeTTL > 0)
                    singleproxy["plugin-opts"]["scavengettl"] = x.KCPScavengeTTL;
                if(x.KCPMtu > 0)
                    singleproxy["plugin-opts"]["mtu"] = x.KCPMtu;
                if(x.KCPRateLimit > 0)
                    singleproxy["plugin-opts"]["ratelimit"] = x.KCPRateLimit;
                if(x.KCPSndWnd > 0)
                    singleproxy["plugin-opts"]["sndwnd"] = x.KCPSndWnd;
                if(x.KCPRcvWnd > 0)
                    singleproxy["plugin-opts"]["rcvwnd"] = x.KCPRcvWnd;
                if(x.KCPDataShard > 0)
                    singleproxy["plugin-opts"]["datashard"] = x.KCPDataShard;
                if(x.KCPParityShard > 0)
                    singleproxy["plugin-opts"]["parityshard"] = x.KCPParityShard;
                if(x.KCPDSCP > 0)
                    singleproxy["plugin-opts"]["dscp"] = x.KCPDSCP;
                if(x.KCPNoComp)
                    singleproxy["plugin-opts"]["nocomp"] = x.KCPNoComp;
                if(x.KCPAckNoDelay)
                    singleproxy["plugin-opts"]["acknodelay"] = x.KCPAckNoDelay;
                if(x.KCPNodelay > 0)
                    singleproxy["plugin-opts"]["nodelay"] = x.KCPNodelay;
                if(x.KCPInterval > 0)
                    singleproxy["plugin-opts"]["interval"] = x.KCPInterval;
                if(x.KCPResend > 0)
                    singleproxy["plugin-opts"]["resend"] = x.KCPResend;
                if(x.KCPSockbuf > 0)
                    singleproxy["plugin-opts"]["sockbuf"] = x.KCPSockbuf;
                if(x.KCPSmuxver > 0)
                    singleproxy["plugin-opts"]["smuxver"] = x.KCPSmuxver;
                if(x.KCPSmuxbuf > 0)
                    singleproxy["plugin-opts"]["smuxbuf"] = x.KCPSmuxbuf;
                if(x.KCPFramesize > 0)
                    singleproxy["plugin-opts"]["framesize"] = x.KCPFramesize;
                if(x.KCPStreambuf > 0)
                    singleproxy["plugin-opts"]["streambuf"] = x.KCPStreambuf;
                if(x.KCPKeepalive > 0)
                    singleproxy["plugin-opts"]["keepalive"] = x.KCPKeepalive;
                break;
            }
            if(x.Plugin != "v2ray-plugin" && x.Plugin != "shadow-tls" && x.Plugin != "gost-plugin" && x.Plugin != "restls" && x.Plugin != "kcptun")
            {
                if(x.TLSSecure)
                    singleproxy["tls"] = true;
            }
            if(!scv.is_undef() && scv.get() && x.Plugin != "v2ray-plugin" && x.Plugin != "shadow-tls" && x.Plugin != "gost-plugin" && x.Plugin != "restls" && x.Plugin != "kcptun")
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.Fingerprint.empty() && x.Plugin != "v2ray-plugin" && x.Plugin != "shadow-tls" && x.Plugin != "gost-plugin" && x.Plugin != "restls" && x.Plugin != "kcptun")
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty() && x.Plugin != "v2ray-plugin" && x.Plugin != "gost-plugin")
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(udp)
                singleproxy["udp"] = true;
            if(!tfo.is_undef())
                singleproxy["fast-open"] = tfo.get();
            if(!x.IPVersion.empty())
                singleproxy["ip-version"] = x.IPVersion;
            if(!x.UDPoverTCP.is_undef() && x.UDPoverTCP.get())
                singleproxy["udp-over-tcp"] = x.UDPoverTCP.get();
            if(x.UDPOverTCPVersion > 0)
                singleproxy["udp-over-tcp-version"] = x.UDPOverTCPVersion;
            if(!x.SmuxEnabled.is_undef())
                smuxNode["enabled"] = x.SmuxEnabled.get();
            if(!x.SmuxProtocol.empty())
                smuxNode["protocol"] = x.SmuxProtocol;
            if(x.SmuxMaxConnections > 0)
                smuxNode["max-connections"] = x.SmuxMaxConnections;
            if(x.SmuxMinStreams > 0)
                smuxNode["min-streams"] = x.SmuxMinStreams;
            if(x.SmuxMaxStreams > 0)
                smuxNode["max-streams"] = x.SmuxMaxStreams;
            if(!x.SmuxPadding.is_undef())
                smuxNode["padding"] = x.SmuxPadding.get();
            if(!x.SmuxStatistic.is_undef())
                smuxNode["statistic"] = x.SmuxStatistic.get();
            if(!x.SmuxOnlyTcp.is_undef())
                smuxNode["only-tcp"] = x.SmuxOnlyTcp.get();
            if(!smuxNode.IsNull())
                singleproxy["smux"] = smuxNode;
            break;
        case ProxyType::VMess:
            singleproxy["type"] = "vmess";
            singleproxy["uuid"] = x.UserId;
            singleproxy["alterId"] = x.AlterId;
            singleproxy["cipher"] = x.EncryptMethod;
            if(!x.TLSStr.empty())
                singleproxy["tls"] = x.TLSSecure;
            if(!x.AllowInsecure.is_undef())
                singleproxy["skip-cert-verify"] = x.AllowInsecure.get();
            else if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.ServerName.empty())
                singleproxy["servername"] = x.ServerName;
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            else if(x.Flow == "xtls-rprx-vision")
                singleproxy["client-fingerprint"] = "chrome";
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            else if(udp && !udp.is_undef() && udp.get())
                singleproxy["udp"] = true;
            if(!x.TCPFastOpen.is_undef())
                singleproxy["fast-open"] = x.TCPFastOpen.get();
            if(!x.IPVersion.empty())
                singleproxy["ip-version"] = x.IPVersion;
            if(!x.AuthenticatedLength.is_undef())
                singleproxy["authenticated-length"] = x.AuthenticatedLength.get();
            if(!x.GlobalPadding.is_undef())
                singleproxy["global-padding"] = x.GlobalPadding.get();
            if(!x.PacketEncoding.empty())
                singleproxy["packet-encoding"] = x.PacketEncoding;
            if(!x.PacketAddr.is_undef())
                singleproxy["packet-addr"] = x.PacketAddr.get();
            if(!x.XUDP.is_undef())
                singleproxy["xudp"] = x.XUDP.get();
            if(!x.AlpnList.empty())
            {
                for(auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if(!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if(!x.PublicKey.empty())
            {
                singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                singleproxy["reality-opts"]["short-id"] = x.ShortID;
                if(!x.ServerName.empty())
                    singleproxy["reality-opts"]["servername"] = x.ServerName;
                else if(!x.SNI.empty())
                    singleproxy["reality-opts"]["servername"] = x.SNI;
                if(!x.SpiderX.empty())
                    singleproxy["reality-opts"]["spiderX"] = x.SpiderX;
                if(!x.SupportX25519Mlkem768.is_undef())
                    singleproxy["reality-opts"]["support-x25519mlkem768"] = x.SupportX25519Mlkem768.get();
            }
            switch(hash_(x.TransferProtocol))
            {
            case "tcp"_hash:
                break;
            case "ws"_hash:
                singleproxy["network"] = x.TransferProtocol;
                if(ext.clash_new_field_name)
                {
                    if(!x.WsPath.empty())
                        singleproxy["ws-opts"]["path"] = x.WsPath;
                    else
                        singleproxy["ws-opts"]["path"] = x.Path;
                    applyEncodedHeaders(x.WsHeadersMap, singleproxy["ws-opts"]["headers"]);
                    if(!x.WsHeaders.empty())
                        singleproxy["ws-opts"]["headers"]["Host"] = x.WsHeaders;
                    else if(!x.Host.empty())
                        singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                    if(!x.Edge.empty())
                        singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                    if(!x.WsEarlyDataHeaderName.empty())
                        singleproxy["ws-opts"]["early-data-header-name"] = x.WsEarlyDataHeaderName;
                    if(x.WsMaxEarlyData > 0)
                        singleproxy["ws-opts"]["max-early-data"] = x.WsMaxEarlyData;
                    if(!x.V2rayHttpUpgrade.is_undef())
                        singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                    if(!x.V2rayHttpUpgradeFastOpen.is_undef())
                        singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"] = x.V2rayHttpUpgradeFastOpen.get();
                }
                else
                {
                    singleproxy["ws-path"] = x.Path;
                    if(!x.WsHeaders.empty())
                        singleproxy["ws-headers"]["Host"] = x.WsHeaders;
                    else if(!x.Host.empty())
                        singleproxy["ws-headers"]["Host"] = x.Host;
                    if(!x.Edge.empty())
                        singleproxy["ws-headers"]["Edge"] = x.Edge;
                }
                if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
                {
                    if(!x.EchEnable.is_undef())
                        singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                    if(!x.EchConfig.empty())
                        singleproxy["ech-opts"]["config"] = x.EchConfig;
                    if(!x.EchQueryServerName.empty())
                        singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
                }
                break;
            case "http"_hash:
                singleproxy["network"] = x.TransferProtocol;
                singleproxy["http-opts"]["method"] = x.HTTPOptsMethod.empty() ? "GET" : x.HTTPOptsMethod;
                if(!x.HTTPOptsPaths.empty())
                {
                    for(const auto &item : x.HTTPOptsPaths)
                        singleproxy["http-opts"]["path"].push_back(item);
                }
                else
                {
                    singleproxy["http-opts"]["path"].push_back(x.Path);
                }
                applyEncodedHeadersMultiValue(x.HTTPOptsHeaders, singleproxy["http-opts"]["headers"]);
                if(!x.Host.empty())
                    singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                if(!x.Edge.empty())
                    singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
                {
                    if(!x.EchEnable.is_undef())
                        singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                    if(!x.EchConfig.empty())
                        singleproxy["ech-opts"]["config"] = x.EchConfig;
                    if(!x.EchQueryServerName.empty())
                        singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
                }
                break;
            case "h2"_hash:
                singleproxy["network"] = x.TransferProtocol;
                singleproxy["h2-opts"]["path"] = x.Path;
                if(!x.H2Hosts.empty())
                {
                    for(const auto &item : x.H2Hosts)
                        singleproxy["h2-opts"]["host"].push_back(item);
                }
                else if(!x.Host.empty())
                    singleproxy["h2-opts"]["host"].push_back(x.Host);
                if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
                {
                    if(!x.EchEnable.is_undef())
                        singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                    if(!x.EchConfig.empty())
                        singleproxy["ech-opts"]["config"] = x.EchConfig;
                    if(!x.EchQueryServerName.empty())
                        singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
                }
                break;
            case "grpc"_hash:
                singleproxy["network"] = x.TransferProtocol;
                if(!x.ServerName.empty())
                    singleproxy["servername"] = x.ServerName;
                else if(!x.Host.empty())
                    singleproxy["servername"] = x.Host;
                if(!x.GrpcServiceName.empty())
                    singleproxy["grpc-opts"]["grpc-service-name"] = x.GrpcServiceName;
                else
                    singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                if(!x.GrpcUserAgent.empty())
                    singleproxy["grpc-opts"]["grpc-user-agent"] = x.GrpcUserAgent;
                if(x.GrpcPingInterval > 0)
                    singleproxy["grpc-opts"]["ping-interval"] = (int)x.GrpcPingInterval;
                if(x.GrpcMaxConnections > 0)
                    singleproxy["grpc-opts"]["max-connections"] = (int)x.GrpcMaxConnections;
                if(x.GrpcMinStreams > 0)
                    singleproxy["grpc-opts"]["min-streams"] = (int)x.GrpcMinStreams;
                if(x.GrpcMaxStreams > 0)
                    singleproxy["grpc-opts"]["max-streams"] = (int)x.GrpcMaxStreams;
                if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
                {
                    if(!x.EchEnable.is_undef())
                        singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                    if(!x.EchConfig.empty())
                        singleproxy["ech-opts"]["config"] = x.EchConfig;
                    if(!x.EchQueryServerName.empty())
                        singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
                }
                break;
            case "quic"_hash:
                singleproxy["network"] = x.TransferProtocol;
                if(!x.QUICSecure.empty())
                    singleproxy["quic-opts"]["security"] = x.QUICSecure;
                else if(!x.Host.empty())
                    singleproxy["quic-opts"]["security"] = x.Host;
                if(!x.QUICSecret.empty())
                    singleproxy["quic-opts"]["key"] = x.QUICSecret;
                else if(!x.Path.empty())
                    singleproxy["quic-opts"]["key"] = x.Path;
                break;
            default:
                continue;
            }
            if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if(!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                if(!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if(!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            break;
        case ProxyType::ShadowsocksR:
            //ignoring all nodes with unsupported obfs, protocols and encryption
            if(ext.filter_deprecated)
            {
                if(!clashR && std::find(clash_ssr_ciphers.cbegin(), clash_ssr_ciphers.cend(), x.EncryptMethod) == clash_ssr_ciphers.cend())
                    continue;
                if(std::find(clashr_protocols.cbegin(), clashr_protocols.cend(), x.Protocol) == clashr_protocols.cend())
                    continue;
                if(std::find(clashr_obfs.cbegin(), clashr_obfs.cend(), x.OBFS) == clashr_obfs.cend())
                    continue;
            }

            singleproxy["type"] = "ssr";
            singleproxy["cipher"] = x.EncryptMethod == "none" ? "dummy" : x.EncryptMethod;
            singleproxy["password"] = x.Password;
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            singleproxy["protocol"] = x.Protocol;
            singleproxy["obfs"] = x.OBFS;
            if(clashR)
            {
                singleproxy["protocolparam"] = x.ProtocolParam;
                singleproxy["obfsparam"] = x.OBFSParam;
            }
            else
            {
                singleproxy["protocol-param"] = x.ProtocolParam;
                singleproxy["obfs-param"] = x.OBFSParam;
            }
            if(udp)
                singleproxy["udp"] = true;
            break;
        case ProxyType::SOCKS5:
            singleproxy["type"] = "socks5";
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
            {
                singleproxy["password"] = x.Password;
                if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
                    singleproxy["password"].SetTag("str");
            }
            if(x.TLSSecure)
                singleproxy["tls"] = x.TLSSecure;
            if(!x.AllowInsecure.is_undef())
                singleproxy["skip-cert-verify"] = x.AllowInsecure.get();
            else if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(udp)
                singleproxy["udp"] = true;
            if(!x.IPVersion.empty())
                singleproxy["ip-version"] = x.IPVersion;
            if(!x.UDPoverTCP.is_undef() && x.UDPoverTCP.get())
                singleproxy["udp-over-tcp"] = x.UDPoverTCP.get();
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            singleproxy["type"] = "http";
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
            {
                singleproxy["password"] = x.Password;
                if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
                    singleproxy["password"].SetTag("str");
            }
            singleproxy["tls"] = x.TLSSecure;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            else if(!x.ServerName.empty())
                singleproxy["sni"] = x.ServerName;
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
               singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(udp)
                singleproxy["udp"] = true;
            if(!x.IPVersion.empty())
                singleproxy["ip-version"] = x.IPVersion;
            applyEncodedHeaders(x.HTTPHeaders, singleproxy["headers"]);
            break;
        case ProxyType::Trojan:
            singleproxy["type"] = "trojan";
            singleproxy["password"] = x.Password;
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["password"].SetTag("str");
            if(!x.ServerName.empty())
                singleproxy["sni"] = x.ServerName;
            else if(!x.Host.empty())
                singleproxy["sni"] = x.Host;
            if(!x.AlpnList.empty())
            {
                for(auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if(!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if(!x.PublicKey.empty())
            {
                singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                singleproxy["reality-opts"]["short-id"] = x.ShortID;
                if(!x.ServerName.empty())
                    singleproxy["reality-opts"]["servername"] = x.ServerName;
                else if(!x.SNI.empty())
                    singleproxy["reality-opts"]["servername"] = x.SNI;
                if(!x.SpiderX.empty())
                    singleproxy["reality-opts"]["spiderX"] = x.SpiderX;
                if(!x.SupportX25519Mlkem768.is_undef())
                    singleproxy["reality-opts"]["support-x25519mlkem768"] = x.SupportX25519Mlkem768.get();
            }
            if(!x.AllowInsecure.is_undef())
                singleproxy["skip-cert-verify"] = x.AllowInsecure.get();
            else if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if(!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                else
                    singleproxy["ech-opts"]["enable"] = true;
                if(!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if(!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            if(!x.Flow.empty())
                singleproxy["flow"] = x.Flow;
            if(!x.FlowShow.is_undef())
                singleproxy["flow-show"] = x.FlowShow.get();
            if(x.TrojanSSOpts == true || !x.TrojanSSMethod.empty() || !x.TrojanSSPassword.empty())
            {
                singleproxy["ss-opts"]["enabled"] = x.TrojanSSOpts;
                if(!x.TrojanSSMethod.empty())
                    singleproxy["ss-opts"]["method"] = x.TrojanSSMethod;
                if(!x.TrojanSSPassword.empty())
                    singleproxy["ss-opts"]["password"] = x.TrojanSSPassword;
            }
            if(x.Flow == "xtls-rprx-vision")
            {
                if(singleproxy["client-fingerprint"].IsNull())
                {
                    if(!x.ClientFingerprint.empty())
                        singleproxy["client-fingerprint"] = x.ClientFingerprint;
                    else if(!x.Fingerprint.empty())
                        singleproxy["client-fingerprint"] = x.Fingerprint;
                    else
                        singleproxy["client-fingerprint"] = "chrome";
                }
                if(x.TransferProtocol.empty() || x.TransferProtocol == "tcp")
                    singleproxy["tls"] = true;
            }
            switch(hash_(x.TransferProtocol))
            {
            case "tcp"_hash:
                break;
            case "grpc"_hash:
                singleproxy["network"] = x.TransferProtocol;
                if(!x.Path.empty())
                    singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                if(!x.GrpcServiceName.empty())
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.GrpcServiceName;
                if(!x.GrpcUserAgent.empty())
                    singleproxy["grpc-opts"]["grpc-user-agent"] = x.GrpcUserAgent;
                if(x.GrpcPingInterval > 0)
                    singleproxy["grpc-opts"]["ping-interval"] = (int)x.GrpcPingInterval;
                if(x.GrpcMaxConnections > 0)
                    singleproxy["grpc-opts"]["max-connections"] = (int)x.GrpcMaxConnections;
                if(x.GrpcMinStreams > 0)
                    singleproxy["grpc-opts"]["min-streams"] = (int)x.GrpcMinStreams;
                if(x.GrpcMaxStreams > 0)
                    singleproxy["grpc-opts"]["max-streams"] = (int)x.GrpcMaxStreams;
                break;
            case "ws"_hash:
                singleproxy["network"] = x.TransferProtocol;
                if(x.TLSSecure)
                    singleproxy["tls"] = true;
                if(!x.WsPath.empty())
                    singleproxy["ws-opts"]["path"] = x.WsPath;
                else if(!x.Path.empty())
                    singleproxy["ws-opts"]["path"] = x.Path;
                applyEncodedHeaders(x.WsHeadersMap, singleproxy["ws-opts"]["headers"]);
                if(!x.WsHeaders.empty())
                    singleproxy["ws-opts"]["headers"]["Host"] = x.WsHeaders;
                else if(!x.Host.empty())
                    singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                if(!x.Edge.empty())
                    singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                if(!x.WsEarlyDataHeaderName.empty())
                    singleproxy["ws-opts"]["early-data-header-name"] = x.WsEarlyDataHeaderName;
                if(x.WsMaxEarlyData > 0)
                    singleproxy["ws-opts"]["max-early-data"] = x.WsMaxEarlyData;
                if(!x.V2rayHttpUpgrade.is_undef())
                    singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                if(!x.V2rayHttpUpgradeFastOpen.is_undef())
                    singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"] = x.V2rayHttpUpgradeFastOpen.get();
                break;
            }
            if(!x.TCPFastOpen.is_undef())
                singleproxy["fast-open"] = x.TCPFastOpen.get();
            break;
        case ProxyType::Snell:
            singleproxy["type"] = "snell";
            singleproxy["psk"] = x.Password;
            if(x.SnellVersion != 0)
                singleproxy["version"] = x.SnellVersion;
            if(!x.OBFS.empty())
            {
                singleproxy["obfs-opts"]["mode"] = x.OBFS;
                if(!x.Host.empty())
                    singleproxy["obfs-opts"]["host"] = x.Host;
            }
            if(std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                singleproxy["psk"].SetTag("str");
            if(x.SnellVersion >= 3)
            {
                if(!x.UDP.is_undef())
                    singleproxy["udp"] = x.UDP.get();
                else if(!udp.is_undef())
                    singleproxy["udp"] = udp.get();
            }
            if(x.SnellVersion >= 4 && !x.Reuse.is_undef())
                singleproxy["reuse"] = x.Reuse.get();
            break;
        case ProxyType::WireGuard:
            singleproxy["type"] = "wireguard";
            singleproxy["public-key"] = x.PublicKey;
            singleproxy["private-key"] = x.PrivateKey;
            singleproxy["ip"] = x.SelfIP;
            if(!x.SelfIPv6.empty())
                singleproxy["ipv6"] = x.SelfIPv6;
            if(!x.PreSharedKey.empty())
            {
                singleproxy["pre-shared-key"] = x.PreSharedKey;
                singleproxy["preshared-key"] = x.PreSharedKey;
            }
            if(!x.DnsServers.empty())
                singleproxy["dns"] = x.DnsServers;
            if(x.Mtu > 0)
                singleproxy["mtu"] = x.Mtu;
            if(!x.AllowedIPs.empty())
                singleproxy["allowed-ips"] = x.AllowedIPs;
            if(x.KeepAlive > 0)
                singleproxy["persistent-keepalive"] = x.KeepAlive;
            if(!x.Reserved.empty())
            {
                for(auto &item : x.Reserved)
                    singleproxy["reserved"].push_back(item);
            }
            if(!x.Peers.empty())
            {
                for(auto &item : x.Peers)
                    singleproxy["peers"].push_back(item);
            }
            if(!x.DialerProxy.empty())
                singleproxy["dialer-proxy"] = x.DialerProxy;
            if(!x.RemoteDnsResolve.is_undef())
                singleproxy["remote-dns-resolve"] = x.RemoteDnsResolve.get();
            if(!x.AmneziaJC.empty() && !x.AmneziaJMin.empty() && !x.AmneziaJMax.empty())
            {
                singleproxy["amnezia-wg-option"]["jc"] = to_int(x.AmneziaJC);
                singleproxy["amnezia-wg-option"]["jmin"] = to_int(x.AmneziaJMin);
                singleproxy["amnezia-wg-option"]["jmax"] = to_int(x.AmneziaJMax);
                singleproxy["amnezia-wg-option"]["s1"] = to_int(x.AmneziaS1);
                singleproxy["amnezia-wg-option"]["s2"] = to_int(x.AmneziaS2);
                if(!x.AmneziaS3.empty())
                    singleproxy["amnezia-wg-option"]["s3"] = to_int(x.AmneziaS3);
                if(!x.AmneziaS4.empty())
                    singleproxy["amnezia-wg-option"]["s4"] = to_int(x.AmneziaS4);
                if(!x.AmneziaH1.empty())
                    singleproxy["amnezia-wg-option"]["h1"] = x.AmneziaH1;
                if(!x.AmneziaH2.empty())
                    singleproxy["amnezia-wg-option"]["h2"] = x.AmneziaH2;
                if(!x.AmneziaH3.empty())
                    singleproxy["amnezia-wg-option"]["h3"] = x.AmneziaH3;
                if(!x.AmneziaH4.empty())
                    singleproxy["amnezia-wg-option"]["h4"] = x.AmneziaH4;
                if(!x.AmneziaI1.empty())
                    singleproxy["amnezia-wg-option"]["i1"] = x.AmneziaI1;
                if(!x.AmneziaI2.empty())
                    singleproxy["amnezia-wg-option"]["i2"] = x.AmneziaI2;
                if(!x.AmneziaI3.empty())
                    singleproxy["amnezia-wg-option"]["i3"] = x.AmneziaI3;
                if(!x.AmneziaI4.empty())
                    singleproxy["amnezia-wg-option"]["i4"] = x.AmneziaI4;
                if(!x.AmneziaI5.empty())
                    singleproxy["amnezia-wg-option"]["i5"] = x.AmneziaI5;
                if(!x.AmneziaJ1.empty())
                    singleproxy["amnezia-wg-option"]["j1"] = x.AmneziaJ1;
                if(!x.AmneziaJ2.empty())
                    singleproxy["amnezia-wg-option"]["j2"] = x.AmneziaJ2;
                if(!x.AmneziaJ3.empty())
                    singleproxy["amnezia-wg-option"]["j3"] = x.AmneziaJ3;
                if(!x.AmneziaItime.empty())
                    singleproxy["amnezia-wg-option"]["itime"] = to_int(x.AmneziaItime);
            }
            break;
        case ProxyType::OpenVPN:
            singleproxy["type"] = "openvpn";
            if(!x.TransferProtocol.empty())
                singleproxy["proto"] = toLower(x.TransferProtocol);
            if(!x.OpenVPNDev.empty())
                singleproxy["dev"] = x.OpenVPNDev;
            if(!x.EncryptMethod.empty())
                singleproxy["cipher"] = x.EncryptMethod;
            if(!x.Auth.empty())
                singleproxy["auth"] = x.Auth;
            if(!x.CompLZO.empty())
                singleproxy["comp-lzo"] = x.CompLZO;
            if(!x.Ca.empty())
                singleproxy["ca"] = x.Ca;
            if(!x.Certificate.empty())
                singleproxy["cert"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["key"] = x.CertificateKey;
            if(!x.OpenVPNTLSCrypt.empty())
                singleproxy["tls-crypt"] = x.OpenVPNTLSCrypt;
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
                singleproxy["password"] = x.Password;
            if(x.Mtu > 0)
                singleproxy["mtu"] = x.Mtu;
            if(x.OpenVPNPing > 0)
                singleproxy["ping"] = x.OpenVPNPing;
            if(x.OpenVPNPingRestart > 0)
                singleproxy["ping-restart"] = x.OpenVPNPingRestart;
            if(!x.RemoteDnsResolve.is_undef())
                singleproxy["remote-dns-resolve"] = x.RemoteDnsResolve.get();
            if(!x.DnsServers.empty())
            {
                YAML::Node dnsarr;
                for(auto &d : x.DnsServers)
                    dnsarr.push_back(d);
                singleproxy["dns"] = dnsarr;
            }
            break;
        case ProxyType::Hysteria:
            if ((x.Up.empty() && !(x.UpSpeed || x.Up == "0")) || (x.Down.empty() && !(x.DownSpeed || x.Down == "0")))
                continue;
            singleproxy["type"] = "hysteria";
            if (!x.Ports.empty())
                singleproxy["ports"] = x.Ports;
            if (!x.Protocol.empty())
                singleproxy["protocol"] = x.Protocol;
            if (!x.OBFSParam.empty())
                singleproxy["obfs-protocol"] = x.OBFSParam;
            if (!x.Up.empty())
                singleproxy["up"] = x.Up;
            else if (x.UpSpeed || x.Up == "0")
                singleproxy["up"] = x.UpSpeed;
            if (!x.Down.empty())
                singleproxy["down"] = x.Down;
            else if (x.DownSpeed || x.Down == "0")
                singleproxy["down"] = x.DownSpeed;
            if (!x.Auth.empty())
                singleproxy["auth"] = x.Auth;
            if (!x.AuthStr.empty())
                singleproxy["auth-str"] = x.AuthStr;
            if (!x.OBFS.empty())
                singleproxy["obfs"] = x.OBFS;
            if (!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if (!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if (!x.AlpnList.empty())
            {
                for (auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if (!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if (!x.Ca.empty())
                singleproxy["ca"] = x.Ca;
            if (!x.CaStr.empty())
                singleproxy["ca-str"] = x.CaStr;
            if (!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if (!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if (!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if (!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                else
                    singleproxy["ech-opts"]["enable"] = true;
                if (!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if (!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            if (x.RecvWindowConn)
                singleproxy["recv-window-conn"] = x.RecvWindowConn;
            if (x.RecvWindow)
                singleproxy["recv-window"] = x.RecvWindow;
            if (!x.DisableMtuDiscovery.is_undef())
                singleproxy["disable-mtu-discovery"] = x.DisableMtuDiscovery.get();
            if (!x.TCPFastOpen.is_undef())
                singleproxy["fast-open"] = x.TCPFastOpen.get();
            if (x.HopInterval)
                singleproxy["hop-interval"] = x.HopInterval;
            if (!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            else if (udp && !udp.is_undef())
                singleproxy["udp"] = udp.get();
            else
                singleproxy["udp"] = true;
            break;
        case ProxyType::Hysteria2:
            singleproxy["type"] = "hysteria2";
            if (!x.Password.empty())
                singleproxy["password"] = x.Password;
            if (!x.Auth.empty())
                singleproxy["auth"] = x.Auth;
            if (!x.Ports.empty() && x.Ports != std::to_string(x.Port))
                singleproxy["ports"] = x.Ports;
            if (!x.Up.empty())
                singleproxy["up"] = x.Up;
            else if (x.UpSpeed)
                singleproxy["up"] = x.UpSpeed;
            if (!x.Down.empty())
                singleproxy["down"] = x.Down;
            else if (x.DownSpeed)
                singleproxy["down"] = x.DownSpeed;
            if (!x.Hysteria2HopInterval.empty())
                singleproxy["hop-interval"] = x.Hysteria2HopInterval;
            else if (x.HopInterval)
                singleproxy["hop-interval"] = x.HopInterval;
            if(!x.BBRProfile.empty())
                singleproxy["bbr-profile"] = x.BBRProfile;
            if(x.UdpMTU > 0)
                singleproxy["udp-mtu"] = x.UdpMTU;
            if (!x.OBFS.empty() && x.OBFS != "none")
                singleproxy["obfs"] = x.OBFS;
            if (!x.OBFSParam.empty() && !x.OBFS.empty() && x.OBFS != "none")
                singleproxy["obfs-password"] = x.OBFSParam;
            if (x.ObfsMinPacketSize > 0)
                singleproxy["obfs-min-packet-size"] = x.ObfsMinPacketSize;
            if (x.ObfsMaxPacketSize > 0)
                singleproxy["obfs-max-packet-size"] = x.ObfsMaxPacketSize;
            if (!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if (!x.AllowInsecure.is_undef())
                singleproxy["skip-cert-verify"] = x.AllowInsecure.get();
            else if (!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if (!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if (!x.AlpnList.empty())
            {
                for (auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if (!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if (!x.Ca.empty())
                singleproxy["ca"] = x.Ca;
            if (!x.CaStr.empty())
                singleproxy["ca-str"] = x.CaStr;
            if (!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if (!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if (!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if (!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                else
                    singleproxy["ech-opts"]["enable"] = true;
                if (!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if (!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            if (x.CWND > 0)
                singleproxy["cwnd"] = x.CWND;
            if (x.InitialStreamReceiveWindow > 0)
                singleproxy["initial-stream-receive-window"] = x.InitialStreamReceiveWindow;
            if (x.MaxStreamReceiveWindow > 0)
                singleproxy["max-stream-receive-window"] = x.MaxStreamReceiveWindow;
            if (x.InitialConnectionReceiveWindow > 0)
                singleproxy["initial-connection-receive-window"] = x.InitialConnectionReceiveWindow;
            if (x.MaxConnectionReceiveWindow > 0)
                singleproxy["max-connection-receive-window"] = x.MaxConnectionReceiveWindow;
            if (!x.RealmEnable.is_undef() || !x.RealmServerURL.empty() || !x.RealmToken.empty() || !x.RealmID.empty() || !x.RealmStunServers.empty() || !x.RealmSNI.empty() || !x.RealmSkipCertVerify.is_undef() || !x.RealmFingerprint.empty() || !x.RealmCertificate.empty() || !x.RealmPrivateKey.empty() || !x.RealmALPN.empty())
            {
                if(!x.RealmEnable.is_undef())
                    singleproxy["realm-opts"]["enable"] = x.RealmEnable.get();
                else
                    singleproxy["realm-opts"]["enable"] = true;
                if(!x.RealmServerURL.empty())
                    singleproxy["realm-opts"]["server-url"] = x.RealmServerURL;
                if(!x.RealmToken.empty())
                    singleproxy["realm-opts"]["token"] = x.RealmToken;
                if(!x.RealmID.empty())
                    singleproxy["realm-opts"]["realm-id"] = x.RealmID;
                if(!x.RealmStunServers.empty())
                {
                    for(const auto &item : x.RealmStunServers)
                        singleproxy["realm-opts"]["stun-servers"].push_back(item);
                }
                if(!x.RealmSNI.empty())
                    singleproxy["realm-opts"]["sni"] = x.RealmSNI;
                if(!x.RealmSkipCertVerify.is_undef())
                    singleproxy["realm-opts"]["skip-cert-verify"] = x.RealmSkipCertVerify.get();
                if(!x.RealmFingerprint.empty())
                    singleproxy["realm-opts"]["fingerprint"] = x.RealmFingerprint;
                if(!x.RealmCertificate.empty())
                    singleproxy["realm-opts"]["certificate"] = x.RealmCertificate;
                if(!x.RealmPrivateKey.empty())
                    singleproxy["realm-opts"]["private-key"] = x.RealmPrivateKey;
                if(!x.RealmALPN.empty())
                {
                    for(const auto &item : x.RealmALPN)
                        singleproxy["realm-opts"]["alpn"].push_back(item);
                }
            }
            if (!x.TCPFastOpen.is_undef())
                singleproxy["fast-open"] = x.TCPFastOpen.get();
            if (!x.UDP.is_undef() && x.UDP.get())
                singleproxy["udp"] = true;
            else if (!x.UDP.is_undef() && !x.UDP.get())
                singleproxy["udp"] = false;
            else if (udp && !udp.is_undef())
                singleproxy["udp"] = udp.get();
            break;
        case ProxyType::TUIC:
            singleproxy["type"] = "tuic";
            if(!x.Token.empty())
            {
                singleproxy["token"] = x.Token;
            }
            else if(!x.UUID.empty() && !x.Password.empty())
            {
                singleproxy["uuid"] = x.UUID;
                singleproxy["password"] = x.Password;
            }
            else
            {
                continue;
            }
            if(!x.HeartbeatInterval.empty())
                singleproxy["heartbeat-interval"] = x.HeartbeatInterval;
            if(!x.AlpnList.empty())
            {
                for(auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if(!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if(!x.FastOpen.is_undef())
                singleproxy["fast-open"] = x.FastOpen.get();
            if(!x.UdpRelayMode.empty())
                singleproxy["udp-relay-mode"] = x.UdpRelayMode;
            if(!x.CongestionController.empty())
                singleproxy["congestion-controller"] = x.CongestionController;
            if(!x.BBRProfile.empty())
                singleproxy["bbr-profile"] = x.BBRProfile;
            if(x.CWND > 0)
                singleproxy["cwnd"] = x.CWND;
            if(!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            else if(!x.ServerName.empty())
                singleproxy["sni"] = x.ServerName;
            if(!x.DisableSNI.is_undef())
                singleproxy["disable-sni"] = x.DisableSNI.get();
            if(!x.ReduceRTT.is_undef())
                singleproxy["reduce-rtt"] = x.ReduceRTT.get();
            if(x.RequestTimeout != 0)
                singleproxy["request-timeout"] = x.RequestTimeout;
            if(x.MaxUdpRelayPacketSize != 0)
                singleproxy["max-udp-relay-packet-size"] = x.MaxUdpRelayPacketSize;
            if(x.MaxOpenStreams != 0)
                singleproxy["max-open-streams"] = x.MaxOpenStreams;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if(!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                else
                    singleproxy["ech-opts"]["enable"] = true;
                if(!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if(!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            if(x.TuicVersion != 0)
                singleproxy["version"] = x.TuicVersion;
            if(!x.UDPOverStream.is_undef())
                singleproxy["udp-over-stream"] = x.UDPOverStream.get();
            if(x.UDPOverStreamVersion > 0)
                singleproxy["udp-over-stream-version"] = x.UDPOverStreamVersion;
            if(!x.UDP.is_undef() && x.UDP.get())
                singleproxy["udp"] = true;
            else if(!x.UDP.is_undef() && !x.UDP.get())
                singleproxy["udp"] = false;
            else if(udp && !udp.is_undef())
                singleproxy["udp"] = udp.get();
            break;
        case ProxyType::GostRelay:
            singleproxy["type"] = "gost-relay";
            if(x.GostRelayForward)
                singleproxy["forward"] = true;
            if(!x.SmuxEnabled.is_undef())
                singleproxy["mux"] = x.SmuxEnabled.get();
            if(x.TLSSecure)
                singleproxy["tls"] = true;
            if(!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            else if(!x.ServerName.empty())
                singleproxy["sni"] = x.ServerName;
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
                singleproxy["password"] = x.Password;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(!x.UnderlyingProxy.empty())
                singleproxy["dialer-proxy"] = x.UnderlyingProxy;
            if(!x.UDP.is_undef() && x.UDP.get())
                singleproxy["udp"] = true;
            else if(!x.UDP.is_undef() && !x.UDP.get())
                singleproxy["udp"] = false;
            else if(udp && !udp.is_undef())
                singleproxy["udp"] = udp.get();
            break;
        case ProxyType::Masque:
            singleproxy["type"] = "masque";
            if(!x.PrivateKey.empty())
                singleproxy["private-key"] = x.PrivateKey;
            if(!x.PublicKey.empty())
                singleproxy["public-key"] = x.PublicKey;
            if(!x.IP.empty())
                singleproxy["ip"] = x.IP;
            if(!x.MasqueIPv6.empty())
                singleproxy["ipv6"] = x.MasqueIPv6;
            if(!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if(!x.TransferProtocol.empty())
                singleproxy["network"] = x.TransferProtocol;
            if(x.Mtu > 0)
                singleproxy["mtu"] = x.Mtu;
            if(x.CWND > 0)
                singleproxy["cwnd"] = x.CWND;
            if(!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            if(!x.UnderlyingProxy.empty())
                singleproxy["dialer-proxy"] = x.UnderlyingProxy;
            if(!x.RemoteDnsResolve.is_undef())
                singleproxy["remote-dns-resolve"] = x.RemoteDnsResolve.get();
            if(!x.DnsServers.empty())
            {
                YAML::Node dnsarr;
                for(auto &d : x.DnsServers)
                    dnsarr.push_back(d);
                singleproxy["dns"] = dnsarr;
            }
            if(!x.CongestionController.empty())
                singleproxy["congestion-controller"] = x.CongestionController;
            if(!x.BBRProfile.empty())
                singleproxy["bbr-profile"] = x.BBRProfile;
            break;
        case ProxyType::AnyTLS:
            singleproxy["type"] = "anytls";
            if(!x.Password.empty())
                singleproxy["password"] = x.Password;
            if(!x.SNI.empty())
                singleproxy["sni"] = x.SNI;
            if(!x.AlpnList.empty())
            {
                for(auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if(!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if(!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                else
                    singleproxy["ech-opts"]["enable"] = true;
                if(!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if(!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            if(x.IdleSessionCheckInterval != 0)
                singleproxy["idle-session-check-interval"] = x.IdleSessionCheckInterval;
            if(x.IdleSessionTimeout != 0)
                singleproxy["idle-session-timeout"] = x.IdleSessionTimeout;
            if(x.MinIdleSession != 0)
                singleproxy["min-idle-session"] = x.MinIdleSession;
            if(!x.Reuse.is_undef())
                singleproxy["reuse"] = x.Reuse.get();
            if(!x.PaddingScheme.empty())
                singleproxy["padding-scheme"] = x.PaddingScheme;
            if(!x.IPVersion.empty())
                singleproxy["ip-version"] = x.IPVersion;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            break;
        case ProxyType::VLESS:
            singleproxy["type"] = "vless";
            singleproxy["uuid"] = x.UUID;
            if(x.TLSSecure || x.TLSStr == "reality")
                singleproxy["tls"] = true;
            if(!x.Encryption.empty() && x.Encryption != "none")
                singleproxy["encryption"] = x.Encryption;
            if(!x.AlpnList.empty())
                for(auto &item: x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            if(!tfo.is_undef())
                singleproxy["fast-open"] = tfo.get();
            if(!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            else if(udp && !udp.is_undef() && udp.get())
                singleproxy["udp"] = true;
            if(!x.XUDP.is_undef())
                singleproxy["xudp"] = x.XUDP.get();
            else if(xudp && !xudp.is_undef())
                singleproxy["xudp"] = xudp.get();
            if(!x.PacketAddr.is_undef())
                singleproxy["packet-addr"] = x.PacketAddr.get();
            if(!x.PacketEncoding.empty())
                singleproxy["packet-encoding"] = x.PacketEncoding;
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            else if(!x.AllowInsecure.is_undef())
                singleproxy["skip-cert-verify"] = x.AllowInsecure.get();
            if(!x.SNI.empty())
                singleproxy["servername"] = x.SNI;
            else if(!x.ServerName.empty())
                singleproxy["servername"] = x.ServerName;
            else if(!x.Host.empty() && x.TransferProtocol != "grpc")
                singleproxy["servername"] = x.Host;
            if(!x.Fingerprint.empty())
                singleproxy["fingerprint"] = x.Fingerprint;
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            else if(!x.Fingerprint.empty() && x.TLSSecure)
                singleproxy["client-fingerprint"] = x.Fingerprint;
            if(!x.Certificate.empty())
                singleproxy["certificate"] = x.Certificate;
            if(!x.CertificateKey.empty())
                singleproxy["private-key"] = x.CertificateKey;
            if(x.XTLS == 2)
                singleproxy["flow"] = "xtls-rprx-vision";
            else if(!x.Flow.empty())
                singleproxy["flow"] = x.Flow;
            if(!x.FlowShow.is_undef())
                singleproxy["flow-show"] = x.FlowShow.get();
            if(!x.EchEnable.is_undef() || !x.EchConfig.empty() || !x.EchQueryServerName.empty())
            {
                if(!x.EchEnable.is_undef())
                    singleproxy["ech-opts"]["enable"] = x.EchEnable.get();
                else
                    singleproxy["ech-opts"]["enable"] = true;
                if(!x.EchConfig.empty())
                    singleproxy["ech-opts"]["config"] = x.EchConfig;
                if(!x.EchQueryServerName.empty())
                    singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
            }
            switch(hash_(x.TransferProtocol))
            {
                case "tcp"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    if(!x.PublicKey.empty() || x.Flow == "xtls-rprx-vision")
                    {
                        if(x.ClientFingerprint.empty() && x.Fingerprint.empty())
                            singleproxy["client-fingerprint"] = "chrome";
                        else if(!x.ClientFingerprint.empty())
                            singleproxy["client-fingerprint"] = x.ClientFingerprint;
                        else if(!x.Fingerprint.empty() && x.TLSSecure)
                            singleproxy["client-fingerprint"] = x.Fingerprint;
                    }
                    if(singleproxy["host"].IsDefined())
                        singleproxy.remove("host");
                    if(singleproxy["path"].IsDefined())
                        singleproxy.remove("path");
                    if(!x.PublicKey.empty())
                    {
                        singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                        singleproxy["reality-opts"]["short-id"] = x.ShortID;
                        if(!x.ServerName.empty())
                            singleproxy["reality-opts"]["servername"] = x.ServerName;
                        else if(!x.SNI.empty())
                            singleproxy["reality-opts"]["servername"] = x.SNI;
                        if(!x.SpiderX.empty())
                            singleproxy["reality-opts"]["spiderX"] = x.SpiderX;
                        if(!x.SupportX25519Mlkem768.is_undef())
                            singleproxy["reality-opts"]["support-x25519mlkem768"] = x.SupportX25519Mlkem768.get();
                    }
                    if(!x.EchConfig.empty())
                    {
                        singleproxy["ech-opts"]["enable"] = true;
                        singleproxy["ech-opts"]["config"] = x.EchConfig;
                    if(!x.EchQueryServerName.empty())
                        singleproxy["ech-opts"]["query-server-name"] = x.EchQueryServerName;
                    }
                    break;
                case "ws"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    if((x.TLSSecure && !x.Fingerprint.empty()) || (x.TLSStr == "reality" && !x.ClientFingerprint.empty()))
                    {
                        if(!x.ClientFingerprint.empty())
                            singleproxy["client-fingerprint"] = x.ClientFingerprint;
                        else if(!x.Fingerprint.empty() && x.TLSSecure)
                            singleproxy["client-fingerprint"] = x.Fingerprint;
                    }
                    if(ext.clash_new_field_name)
                    {
                        if(!x.WsPath.empty())
                            singleproxy["ws-opts"]["path"] = x.WsPath;
                        else
                            singleproxy["ws-opts"]["path"] = x.Path;
                        applyEncodedHeaders(x.WsHeadersMap, singleproxy["ws-opts"]["headers"]);
                        if(!x.Host.empty())
                            singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                        if(!x.Edge.empty())
                            singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                        if(!x.WsEarlyDataHeaderName.empty())
                            singleproxy["ws-opts"]["early-data-header-name"] = x.WsEarlyDataHeaderName;
                        if(x.WsMaxEarlyData > 0)
                            singleproxy["ws-opts"]["max-early-data"] = x.WsMaxEarlyData;
                        if(!x.V2rayHttpUpgrade.is_undef())
                            singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                        if(!x.V2rayHttpUpgradeFastOpen.is_undef())
                            singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"] = x.V2rayHttpUpgradeFastOpen.get();
                    }
                    else
                    {
                        singleproxy["ws-path"] = x.Path;
                        if(!x.Host.empty())
                            singleproxy["ws-headers"]["Host"] = x.Host;
                        if(!x.Edge.empty())
                            singleproxy["ws-headers"]["Edge"] = x.Edge;
                    }
                    break;
                case "http"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    singleproxy["http-opts"]["method"] = x.HTTPOptsMethod.empty() ? "GET" : x.HTTPOptsMethod;
                    if(!x.HTTPOptsPaths.empty())
                    {
                        for(const auto &item : x.HTTPOptsPaths)
                            singleproxy["http-opts"]["path"].push_back(item);
                    }
                    else
                    {
                        singleproxy["http-opts"]["path"].push_back(x.Path.empty() ? "/" : x.Path);
                    }
                    applyEncodedHeadersMultiValue(x.HTTPOptsHeaders, singleproxy["http-opts"]["headers"]);
                    if(!x.Host.empty())
                        singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                    if(!x.Edge.empty())
                        singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                    break;
                case "h2"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    singleproxy["h2-opts"]["path"] = x.Path.empty() ? "/" : x.Path;
                    if(!x.H2Hosts.empty())
                    {
                        for(const auto &item : x.H2Hosts)
                            singleproxy["h2-opts"]["host"].push_back(item);
                    }
                    else if(!x.Host.empty())
                        singleproxy["h2-opts"]["host"].push_back(x.Host);
                    break;
                case "xhttp"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    singleproxy["xhttp-opts"]["path"] = x.Path.empty() ? "/" : x.Path;
                    if(!x.Host.empty())
                        singleproxy["xhttp-opts"]["host"] = x.Host;
                    if(!x.XHTTPHeaders.empty())
                    {
                        string_array header_pairs = split(x.XHTTPHeaders, ";");
                        for(const auto &pair : header_pairs)
                        {
                            if(pair.empty())
                                continue;
                            const auto pos = pair.find('=');
                            if(pos == std::string::npos)
                                continue;
                            const auto key = urlDecode(pair.substr(0, pos));
                            const auto value = urlDecode(pair.substr(pos + 1));
                            if(key.empty())
                                continue;
                            if(toLower(key) == "host")
                                continue;
                            singleproxy["xhttp-opts"]["headers"][key] = value;
                        }
                    }
                    if(!x.GRPCMode.empty())
                        singleproxy["xhttp-opts"]["mode"] = x.GRPCMode;
                    if(!x.XHTTPNoGRPCHeader.is_undef())
                        singleproxy["xhttp-opts"]["no-grpc-header"] = x.XHTTPNoGRPCHeader.get();
                    if(!x.XHTTPXPaddingBytes.empty())
                        singleproxy["xhttp-opts"]["x-padding-bytes"] = x.XHTTPXPaddingBytes;
                    if(!x.XHTTPXPaddingObfsMode.is_undef())
                        singleproxy["xhttp-opts"]["x-padding-obfs-mode"] = x.XHTTPXPaddingObfsMode.get();
                    if(!x.XHTTPXPaddingKey.empty())
                        singleproxy["xhttp-opts"]["x-padding-key"] = x.XHTTPXPaddingKey;
                    if(!x.XHTTPXPaddingHeader.empty())
                        singleproxy["xhttp-opts"]["x-padding-header"] = x.XHTTPXPaddingHeader;
                    if(!x.XHTTPXPaddingPlacement.empty())
                        singleproxy["xhttp-opts"]["x-padding-placement"] = x.XHTTPXPaddingPlacement;
                    if(!x.XHTTPXPaddingMethod.empty())
                        singleproxy["xhttp-opts"]["x-padding-method"] = x.XHTTPXPaddingMethod;
                    if(!x.XHTTPUplinkHTTPMethod.empty())
                        singleproxy["xhttp-opts"]["uplink-http-method"] = x.XHTTPUplinkHTTPMethod;
                    if(!x.XHTTPSessionPlacement.empty())
                        singleproxy["xhttp-opts"]["session-placement"] = x.XHTTPSessionPlacement;
                    if(!x.XHTTPSessionKey.empty())
                        singleproxy["xhttp-opts"]["session-key"] = x.XHTTPSessionKey;
                    if(!x.XHTTPSessionTable.empty())
                        singleproxy["xhttp-opts"]["session-table"] = x.XHTTPSessionTable;
                    if(!x.XHTTPSessionLength.empty())
                        singleproxy["xhttp-opts"]["session-length"] = x.XHTTPSessionLength;
                    if(!x.XHTTPSeqPlacement.empty())
                        singleproxy["xhttp-opts"]["seq-placement"] = x.XHTTPSeqPlacement;
                    if(!x.XHTTPSeqKey.empty())
                        singleproxy["xhttp-opts"]["seq-key"] = x.XHTTPSeqKey;
                    if(!x.XHTTPUplinkDataPlacement.empty())
                        singleproxy["xhttp-opts"]["uplink-data-placement"] = x.XHTTPUplinkDataPlacement;
                    if(!x.XHTTPUplinkDataKey.empty())
                        singleproxy["xhttp-opts"]["uplink-data-key"] = x.XHTTPUplinkDataKey;
                    if(!x.XHTTPUplinkChunkSize.empty())
                        singleproxy["xhttp-opts"]["uplink-chunk-size"] = x.XHTTPUplinkChunkSize;
                    if(!x.XHTTPScMaxEachPostBytes.empty())
                        singleproxy["xhttp-opts"]["sc-max-each-post-bytes"] = x.XHTTPScMaxEachPostBytes;
                    if(!x.XHTTPScMaxBufferedPosts.empty())
                        singleproxy["xhttp-opts"]["sc-max-buffered-posts"] = x.XHTTPScMaxBufferedPosts;
                    if(!x.XHTTPScMinPostsIntervalMs.empty())
                        singleproxy["xhttp-opts"]["sc-min-posts-interval-ms"] = x.XHTTPScMinPostsIntervalMs;
                    if(!x.XHTTPReuseMaxConnections.empty() || !x.XHTTPReuseMaxConcurrency.empty() || !x.XHTTPReuseCMaxReuseTimes.empty() || !x.XHTTPReuseHMaxRequestTimes.empty() || !x.XHTTPReuseHMaxReusableSecs.empty() || x.XHTTPReuseHKeepAlivePeriod > 0)
                    {
                        if(!x.XHTTPReuseMaxConnections.empty())
                            singleproxy["xhttp-opts"]["reuse-settings"]["max-connections"] = x.XHTTPReuseMaxConnections;
                        if(!x.XHTTPReuseMaxConcurrency.empty())
                            singleproxy["xhttp-opts"]["reuse-settings"]["max-concurrency"] = x.XHTTPReuseMaxConcurrency;
                        if(!x.XHTTPReuseCMaxReuseTimes.empty())
                            singleproxy["xhttp-opts"]["reuse-settings"]["c-max-reuse-times"] = x.XHTTPReuseCMaxReuseTimes;
                        if(!x.XHTTPReuseHMaxRequestTimes.empty())
                            singleproxy["xhttp-opts"]["reuse-settings"]["h-max-request-times"] = x.XHTTPReuseHMaxRequestTimes;
                        if(!x.XHTTPReuseHMaxReusableSecs.empty())
                            singleproxy["xhttp-opts"]["reuse-settings"]["h-max-reusable-secs"] = x.XHTTPReuseHMaxReusableSecs;
                        if(x.XHTTPReuseHKeepAlivePeriod > 0)
                            singleproxy["xhttp-opts"]["reuse-settings"]["h-keep-alive-period"] = (int)x.XHTTPReuseHKeepAlivePeriod;
                    }
                    if(!x.XHTTPDownloadPath.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["path"] = x.XHTTPDownloadPath;
                    if(!x.XHTTPDownloadHost.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["host"] = x.XHTTPDownloadHost;
                    if(!x.XHTTPDownloadHeaders.empty())
                    {
                        string_array header_pairs = split(x.XHTTPDownloadHeaders, ";");
                        for(const auto &pair : header_pairs)
                        {
                            if(pair.empty())
                                continue;
                            const auto pos = pair.find('=');
                            if(pos == std::string::npos)
                                continue;
                            const auto key = urlDecode(pair.substr(0, pos));
                            const auto value = urlDecode(pair.substr(pos + 1));
                            if(key.empty())
                                continue;
                            if(toLower(key) == "host")
                                continue;
                            singleproxy["xhttp-opts"]["download-settings"]["headers"][key] = value;
                        }
                    }
                    if(!x.XHTTPDownloadReuseMaxConnections.empty() || !x.XHTTPDownloadReuseMaxConcurrency.empty() || !x.XHTTPDownloadReuseCMaxReuseTimes.empty() || !x.XHTTPDownloadReuseHMaxRequestTimes.empty() || !x.XHTTPDownloadReuseHMaxReusableSecs.empty() || x.XHTTPDownloadReuseHKeepAlivePeriod > 0)
                    {
                        if(!x.XHTTPDownloadReuseMaxConnections.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reuse-settings"]["max-connections"] = x.XHTTPDownloadReuseMaxConnections;
                        if(!x.XHTTPDownloadReuseMaxConcurrency.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reuse-settings"]["max-concurrency"] = x.XHTTPDownloadReuseMaxConcurrency;
                        if(!x.XHTTPDownloadReuseCMaxReuseTimes.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reuse-settings"]["c-max-reuse-times"] = x.XHTTPDownloadReuseCMaxReuseTimes;
                        if(!x.XHTTPDownloadReuseHMaxRequestTimes.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reuse-settings"]["h-max-request-times"] = x.XHTTPDownloadReuseHMaxRequestTimes;
                        if(!x.XHTTPDownloadReuseHMaxReusableSecs.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reuse-settings"]["h-max-reusable-secs"] = x.XHTTPDownloadReuseHMaxReusableSecs;
                        if(x.XHTTPDownloadReuseHKeepAlivePeriod > 0)
                            singleproxy["xhttp-opts"]["download-settings"]["reuse-settings"]["h-keep-alive-period"] = (int)x.XHTTPDownloadReuseHKeepAlivePeriod;
                    }
                    if(!x.XHTTPDownloadServer.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["server"] = x.XHTTPDownloadServer;
                    if(x.XHTTPDownloadPort != 0)
                        singleproxy["xhttp-opts"]["download-settings"]["port"] = x.XHTTPDownloadPort;
                    if(!x.XHTTPDownloadTLS.is_undef())
                        singleproxy["xhttp-opts"]["download-settings"]["tls"] = x.XHTTPDownloadTLS.get();
                    for(const auto &alpn : x.XHTTPDownloadALPN)
                        singleproxy["xhttp-opts"]["download-settings"]["alpn"].push_back(alpn);
                    if(!x.XHTTPDownloadECHEnable.is_undef() || !x.XHTTPDownloadECHConfig.empty() || !x.XHTTPDownloadECHQueryServerName.empty())
                    {
                        if(!x.XHTTPDownloadECHEnable.is_undef())
                            singleproxy["xhttp-opts"]["download-settings"]["ech-opts"]["enable"] = x.XHTTPDownloadECHEnable.get();
                        if(!x.XHTTPDownloadECHConfig.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["ech-opts"]["config"] = x.XHTTPDownloadECHConfig;
                        if(!x.XHTTPDownloadECHQueryServerName.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["ech-opts"]["query-server-name"] = x.XHTTPDownloadECHQueryServerName;
                    }
                    if(!x.XHTTPDownloadRealityPublicKey.empty() || !x.XHTTPDownloadRealityShortID.empty() || !x.XHTTPDownloadRealitySpiderX.empty() || !x.XHTTPDownloadRealitySupportX25519Mlkem768.is_undef())
                    {
                        if(!x.XHTTPDownloadRealityPublicKey.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reality-opts"]["public-key"] = x.XHTTPDownloadRealityPublicKey;
                        if(!x.XHTTPDownloadRealityShortID.empty())
                        {
                            singleproxy["xhttp-opts"]["download-settings"]["reality-opts"]["short-id"] = x.XHTTPDownloadRealityShortID;
                        }
                        if(!x.XHTTPDownloadRealitySpiderX.empty())
                            singleproxy["xhttp-opts"]["download-settings"]["reality-opts"]["spiderX"] = x.XHTTPDownloadRealitySpiderX;
                        if(!x.XHTTPDownloadRealitySupportX25519Mlkem768.is_undef())
                            singleproxy["xhttp-opts"]["download-settings"]["reality-opts"]["support-x25519mlkem768"] = x.XHTTPDownloadRealitySupportX25519Mlkem768.get();
                    }
                    if(!x.XHTTPDownloadSkipCertVerify.is_undef())
                        singleproxy["xhttp-opts"]["download-settings"]["skip-cert-verify"] = x.XHTTPDownloadSkipCertVerify.get();
                    if(!x.XHTTPDownloadFingerprint.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["fingerprint"] = x.XHTTPDownloadFingerprint;
                    if(!x.XHTTPDownloadCertificate.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["certificate"] = x.XHTTPDownloadCertificate;
                    if(!x.XHTTPDownloadPrivateKey.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["private-key"] = x.XHTTPDownloadPrivateKey;
                    if(!x.XHTTPDownloadServerName.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["servername"] = x.XHTTPDownloadServerName;
                    if(!x.XHTTPDownloadClientFingerprint.empty())
                        singleproxy["xhttp-opts"]["download-settings"]["client-fingerprint"] = x.XHTTPDownloadClientFingerprint;
                    break;
                case "grpc"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    singleproxy["grpc-opts"]["grpc-mode"] = x.GRPCMode;
                    if(!x.GrpcServiceName.empty())
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.GrpcServiceName;
                    else if(!x.Path.empty())
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                    if(!x.GrpcUserAgent.empty())
                        singleproxy["grpc-opts"]["grpc-user-agent"] = x.GrpcUserAgent;
                    if(x.GrpcPingInterval > 0)
                        singleproxy["grpc-opts"]["ping-interval"] = (int)x.GrpcPingInterval;
                    if(x.GrpcMaxConnections > 0)
                        singleproxy["grpc-opts"]["max-connections"] = (int)x.GrpcMaxConnections;
                    if(x.GrpcMinStreams > 0)
                        singleproxy["grpc-opts"]["min-streams"] = (int)x.GrpcMinStreams;
                    if(x.GrpcMaxStreams > 0)
                        singleproxy["grpc-opts"]["max-streams"] = (int)x.GrpcMaxStreams;
                    if(!x.PublicKey.empty() || x.Flow == "xtls-rprx-vision")
                    {
                        if(x.ClientFingerprint.empty() && x.Fingerprint.empty())
                            singleproxy["client-fingerprint"] = "chrome";
                        else if(!x.ClientFingerprint.empty())
                            singleproxy["client-fingerprint"] = x.ClientFingerprint;
                        else if(!x.Fingerprint.empty() && x.TLSSecure)
                            singleproxy["client-fingerprint"] = x.Fingerprint;
                    }
                    if(!x.PublicKey.empty())
                    {
                        singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                        singleproxy["reality-opts"]["short-id"] = x.ShortID;
                        if(!x.ServerName.empty())
                            singleproxy["reality-opts"]["servername"] = x.ServerName;
                        else if(!x.SNI.empty())
                            singleproxy["reality-opts"]["servername"] = x.SNI;
                        if(!x.SpiderX.empty())
                            singleproxy["reality-opts"]["spiderX"] = x.SpiderX;
                        if(!x.SupportX25519Mlkem768.is_undef())
                            singleproxy["reality-opts"]["support-x25519mlkem768"] = x.SupportX25519Mlkem768.get();
                    }
                    break;
                case "quic"_hash:
                    singleproxy["network"] = x.TransferProtocol;
                    if(!x.QUICSecure.empty())
                        singleproxy["quic-opts"]["security"] = x.QUICSecure;
                    else if(!x.Host.empty())
                        singleproxy["quic-opts"]["security"] = x.Host;
                    if(!x.QUICSecret.empty())
                        singleproxy["quic-opts"]["key"] = x.QUICSecret;
                    else if(!x.Path.empty())
                        singleproxy["quic-opts"]["key"] = x.Path;
                    if(!x.PublicKey.empty() || x.Flow == "xtls-rprx-vision")
                    {
                        if(x.ClientFingerprint.empty() && x.Fingerprint.empty())
                            singleproxy["client-fingerprint"] = "chrome";
                        else if(!x.ClientFingerprint.empty())
                            singleproxy["client-fingerprint"] = x.ClientFingerprint;
                        else if(!x.Fingerprint.empty() && x.TLSSecure)
                            singleproxy["client-fingerprint"] = x.Fingerprint;
                    }
                    if(!x.PublicKey.empty())
                    {
                        singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                        singleproxy["reality-opts"]["short-id"] = x.ShortID;
                        if(!x.ServerName.empty())
                            singleproxy["reality-opts"]["servername"] = x.ServerName;
                        else if(!x.SNI.empty())
                            singleproxy["reality-opts"]["servername"] = x.SNI;
                        if(!x.SpiderX.empty())
                            singleproxy["reality-opts"]["spiderX"] = x.SpiderX;
                        if(!x.SupportX25519Mlkem768.is_undef())
                            singleproxy["reality-opts"]["support-x25519mlkem768"] = x.SupportX25519Mlkem768.get();
                    }
                    break;
                default:
                    continue;
            }
            break;
        case ProxyType::Mieru:
            singleproxy["type"] = "mieru";
            if(!x.Password.empty())
                singleproxy["password"] = x.Password;
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Multiplexing.empty())
                singleproxy["multiplexing"] = x.Multiplexing;
            if(!x.TransferProtocol.empty())
                singleproxy["transport"] = x.TransferProtocol;
            if(!x.Ports.empty())
            {
                singleproxy["port-range"] = x.Ports;
                singleproxy.remove("port");
            }
            if(!x.PortRange.empty())
                singleproxy["port-range"] = x.PortRange;
            if(!x.HandshakeMode.empty())
                singleproxy["handshake-mode"] = x.HandshakeMode;
            if(!x.TrafficPattern.empty())
                singleproxy["traffic-pattern"] = x.TrafficPattern;
            break;
        case ProxyType::Sudoku:
            singleproxy["type"] = "sudoku";
            if(!x.Key.empty())
                singleproxy["key"] = x.Key;
            if(!x.AEAD.empty())
                singleproxy["aead-method"] = x.AEAD;
            if(x.PaddingMin > 0)
                singleproxy["padding-min"] = x.PaddingMin;
            if(x.PaddingMax > 0)
                singleproxy["padding-max"] = x.PaddingMax;
            if(!x.TableType.empty())
                singleproxy["table-type"] = x.TableType;
            if(!x.CustomTable.empty())
                singleproxy["custom-table"] = x.CustomTable;
            if(!x.CustomTables.empty())
            {
                YAML::Node ctNode;
                for(const std::string &t : x.CustomTables)
                    ctNode.push_back(t);
                singleproxy["custom-tables"] = ctNode;
            }
            if(x.HandshakeTimeout > 0)
                singleproxy["handshake-timeout"] = x.HandshakeTimeout;
            if(!x.EnablePureDownlink.is_undef())
                singleproxy["enable-pure-downlink"] = x.EnablePureDownlink.get();
            if(!x.DisableHTTPMask.is_undef() || !x.HTTPMask.is_undef() || !x.HTTPMaskMode.empty() || !x.HTTPMaskTLS.is_undef() ||
               !x.HTTPMaskHost.empty() || !x.PathRoot.empty() || !x.HTTPMaskMultiplex.empty())
            {
                YAML::Node httpmask;
                if(!x.DisableHTTPMask.is_undef())
                    httpmask["disable"] = x.DisableHTTPMask.get();
                else if(!x.HTTPMask.is_undef())
                    httpmask["disable"] = !x.HTTPMask.get();
                if(!x.HTTPMaskMode.empty())
                    httpmask["mode"] = x.HTTPMaskMode;
                if(!x.HTTPMaskTLS.is_undef())
                    httpmask["tls"] = x.HTTPMaskTLS.get();
                if(!x.HTTPMaskHost.empty())
                    httpmask["host"] = x.HTTPMaskHost;
                if(!x.PathRoot.empty())
                    httpmask["path-root"] = x.PathRoot;
                if(!x.HTTPMaskMultiplex.empty())
                    httpmask["multiplex"] = x.HTTPMaskMultiplex;
                singleproxy["httpmask"] = httpmask;
            }
            break;
        case ProxyType::TrustTunnel:
            singleproxy["type"] = "trusttunnel";
            if(!x.Username.empty())
                singleproxy["username"] = x.Username;
            if(!x.Password.empty())
                singleproxy["password"] = x.Password;
            if(!x.SNI.empty() || !x.ServerName.empty())
                singleproxy["sni"] = x.SNI.empty() ? x.ServerName : x.SNI;
            if(!x.AlpnList.empty())
            {
                for(auto &item : x.AlpnList)
                    singleproxy["alpn"].push_back(item);
            }
            else if(!x.Alpn.empty())
                singleproxy["alpn"].push_back(x.Alpn);
            if(!x.ClientFingerprint.empty())
                singleproxy["client-fingerprint"] = x.ClientFingerprint;
            if(!x.HealthCheck.is_undef())
                singleproxy["health-check"] = x.HealthCheck.get();
            if(!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            else if(!udp.is_undef())
                singleproxy["udp"] = udp.get();
            if(!scv.is_undef())
                singleproxy["skip-cert-verify"] = scv.get();
            if(!x.QUIC.is_undef())
                singleproxy["quic"] = x.QUIC.get();
            if(!x.CongestionController.empty())
                singleproxy["congestion-controller"] = x.CongestionController;
            break;
        case ProxyType::Tailscale:
            singleproxy["type"] = "tailscale";
            if(!x.Hostname.empty())
                singleproxy["hostname"] = x.Hostname;
            if(!x.TailscaleAuthKey.empty())
                singleproxy["auth-key"] = x.TailscaleAuthKey;
            if(!x.TailscaleControlURL.empty())
                singleproxy["control-url"] = x.TailscaleControlURL;
            if(!x.TailscaleStateDir.empty())
                singleproxy["state-dir"] = x.TailscaleStateDir;
            if(!x.TailscaleEphemeral.is_undef())
                singleproxy["ephemeral"] = x.TailscaleEphemeral.get();
            if(!x.UDP.is_undef())
                singleproxy["udp"] = x.UDP.get();
            else if(!udp.is_undef())
                singleproxy["udp"] = udp.get();
            if(!x.TailscaleAcceptRoutes.is_undef())
                singleproxy["accept-routes"] = x.TailscaleAcceptRoutes.get();
            if(!x.TailscaleExitNode.empty())
                singleproxy["exit-node"] = x.TailscaleExitNode;
            if(!x.TailscaleExitNodeAllowLANAccess.is_undef())
                singleproxy["exit-node-allow-lan-access"] = x.TailscaleExitNodeAllowLANAccess.get();
            break;
        default:
            continue;
        }

        // UDP is not supported yet in clash using snell
        // sees in https://dreamacro.github.io/clash/configuration/outbound.html#snell
        if(udp && x.Type != ProxyType::Snell && x.Type != ProxyType::TUIC)
            singleproxy["udp"] = true;
        if(!clashR && !x.UnderlyingProxy.empty())
            singleproxy["dialer-proxy"] = x.UnderlyingProxy;
        if(!tfo.is_undef())
            singleproxy["fast-open"] = tfo.get();
        if(proxy_block)
            singleproxy.SetStyle(YAML::EmitterStyle::Block);
        else
            singleproxy.SetStyle(YAML::EmitterStyle::Flow);
        proxies.push_back(singleproxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if(proxy_compact)
        proxies.SetStyle(YAML::EmitterStyle::Flow);

    if(ext.nodelist)
    {
        YAML::Node provider;
        provider["proxies"] = proxies;
        yamlnode.reset(provider);
        return;
    }

    if(ext.clash_new_field_name)
        yamlnode["proxies"] = proxies;
    else
        yamlnode["Proxy"] = proxies;


    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        YAML::Node singlegroup;
        string_array filtered_nodelist;

        singlegroup["name"] = x.Name;
        if (x.Type == ProxyGroupType::Smart)
            singlegroup["type"] = "url-test";
        else
            singlegroup["type"] = x.TypeStr();

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Relay:
            break;
        case ProxyGroupType::LoadBalance:
            singlegroup["strategy"] = x.StrategyStr();
            if(!x.Lazy.is_undef())
                singlegroup["lazy"] = x.Lazy.get();
            singlegroup["url"] = x.Url;
            if(x.Interval > 0)
                singlegroup["interval"] = x.Interval;
            [[fallthrough]];
        case ProxyGroupType::Smart:
            [[fallthrough]];
        case ProxyGroupType::URLTest:
            if(!x.Lazy.is_undef())
                singlegroup["lazy"] = x.Lazy.get();
            [[fallthrough]];
        case ProxyGroupType::Fallback:
            singlegroup["url"] = x.Url;
            if(x.Interval > 0)
                singlegroup["interval"] = x.Interval;
            if(x.Tolerance > 0)
                singlegroup["tolerance"] = x.Tolerance;
            break;
        default:
            continue;
        }
        if(!x.DisableUdp.is_undef())
            singlegroup["disable-udp"] = x.DisableUdp.get();

        for(const auto& y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(!x.UsingProvider.empty())
            singlegroup["use"] = x.UsingProvider;
        else
        {
            if(filtered_nodelist.empty())
                filtered_nodelist.emplace_back("DIRECT");
        }
        if(!filtered_nodelist.empty())
            singlegroup["proxies"] = filtered_nodelist;
        if(group_block)
            singlegroup.SetStyle(YAML::EmitterStyle::Block);
        else
            singlegroup.SetStyle(YAML::EmitterStyle::Flow);

        bool replace_flag = false;
        for(auto && original_group : original_groups)
        {
            if(original_group["name"].as<std::string>() == x.Name)
            {
                original_group.reset(singlegroup);
                replace_flag = true;
                break;
            }
        }
        if(!replace_flag)
            original_groups.push_back(singlegroup);
    }

    if(group_compact)
        original_groups.SetStyle(YAML::EmitterStyle::Flow);

    if(ext.clash_new_field_name)
        yamlnode["proxy-groups"] = original_groups;
    else
        yamlnode["Proxy Group"] = original_groups;
}

std::string proxyToClash(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, bool clashR, extra_settings &ext)
{
    YAML::Node yamlnode;

    try
    {
        yamlnode = YAML::Load(base_conf);
    }
    catch (std::exception &e)
    {
        writeLog(0, std::string("Clash base loader failed with error: ") + e.what(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToClash(nodes, yamlnode, extra_proxy_group, clashR, ext);

    if(ext.nodelist)
        return YAML::Dump(yamlnode);

    /*
    if(ext.enable_rule_generator)
        rulesetToClash(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);

    return YAML::Dump(yamlnode);
    */
    if(!ext.enable_rule_generator)
        return YAML::Dump(yamlnode);

    if(!ext.managed_config_prefix.empty() || ext.clash_script)
    {
        if(yamlnode["mode"].IsDefined())
        {
            if(ext.clash_new_field_name)
                yamlnode["mode"] = ext.clash_script ? "script" : "rule";
            else
                yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
        }

        renderClashScript(yamlnode, ruleset_content_array, ext.managed_config_prefix, ext.clash_script, ext.overwrite_original_rules, ext.clash_classical_ruleset);
        return YAML::Dump(yamlnode);
    }

    std::string output_content = rulesetToClashStr(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);
    output_content.insert(0, YAML::Dump(yamlnode));
    //rulesetToClash(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);
    //std::string output_content = YAML::Dump(yamlnode);

    return output_content;
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
std::string generatePeer(Proxy &node, bool client_id_as_reserved = false)
{
    std::string result;
    result += "public-key = " + node.PublicKey;
    result += ", endpoint = " + node.Hostname + ":" + std::to_string(node.Port);
    if(!node.PreSharedKey.empty())
        result += ", preshared-key = " + node.PreSharedKey;
    if(!node.AllowedIPs.empty())
        result += ", allowed-ips = \"" + node.AllowedIPs + "\"";
    if(node.KeepAlive > 0)
        result += ", keepalive = " + std::to_string(node.KeepAlive);
    if(!node.ClientId.empty())
    {
        if(client_id_as_reserved)
            result += ", reserved = [" + node.ClientId + "]";
        else
            result += ", client-id = " + node.ClientId;
    }
    return result;
}

std::string proxyToSurge(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, int surge_ver, extra_settings &ext)
{
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;
    unsigned short local_port = 1080;
    string_array remarks_list;

    ini.store_any_line = true;
    // filter out sections that requires direct-save
    ini.add_direct_save_section("General");
    ini.add_direct_save_section("Replica");
    ini.add_direct_save_section("Rule");
    ini.add_direct_save_section("MITM");
    ini.add_direct_save_section("Script");
    ini.add_direct_save_section("Host");
    ini.add_direct_save_section("URL Rewrite");
    ini.add_direct_save_section("Header Rewrite");
    if(ini.parse(base_conf) != 0 && !ext.nodelist)
    {
        writeLog(0, "Surge base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();
    ini.set("{NONAME}", "DIRECT = direct");

    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &sni = x.ServerName, &username = x.Username, &password = x.Password, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &edge = x.Edge, &path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &plugin = x.Plugin, &pluginopts = x.PluginOption, &underlying_proxy = x.UnderlyingProxy;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        std::string proxy, section, real_section;
        string_array args, headers;

        std::stringstream ss;

        switch (x.Type)
        {
        case ProxyType::Shadowsocks:
            if(surge_ver >= 3 || surge_ver == -3)
            {
                proxy = "ss, " + hostname + ", " + port + ", encrypt-method=" + method + ", password=" + password;
            }
            else
            {
                proxy = "custom, "  + hostname + ", " + port + ", " + method + ", " + password + ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module";
            }
            if(!plugin.empty())
            {
                switch(hash_(plugin))
                {
                case "simple-obfs"_hash:
                case "obfs-local"_hash:
                    if(!pluginopts.empty())
                        proxy += "," + replaceAllDistinct(pluginopts, ";", ",");
                    break;
                default:
                    continue;
                }
            }
            break;
        case ProxyType::VMess:
            if(surge_ver < 4 && surge_ver != -3)
                continue;
            proxy = "vmess, " + hostname + ", " + port + ", username=" + id;
            if(surge_ver == -3)
            {
                proxy += ", udp-relay=" + std::string(udp.is_undef() ? "false" : udp.get_str());
                udp = tribool();
            }
            switch(hash_(transproto))
            {
            case "tcp"_hash:
                if(surge_ver == -3)
                    proxy += ", ws=false";
                break;
            case "ws"_hash:
                proxy += ", ws=true, ws-path=" + (path.empty() ? "/" : path);
                if(!host.empty())
                    headers.push_back("Host:" + host);
                if(!edge.empty())
                    headers.push_back("Edge:" + edge);
                if(!headers.empty())
                    proxy += ", ws-headers=" + join(headers, "|");
                break;
            default:
                continue;
            }
            proxy += ", tls=" + std::string(tlssecure ? "true" : "false");
            if(tlssecure && !scv.is_undef())
                proxy += ", skip-cert-verify=" + scv.get_str();
            if(tlssecure)
            {
                if(!x.ServerName.empty())
                    proxy += ", sni=" + x.ServerName;
                else if(!x.SNI.empty())
                    proxy += ", sni=" + x.SNI;
                else if(!host.empty())
                    proxy += ", sni=" + host;
                else
                    proxy += ", sni=" + hostname;
            }
            proxy += ", vmess-aead=" + std::string(x.AlterId == 0 ? "true" : "false");
            if(tlssecure && !tls13.is_undef())
                proxy += ", tls13=" + std::string(tls13 ? "true" : "false");
            break;
        case ProxyType::ShadowsocksR:
            if(ext.surge_ssr_path.empty() || surge_ver < 2)
                continue;
            proxy = "external, exec=\"" + ext.surge_ssr_path + "\", args=\"";
            args = {"-l", std::to_string(local_port), "-s", hostname, "-p", port, "-m", method, "-k", password, "-o", obfs, "-O", protocol};
            if(!obfsparam.empty())
            {
                args.emplace_back("-g");
                args.emplace_back(std::move(obfsparam));
            }
            if(!protoparam.empty())
            {
                args.emplace_back("-G");
                args.emplace_back(std::move(protoparam));
            }
            proxy += join(args, "\", args=\"");
            proxy += "\", local-port=" + std::to_string(local_port);
            if(isIPv4(hostname) || isIPv6(hostname))
                proxy += ", addresses=" + hostname;
            else if(global.surgeResolveHostname)
                proxy += ", addresses=" + hostnameToIPAddr(hostname);
            local_port++;
            break;
        case ProxyType::SOCKS5:
            proxy = (surge_ver == -3 && tlssecure) ? "socks5-tls, " : "socks5, ";
            proxy += hostname + ", " + port;
            if(surge_ver == -3)
            {
                if(!username.empty())
                    proxy += ", " + username;
                if(!password.empty())
                    proxy += ", " + password;
            }
            else
            {
                if(!username.empty())
                    proxy += ", username=" + username;
                if(!password.empty())
                    proxy += ", password=" + password;
            }
            if(surge_ver == -3 ? tlssecure && !scv.is_undef() : !scv.is_undef())
                proxy += ", skip-cert-verify=" + scv.get_str();
            if(surge_ver == -3 && tlssecure && !sni.empty())
                proxy += ", sni=" + sni;
            break;
        case ProxyType::HTTPS:
            if(surge_ver == -3)
            {
                proxy = "https, " + hostname + ", " + port;
                if(!username.empty())
                    proxy += ", " + username;
                if(!password.empty())
                    proxy += ", " + password;
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                if(!sni.empty())
                    proxy += ", sni=" + sni;
                break;
            }
            [[fallthrough]];
        case ProxyType::HTTP:
            if(surge_ver == -3)
            {
                proxy = "http, " + hostname + ", " + port;
                if(!username.empty())
                    proxy += ", " + username;
                if(!password.empty())
                    proxy += ", " + password;
            }
            else
            {
                proxy = "http, " + hostname + ", " + port;
                if(!username.empty())
                    proxy += ", username=" + username;
                if(!password.empty())
                    proxy += ", password=" + password;
                proxy += std::string(", tls=") + (x.TLSSecure ? "true" : "false");
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
            }
            break;
        case ProxyType::Trojan:
            if(surge_ver < 4 && surge_ver != -3)
                continue;
            proxy = "trojan, " + hostname + ", " + port + ", password=" + password;
            if(x.SnellVersion != 0 && surge_ver != -3)
                proxy += ", version=" + std::to_string(x.SnellVersion);
            if(surge_ver == -3 && !udp.is_undef())
            {
                proxy += ", udp-relay=" + udp.get_str();
                udp = tribool();
            }
            if(!scv.is_undef())
                proxy += ", skip-cert-verify=" + scv.get_str();
            if(!sni.empty())
                proxy += ", sni=" + sni;
            else if(!host.empty())
                proxy += ", sni=" + host;
            if (transproto == "ws") {
                proxy += ", ws=true, ws-path=" + (path.empty() ? "/" : path);
                if (!host.empty())
                    headers.push_back("Host:" + host);
                if (!headers.empty())
                    proxy += ", ws-headers=" + join(headers, "|");
            }
            break;
        case ProxyType::Snell:
            proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
            if(surge_ver == -3 && !udp.is_undef())
            {
                proxy += ", udp-relay=" + udp.get_str();
                udp = tribool();
            }
            if(!obfs.empty())
            {
                proxy += ", obfs=" + obfs;
                if(!host.empty())
                    proxy += ", obfs-host=" + host;
                if(obfs == "http" && !path.empty())
                    proxy += ", obfs-uri=" + path;
            }
            if(x.SnellVersion != 0)
                proxy += ", version=" + std::to_string(x.SnellVersion);
            break;
        case ProxyType::WireGuard:
            if(surge_ver < 4 && surge_ver != -3)
                continue;
            ss << std::hex << hash_(x.Remark);
            section = ss.str().substr(0, 5);
            real_section = "WireGuard " + section;
            proxy = "wireguard, section-name=" + section;
            if(!x.TestUrl.empty())
                proxy += ", test-url=" + x.TestUrl;
            ini.set(real_section, "private-key", x.PrivateKey);
            ini.set(real_section, "self-ip", x.SelfIP);
            if(!x.SelfIPv6.empty())
                ini.set(real_section, "self-ip-v6", x.SelfIPv6);
            if(!x.DnsServers.empty())
                ini.set(real_section, "dns-server", join(x.DnsServers, ","));
            if(x.Mtu > 0)
                ini.set(real_section, "mtu", std::to_string(x.Mtu));
            ini.set(real_section, "peer", "(" + generatePeer(x) + ")");
            break;
        case ProxyType::Hysteria2:
            if(surge_ver < 5 && surge_ver != -3)
                continue;
            proxy = surge_ver == -3 ? "hysteria2, " : "hysteria, ";
            proxy += hostname + ", " + port + ", password=" + password;
            if(x.DownSpeed)
                proxy += ", download-bandwidth=" + std::to_string(x.DownSpeed);
            else if(!x.Down.empty())
                proxy += ", download-bandwidth=" + x.Down;
            if(x.UpSpeed)
                proxy += ", upload-bandwidth=" + std::to_string(x.UpSpeed);
            else if(!x.Up.empty())
                proxy += ", upload-bandwidth=" + x.Up;
            if(!x.Ports.empty() && x.Ports != port)
                proxy += ", port-hopping=\"" + x.Ports + "\"";
            if(x.HopInterval)
                proxy += ", port-hopping-interval=" + std::to_string(x.HopInterval);
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ",server-cert-fingerprint-sha256=" + x.Fingerprint;
            if(!x.SNI.empty())
                proxy += ",sni=" + x.SNI;
            else if(!x.ServerName.empty())
                proxy += ",sni=" + x.ServerName;
            break;
        case ProxyType::TUIC:
            if(surge_ver < 5 && surge_ver != -3)
                continue;
            proxy = "tuic-v5, " + hostname + ", " + port + ", password=" + password;
            if(!x.UUID.empty())
                    proxy += ",uuid=" + x.UUID;
            if(!x.SNI.empty())
                proxy += ",sni=" + x.SNI;
            else if(!x.ServerName.empty())
                proxy += ",sni=" + x.ServerName;
            if(!x.Alpn.empty())
                proxy += ",alpn=" + x.Alpn;
            else if(!x.AlpnList.empty())
                proxy += ",alpn=" + x.AlpnList.front();
            if(!x.CongestionController.empty())
                proxy += ",congestion-controller=" + x.CongestionController;
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + scv.get_str();
            break;
        case ProxyType::AnyTLS:
            if(surge_ver < 5 && surge_ver != -3)
                continue;
            if(surge_ver == -3)
            {
                proxy = "anytls, " + hostname + ", " + port + ", " + password;
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                if(!x.SNI.empty())
                    proxy += ", sni=" + x.SNI;
                else if(!x.ServerName.empty())
                    proxy += ", sni=" + x.ServerName;
                if(!x.Reuse.is_undef())
                    proxy += ", reuse=" + x.Reuse.get_str();
            }
            else
            {
                proxy = "anytls, " + hostname + ", " + port + ", password=" + password;
                if(!x.SNI.empty())
                    proxy += ", sni=" + x.SNI;
                else if(!x.ServerName.empty())
                    proxy += ", sni=" + x.ServerName;
                if(!x.Alpn.empty())
                    proxy += ", alpn=" + x.Alpn;
                else if(!x.AlpnList.empty())
                    proxy += ", alpn=" + join(x.AlpnList, ",");
                if(!x.Fingerprint.empty())
                    proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
                if(x.IdleSessionCheckInterval > 0)
                    proxy += ", idle-session-check-interval=" + std::to_string(x.IdleSessionCheckInterval);
                if(x.IdleSessionTimeout > 0)
                    proxy += ", idle-session-timeout=" + std::to_string(x.IdleSessionTimeout);
                if(x.MinIdleSession > 0)
                    proxy += ", min-idle-session=" + std::to_string(x.MinIdleSession);
                if(!x.PaddingScheme.empty())
                    proxy += ", padding-scheme=" + x.PaddingScheme;
                if(!x.IPVersion.empty())
                    proxy += ", ip-version=" + x.IPVersion;
                if(!tls13.is_undef())
                    proxy += ", tls13=" + tls13.get_str();
                if(!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                if(!x.Reuse.is_undef())
                    proxy += ", reuse=" + x.Reuse.get_str();
            }
            break;
        default:
            continue;
        }

        if(!tfo.is_undef())
            proxy += ", tfo=" + tfo.get_str();
        if(!udp.is_undef())
            proxy += ", udp-relay=" + udp.get_str();

        if (underlying_proxy != "")
            proxy += ", underlying-proxy=" + underlying_proxy;

        if (ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else
        {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
        }
        remarks_list.emplace_back(x.Remark);
    }

    if(ext.nodelist)
        return output_nodelist;

    string_multimap original_groups;
    ini.set_current_section("Proxy Group");
    ini.get_items(original_groups);
    ini.erase_section();
    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string group;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Smart:
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Fallback:
            break;
        case ProxyGroupType::LoadBalance:
            if(surge_ver < 1 && surge_ver != -3)
                continue;
            break;
        case ProxyGroupType::SSID:
            group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
                group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
                ini.set("{NONAME}", x.Name + " = " + group); //insert order
            continue;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        if(filtered_nodelist.size() == 1)
        {
            group = toLower(filtered_nodelist[0]);
            switch(hash_(group))
            {
            case "direct"_hash:
            case "reject"_hash:
            case "reject-tinygif"_hash:
                ini.set("Proxy", "{NONAME}", x.Name + " = " + group);
                continue;
            }
        }

        group = x.TypeStr() + ",";
        group += join(filtered_nodelist, ",");
        if(x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Fallback || x.Type == ProxyGroupType::LoadBalance)
        {
            group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
            if(x.Tolerance > 0)
                group += ",tolerance=" + std::to_string(x.Tolerance);
            if(x.Timeout > 0)
                group += ",timeout=" + std::to_string(x.Timeout);
            if(!x.Persistent.is_undef())
                group += ",persistent=" + x.Persistent.get_str();
            if(!x.EvaluateBeforeUse.is_undef())
                group += ",evaluate-before-use=" + x.EvaluateBeforeUse.get_str();
        }

        auto iter = original_groups.find(x.Name);
        if(iter != original_groups.end())
        {
            string_array vArray = split(iter->second, ",");
            if(vArray.size() > 1)
            {
                std::string content = trim(vArray[vArray.size() - 1]);
                if(content.find("icon-url") == 0)
                    group += "," + content;
            }
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, surge_ver, ext.overwrite_original_rules, ext.managed_config_prefix);

    return ini.to_string();
}

std::string proxyToSurfboard(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::vector<Proxy> filtered_nodes;
    filtered_nodes.reserve(nodes.size());

    for(const auto &node : nodes)
    {
        switch(node.Type)
        {
        case ProxyType::Shadowsocks:
        case ProxyType::VMess:
        case ProxyType::SOCKS5:
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
        case ProxyType::Trojan:
        case ProxyType::Snell:
        case ProxyType::WireGuard:
        case ProxyType::Hysteria2:
        case ProxyType::AnyTLS:
            filtered_nodes.push_back(node);
            break;
        default:
            break;
        }
    }

    return proxyToSurge(filtered_nodes, base_conf, ruleset_content_array, extra_proxy_group, -3, ext);
}

std::string proxyToSingle(std::vector<Proxy> &nodes, int types, extra_settings &ext)
{
    /// types: SS=1 SSR=2 VMess=4 Trojan=8 hysteria=16 vless=32 sudoku=64 hysteria2=128 tuic=256 anytls=512 trusttunnel=1024 mieru=2048 wireguard=4096 masque=8192
    std::string proxyStr, allLinks;
    bool ss = GETBIT(types, 1), ssr = GETBIT(types, 2), vmess = GETBIT(types, 3), trojan = GETBIT(types, 4), hysteria = GETBIT(types, 5), vless = GETBIT(types, 6), sudoku = GETBIT(types, 7), hysteria2 = GETBIT(types, 8), tuic = GETBIT(types, 9), anytls = GETBIT(types, 10), trusttunnel = GETBIT(types, 11), mieru = GETBIT(types, 12), wireguard = GETBIT(types, 13), masque = GETBIT(types, 14), openvpn = GETBIT(types, 15);

    for(Proxy &x : nodes)
    {
        std::string remark = x.Remark;
        std::string &hostname = x.Hostname, &password = x.Password, &username = x.Username, &method = x.EncryptMethod, &plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &fake_type = x.FakeType, &flow = x.Flow, &public_key = x.PublicKey, &short_id = x.ShortID, &spider_x = x.SpiderX, &fingerprint = x.Fingerprint, &packet_encoding = x.PacketEncoding, &mode = x.GRPCMode, &tls = x.TLSStr, &faketype = x.FakeType, &ports = x.Ports;
        std::string id = (x.Type == ProxyType::VLESS) ? x.UUID : x.UserId;
        std::string sni = (x.Type == ProxyType::VLESS || x.Type == ProxyType::Hysteria || x.Type == ProxyType::Hysteria2 || x.Type == ProxyType::TUIC || x.Type == ProxyType::AnyTLS) ? x.SNI : x.ServerName;
        bool &tlssecure = x.TLSSecure;
        std::vector<string> alpns = x.AlpnList;
        std::string port = std::to_string(x.Port);
        std::string aid = std::to_string(x.AlterId);

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(ss)
            {
                std::string query;
                auto append_query = [&query](const std::string &key, const std::string &value) {
                    if(value.empty())
                        return;
                    if(!query.empty())
                        query += "&";
                    query += key + "=" + value;
                };
                proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                if(!plugin.empty())
                {
                    std::string plugin_value = plugin;
                    if(!pluginopts.empty())
                        plugin_value += ";" + pluginopts;
                    append_query("plugin", urlEncode(plugin_value));
                }
                if(!x.UDP.is_undef())
                    append_query("udp", x.UDP.get() ? "1" : "0");
                if(!x.TCPFastOpen.is_undef())
                    append_query("tfo", x.TCPFastOpen.get() ? "1" : "0");
                if(!x.AllowInsecure.is_undef())
                    append_query("insecure", x.AllowInsecure.get() ? "1" : "0");
                if(!x.IPVersion.empty())
                    append_query("ip-version", urlEncode(x.IPVersion));
                if(!x.ClientFingerprint.empty())
                    append_query("client-fingerprint", urlEncode(x.ClientFingerprint));
                if(!x.UDPoverTCP.is_undef())
                    append_query("udp-over-tcp", x.UDPoverTCP.get() ? "1" : "0");
                if(x.UDPOverTCPVersion > 0)
                    append_query("udp-over-tcp-version", std::to_string(x.UDPOverTCPVersion));
                if(!query.empty())
                    proxyStr += "/?" + query;
                proxyStr += "#" + urlEncode(remark);
            }
            else if(ssr)
            {
                if(std::find(ssr_ciphers.begin(), ssr_ciphers.end(), method) != ssr_ciphers.end() && plugin.empty())
                    proxyStr = "ssr://" + urlSafeBase64Encode(hostname + ":" + port + ":origin:" + method + ":plain:" + urlSafeBase64Encode(password) \
                               + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(remark));
            }
            else
                continue;
            break;
        case ProxyType::ShadowsocksR:
            if(ssr)
            {
                proxyStr = "ssr://" + urlSafeBase64Encode(hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" + urlSafeBase64Encode(password) \
                           + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(remark) \
                           + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" + urlSafeBase64Encode(protoparam));
            }
            else if(ss)
            {
                if(std::find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && protocol == "origin" && obfs == "plain")
                    proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port + "#" + urlEncode(remark);
            }
            else
                continue;
            break;
        case ProxyType::VMess:
            if(!vmess)
                continue;
            {
                std::string vmess_sni = sni.empty() ? (tlssecure ? host : "") : sni;
                std::string vmess_alpn;
                if(!alpns.empty())
                    vmess_alpn = alpns[0];
                std::string vmess_skip_cert_verify;
                if(!x.AllowInsecure.is_undef())
                    vmess_skip_cert_verify = x.AllowInsecure.get() ? "true" : "false";
                std::string vmess_udp, vmess_tfo, vmess_ip_version, vmess_packet_encoding, vmess_authlen, vmess_globalpad, vmess_ech_enable, vmess_ech_config, vmess_client_fp;
                if(!x.UDP.is_undef())
                    vmess_udp = x.UDP.get() ? "true" : "false";
                if(!x.TCPFastOpen.is_undef())
                    vmess_tfo = x.TCPFastOpen.get() ? "true" : "false";
                if(!x.IPVersion.empty())
                    vmess_ip_version = x.IPVersion;
                if(!x.PacketEncoding.empty())
                    vmess_packet_encoding = x.PacketEncoding;
                if(!x.AuthenticatedLength.is_undef())
                    vmess_authlen = x.AuthenticatedLength.get() ? "true" : "false";
                if(!x.GlobalPadding.is_undef())
                    vmess_globalpad = x.GlobalPadding.get() ? "true" : "false";
                if(!x.EchEnable.is_undef())
                    vmess_ech_enable = x.EchEnable.get() ? "true" : "false";
                if(!x.EchConfig.empty())
                    vmess_ech_config = x.EchConfig;
                if(!x.ClientFingerprint.empty())
                    vmess_client_fp = x.ClientFingerprint;
                else if(!fingerprint.empty())
                    vmess_client_fp = fingerprint;

                proxyStr = "vmess://" + base64Encode(vmessLinkConstruct(remark, hostname, port, faketype, id, aid, transproto, path, host, tlssecure ? "tls" : "", vmess_sni, vmess_alpn, fingerprint, vmess_skip_cert_verify, vmess_udp, vmess_tfo, vmess_ip_version, vmess_packet_encoding, vmess_authlen, vmess_globalpad, vmess_ech_enable, vmess_ech_config, vmess_client_fp));
            }
            break;
        case ProxyType::Trojan:
            if(!trojan)
                continue;
            proxyStr = "trojan://" + password + "@" + hostname + ":" + port + "?allowInsecure=" + (x.AllowInsecure.get() ? "1" : "0");
            if(!sni.empty())
                proxyStr += "&sni=" + sni;
            else if(!host.empty())
                proxyStr += "&sni=" + host;
            if(!x.UDP.is_undef())
                proxyStr += "&udp=" + std::string(x.UDP.get() ? "1" : "0");
            if(!x.TCPFastOpen.is_undef())
                proxyStr += "&tfo=" + std::string(x.TCPFastOpen.get() ? "1" : "0");
            if(!flow.empty())
                proxyStr += "&flow=" + urlEncode(flow);
            if(!fingerprint.empty())
                proxyStr += "&fingerprint=" + fingerprint;
            if(!x.ClientFingerprint.empty())
                proxyStr += "&client-fingerprint=" + x.ClientFingerprint;
            if(!alpns.empty())
                proxyStr += "&alpn=" + urlEncode(alpns[0]);
            if(transproto == "grpc")
            {
                proxyStr += "&type=grpc";
                if(!path.empty())
                    proxyStr += "&serviceName=" + urlEncode(path);
            }
            if(transproto == "ws")
            {
                proxyStr += "&ws=1";
                if(!path.empty())
                    proxyStr += "&wspath=" + urlEncode(path);
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::Sudoku:
            if(!sudoku)
                continue;
            proxyStr = "sudoku://" + hostname + ":" + port;
            if(!x.Key.empty())
                proxyStr += "?" + std::string("key=") + urlEncode(x.Key);
            if(!x.AEAD.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("aead-method=") + urlEncode(x.AEAD);
            if(x.PaddingMin > 0)
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("padding-min=") + std::to_string(x.PaddingMin);
            if(x.PaddingMax > 0)
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("padding-max=") + std::to_string(x.PaddingMax);
            if(!x.TableType.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("table-type=") + urlEncode(x.TableType);
            if(!x.HTTPMask.is_undef())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("http-mask=") + (x.HTTPMask.get() ? "1" : "0");
            if(!x.HTTPMaskMode.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("http-mask-mode=") + urlEncode(x.HTTPMaskMode);
            if(!x.HTTPMaskTLS.is_undef())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("http-mask-tls=") + (x.HTTPMaskTLS.get() ? "1" : "0");
            if(!x.HTTPMaskHost.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("http-mask-host=") + urlEncode(x.HTTPMaskHost);
            if(!x.HTTPMaskMultiplex.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("http-mask-multiplex=") + urlEncode(x.HTTPMaskMultiplex);
            if(!x.DisableHTTPMask.is_undef())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("disable-http-mask=") + (x.DisableHTTPMask.get() ? "1" : "0");
            if(!x.PathRoot.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("path-root=") + urlEncode(x.PathRoot);
            if(x.HandshakeTimeout > 0)
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("handshake-timeout=") + std::to_string(x.HandshakeTimeout);
            if(!x.EnablePureDownlink.is_undef())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("enable-pure-downlink=") + (x.EnablePureDownlink.get() ? "1" : "0");
            if(!x.CustomTable.empty())
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("custom-table=") + urlEncode(x.CustomTable);
            if(!x.CustomTables.empty())
            {
                std::string joined_tables;
                for(size_t i = 0; i < x.CustomTables.size(); ++i)
                {
                    if(i != 0) joined_tables += ",";
                    joined_tables += x.CustomTables[i];
                }
                proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") + std::string("custom-tables=") + urlEncode(joined_tables);
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::TrustTunnel:
            if(!trusttunnel)
                continue;
            proxyStr = "trusttunnel://" + urlSafeBase64Encode(username + ":" + password) + "@" + hostname + ":" + port;
            {
                std::string query;
                auto append_query = [&query](const std::string &key, const std::string &value) {
                    if(value.empty())
                        return;
                    if(!query.empty())
                        query += "&";
                    query += key + "=" + urlEncode(value);
                };
                if(!sni.empty())
                    append_query("sni", sni);
                else if(!host.empty())
                    append_query("sni", host);
                if(!alpns.empty())
                    append_query("alpn", join(alpns, ","));
                if(!x.ClientFingerprint.empty())
                    append_query("client-fingerprint", x.ClientFingerprint);
                if(!x.HealthCheck.is_undef())
                    append_query("health-check", x.HealthCheck.get() ? "true" : "false");
                if(!x.UDP.is_undef())
                    append_query("udp", x.UDP.get() ? "1" : "0");
                if(!x.AllowInsecure.is_undef())
                    append_query("skip-cert-verify", x.AllowInsecure.get() ? "1" : "0");
                if(!x.QUIC.is_undef())
                    append_query("quic", x.QUIC.get() ? "true" : "false");
                if(!x.CongestionController.empty())
                    append_query("congestion-controller", x.CongestionController);
                if(!query.empty())
                    proxyStr += "?" + query;
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::Tailscale:
            continue;
        case ProxyType::OpenVPN:
            if(!openvpn)
                continue;
            // OpenVPN URL format: openvpn://[username:password@]server:port?proto=udp&cipher=AES-256-GCM&auth=SHA256&ca=<base64>&cert=<base64>&key=<base64>&tls-crypt=<base64>
            if(!username.empty() && !password.empty())
                proxyStr = "openvpn://" + urlEncode(username) + ":" + urlEncode(password) + "@" + hostname + ":" + port;
            else
                proxyStr = "openvpn://" + hostname + ":" + port;
            {
                std::string query;
                auto append_query = [&query](const std::string &key, const std::string &value) {
                    if(value.empty())
                        return;
                    if(!query.empty())
                        query += "&";
                    query += key + "=" + urlEncode(value);
                };
                if(!transproto.empty() && transproto != "udp")
                    append_query("proto", transproto);
                if(!x.OpenVPNDev.empty())
                    append_query("dev", x.OpenVPNDev);
                if(!method.empty())
                    append_query("cipher", method);
                if(!x.Auth.empty())
                    append_query("auth", x.Auth);
                if(!x.Ca.empty())
                    append_query("ca", urlSafeBase64Encode(x.Ca));
                if(!x.Certificate.empty())
                    append_query("cert", urlSafeBase64Encode(x.Certificate));
                if(!x.CertificateKey.empty())
                    append_query("key", urlSafeBase64Encode(x.CertificateKey));
                if(!x.OpenVPNTLSCrypt.empty())
                    append_query("tls-crypt", urlSafeBase64Encode(x.OpenVPNTLSCrypt));
                if(!x.CompLZO.empty())
                    append_query("comp-lzo", x.CompLZO);
                if(x.OpenVPNPing > 0)
                    append_query("ping", std::to_string(x.OpenVPNPing));
                if(x.OpenVPNPingRestart > 0)
                    append_query("ping-restart", std::to_string(x.OpenVPNPingRestart));
                if(x.Mtu > 0)
                    append_query("mtu", std::to_string(x.Mtu));
                if(!x.RemoteDnsResolve.is_undef())
                    append_query("remote-dns-resolve", x.RemoteDnsResolve.get() ? "1" : "0");
                if(!x.DnsServers.empty())
                    append_query("dns", join(x.DnsServers, ","));
                if(!query.empty())
                    proxyStr += "?" + query;
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::WireGuard:
            if(!wireguard)
                continue;
            proxyStr = "wireguard://" + public_key + "@" + hostname + ":" + port;
            {
                std::string query;
                auto append_query = [&query](const std::string &key, const std::string &value) {
                    if(value.empty())
                        return;
                    if(!query.empty())
                        query += "&";
                    query += key + "=" + urlEncode(value);
                };
                append_query("private-key", x.PrivateKey);
                append_query("self-ip", x.SelfIP);
                append_query("self-ip-v6", x.SelfIPv6);
                append_query("preshared-key", x.PreSharedKey);
                if(!x.DnsServers.empty())
                    append_query("dns", join(x.DnsServers, ","));
                if(x.Mtu > 0)
                    append_query("mtu", std::to_string(x.Mtu));
                if(!x.AllowedIPs.empty())
                    append_query("allowed-ips", x.AllowedIPs);
                if(x.KeepAlive > 0)
                    append_query("keepalive", std::to_string(x.KeepAlive));
                if(!x.Reserved.empty())
                    append_query("reserved", join(x.Reserved, ","));
                if(!x.Peers.empty())
                    append_query("peers", join(x.Peers, ","));
                append_query("dialer-proxy", x.DialerProxy);
                if(!x.RemoteDnsResolve.is_undef())
                    append_query("remote-dns-resolve", x.RemoteDnsResolve.get() ? "1" : "0");
                if(!query.empty())
                    proxyStr += "/?" + query;
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::Masque:
            if(!masque)
                continue;
            proxyStr = "masque://" + hostname + ":" + port + "?";
            if(!x.PrivateKey.empty())
                proxyStr += "private_key=" + urlEncode(x.PrivateKey) + "&";
            if(!x.PublicKey.empty())
                proxyStr += "public_key=" + urlEncode(x.PublicKey) + "&";
            if(!x.IP.empty())
                proxyStr += "ip=" + urlEncode(x.IP) + "&";
            if(!x.MasqueIPv6.empty())
                proxyStr += "ipv6=" + urlEncode(x.MasqueIPv6) + "&";
            if(x.Mtu > 0)
                proxyStr += "mtu=" + std::to_string(x.Mtu) + "&";
            if(!x.TransferProtocol.empty())
                proxyStr += "network=" + urlEncode(x.TransferProtocol) + "&";
            if(!x.UDP.is_undef())
                proxyStr += string("udp=") + (x.UDP.get() ? "1" : "0") + "&";
            if(!x.UnderlyingProxy.empty())
                proxyStr += "dialer_proxy=" + urlEncode(x.UnderlyingProxy) + "&";
            if(!x.RemoteDnsResolve.is_undef())
                proxyStr += string("remote_dns_resolve=") + (x.RemoteDnsResolve.get() ? "1" : "0") + "&";
            if(!x.DnsServers.empty())
                proxyStr += "dns=" + urlEncode(join(x.DnsServers, ",")) + "&";
            if(!x.CongestionController.empty())
                proxyStr += "congestion_controller=" + urlEncode(x.CongestionController) + "&";
            if(proxyStr.back() == '&')
                proxyStr.pop_back();
            else if(proxyStr.back() == '?')
                proxyStr.pop_back();
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::Hysteria:
            if(!hysteria)
                continue;
            proxyStr = "hysteria://" + hostname + ":" + port + "?";
            if(!protocol.empty())
                proxyStr += "protocol=" + protocol + "&";
            if(!obfsparam.empty())
                proxyStr += "obfs-protocol=" + obfsparam + "&";
            if(!x.Up.empty())
            {
                if(x.UpSpeed > 0)
                    proxyStr += "upmbps=" + std::to_string(x.UpSpeed) + "&";
                else if(!x.Up.empty())
                    proxyStr += "up-speed=" + x.Up + "&";
            }
            if(!x.Down.empty())
            {
                if(x.DownSpeed > 0)
                    proxyStr += "downmbps=" + std::to_string(x.DownSpeed) + "&";
                else if(!x.Down.empty())
                    proxyStr += "down-speed=" + x.Down + "&";
            }
            if(!x.Auth.empty())
                proxyStr += "auth=" + urlEncode(x.Auth) + "&";
            if(!x.AuthStr.empty())
                proxyStr += "auth_str=" + urlEncode(x.AuthStr) + "&";
            if(!obfs.empty())
                proxyStr += "obfs=" + obfs + "&";
            if(!sni.empty())
                proxyStr += "peer=" + sni + "&";
            if(!fingerprint.empty())
                proxyStr += "fingerprint=" + fingerprint + "&";
            if(!x.AlpnList.empty())
            {
                proxyStr += "alpn=" + x.AlpnList[0] + "&";
            }
            else if(!x.Alpn.empty())
                proxyStr += "alpn=" + x.Alpn + "&";
            if(!x.Ca.empty())
                proxyStr += "ca=" + x.Ca + "&";
            if(!x.CaStr.empty())
                proxyStr += "ca-str=" + x.CaStr + "&";
            if(x.RecvWindowConn > 0)
                proxyStr += "recv-window-conn=" + std::to_string(x.RecvWindowConn) + "&";
            if(x.RecvWindow > 0)
                proxyStr += "recv-window=" + std::to_string(x.RecvWindow) + "&";
            if(!x.DisableMtuDiscovery.is_undef() && x.DisableMtuDiscovery.get())
                proxyStr += "disable-mtu-discovery=true&";
            if(x.HopInterval > 0)
                proxyStr += "hop-interval=" + std::to_string(x.HopInterval) + "&";
            if(!x.AllowInsecure.is_undef() && x.AllowInsecure.get())
                proxyStr += "insecure=true&";
            if(proxyStr.back() == '&')
                proxyStr.pop_back();
            else if(proxyStr.back() == '?')
                proxyStr.pop_back();
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::Hysteria2:
            if(!hysteria2)
                continue;
            {
                const std::string auth = password.empty() ? x.Auth : password;
                auto append_query = [&proxyStr](const std::string &key, const std::string &value) {
                    if(value.empty())
                        return;
                    proxyStr += (proxyStr.find("/?") == std::string::npos ? "/?" : "&");
                    proxyStr += key + "=" + urlEncode(value);
                };
                proxyStr = "hysteria2://";
                if(!auth.empty())
                    proxyStr += urlEncode(auth) + "@";
                proxyStr += isIPv6(hostname) ? ("[" + hostname + "]") : hostname;
                if(!ports.empty())
                    proxyStr += ":" + ports;
                else if(!port.empty())
                    proxyStr += ":" + port;
                if(!x.AllowInsecure.is_undef())
                    append_query("insecure", x.AllowInsecure.get() ? "1" : "0");
                if(!obfs.empty() && obfs != "none")
                {
                    append_query("obfs", obfs);
                    append_query("obfs-password", obfsparam);
                }
                append_query("sni", sni);
                append_query("pinSHA256", fingerprint);
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::TUIC:
            if(!tuic)
                continue;
            if(!x.Token.empty())
            {
                proxyStr = "tuic://" + x.Token + "@" + hostname + ":" + port + "?";
            }
            else if(!x.UUID.empty() && !password.empty())
            {
                proxyStr = "tuic://" + x.UUID + ":" + password + "@" + hostname + ":" + port + "?";
            }
            else
            {
                continue;
            }
            if(x.TuicVersion > 0)
                proxyStr += "version=" + std::to_string(x.TuicVersion) + "&";
            else if(!x.Token.empty())
                proxyStr += "version=4&";
            if(!x.HeartbeatInterval.empty())
                proxyStr += "heartbeat_interval=" + x.HeartbeatInterval + "&";
            if(!x.DisableSNI.is_undef() && x.DisableSNI.get())
                proxyStr += "disable_sni=true&";
            if(!x.ReduceRTT.is_undef() && x.ReduceRTT.get())
                proxyStr += "reduce_rtt=true&";
            if(x.RequestTimeout > 0)
                proxyStr += "request_timeout=" + std::to_string(x.RequestTimeout) + "&";
            if(!x.UdpRelayMode.empty())
                proxyStr += "udp_relay_mode=" + x.UdpRelayMode + "&";
            if(!x.CongestionController.empty())
                proxyStr += "congestion_control=" + x.CongestionController + "&";
            if(x.MaxUdpRelayPacketSize > 0)
                proxyStr += "max_udp_relay_packet_size=" + std::to_string(x.MaxUdpRelayPacketSize) + "&";
            if(x.MaxOpenStreams > 0)
                proxyStr += "max_open_streams=" + std::to_string(x.MaxOpenStreams) + "&";
            if(!x.Alpn.empty())
                proxyStr += "alpn=" + x.Alpn + "&";
            if(!sni.empty())
                proxyStr += "sni=" + sni + "&";
            if(!x.FastOpen.is_undef() && x.FastOpen.get())
                proxyStr += "fast_open=true&";
            if(!x.AllowInsecure.is_undef() && x.AllowInsecure.get())
                proxyStr += "insecure=true&";
            if(proxyStr.back() == '&')
                proxyStr.pop_back();
            else if(proxyStr.back() == '?')
                proxyStr.pop_back();
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::AnyTLS:
            if(!anytls)
                continue;
            if(password.empty())
                continue;
            proxyStr = "anytls://" + urlEncode(password) + "@" + hostname;
            if(x.Port != 443)
                proxyStr += ":" + port;
            {
                std::string query;
                if(!sni.empty())
                    query += "sni=" + urlEncode(sni);
                if(!x.AllowInsecure.is_undef())
                {
                    if(!query.empty())
                        query += "&";
                    query += std::string("insecure=") + (x.AllowInsecure.get() ? "1" : "0");
                }
                if(!x.Reuse.is_undef())
                {
                    if(!query.empty())
                        query += "&";
                    query += std::string("reuse=") + (x.Reuse.get() ? "1" : "0");
                }
                if(!query.empty())
                    proxyStr += "/?" + query;
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::Mieru:
            if(!mieru)
                continue;
            // format: mierus://username:password@host?[port=<num>|port-range=<range>]&protocol=<TCP|UDP>&multiplexing=<...>&handshake-mode=<...>&mtu=<...>&udp=<0|1>
            // strategy: current Proxy model keeps a single endpoint binding, so export keeps one port/protocol pair.
            proxyStr = "mierus://" + urlEncode(username) + ":" + urlEncode(password) + "@" + hostname;
            {
                std::string query;
                auto append_query = [&query](const std::string &key, const std::string &value) {
                    if(value.empty())
                        return;
                    if(!query.empty())
                        query += "&";
                    query += key + "=" + urlEncode(value);
                };
                if(!x.PortRange.empty())
                    append_query("port-range", x.PortRange);
                else if(x.Port != 0)
                    append_query("port", port);
                if(!x.TransferProtocol.empty() && x.TransferProtocol != "TCP")
                    append_query("protocol", x.TransferProtocol);
                if(!x.Multiplexing.empty() && x.Multiplexing != "MULTIPLEXING_LOW")
                    append_query("multiplexing", x.Multiplexing);
                if(!x.HandshakeMode.empty())
                    append_query("handshake-mode", x.HandshakeMode);
                if(x.Mtu > 0)
                    append_query("mtu", std::to_string(x.Mtu));
                if(!x.UDP.is_undef())
                    append_query("udp", x.UDP.get() ? "1" : "0");
                if(!x.TrafficPattern.empty())
                    append_query("traffic-pattern", x.TrafficPattern);
                if(!query.empty())
                    proxyStr += "/?" + query;
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        case ProxyType::VLESS:
            if(!vless)
                continue;
            proxyStr = "vless://" + (id.empty() ? "00000000-0000-0000-0000-000000000000" : id) + "@" + hostname + ":" + port + "?encryption=none";
            if(!tls.empty() && tls != "none")
                proxyStr += "&security=" + urlEncode(tls);
            if(!flow.empty())
                proxyStr += "&flow=" + urlEncode(flow);
            if(!fingerprint.empty() && fingerprint != "none")
                proxyStr += "&fp=" + urlEncode(fingerprint);
            if(!x.ClientFingerprint.empty())
                proxyStr += "&client-fingerprint=" + urlEncode(x.ClientFingerprint);
            if(!packet_encoding.empty())
            {
                proxyStr += "&packet-encoding=" + urlEncode(packet_encoding);
                proxyStr += "&packetEncoding=" + urlEncode(packet_encoding);
            }
            if(!x.EchConfig.empty())
            {
                proxyStr += "&ech-config=" + urlEncode(x.EchConfig);
                proxyStr += "&ech=" + urlEncode(x.EchConfig);
            }
            if(!x.AllowInsecure.is_undef())
            {
                proxyStr += "&insecure=" + std::string(x.AllowInsecure.get() ? "1" : "0");
                proxyStr += "&allowInsecure=" + std::string(x.AllowInsecure.get() ? "1" : "0");
            }
            if(!x.UDP.is_undef())
                proxyStr += "&udp=" + std::string(x.UDP.get() ? "1" : "0");
            if(!x.TCPFastOpen.is_undef())
                proxyStr += "&tfo=" + std::string(x.TCPFastOpen.get() ? "1" : "0");
            if(!x.XUDP.is_undef())
                proxyStr += "&xudp=" + std::string(x.XUDP.get() ? "1" : "0");
            if(!alpns.empty())
            {
                for(size_t i = 0; i < alpns.size(); i++)
                {
                    if(i == 0)
                        proxyStr += "&alpn=" + urlEncode(alpns[i]);
                    else
                        proxyStr += "%2C" + urlEncode(alpns[i]);
                }
            }
            if(!sni.empty())
                proxyStr += "&sni=" + urlEncode(sni);
            if(!transproto.empty())
            {
                proxyStr += "&type=" + urlEncode(transproto);
                switch(hash_(transproto))
                {
                    case "tcp"_hash:
                        if(!public_key.empty())
                            proxyStr += "&pbk=" + urlEncode(public_key);
                        if(!short_id.empty())
                            proxyStr += "&sid=" + urlEncode(short_id);
                        if(!spider_x.empty())
                            proxyStr += "&spx=" + urlEncode(spider_x);
                        break;
                    case "ws"_hash:
                    case "h2"_hash:
                        if(!fake_type.empty())
                            proxyStr += "&headerType=" + urlEncode(fake_type);
                        if(!host.empty())
                            proxyStr += "&host=" + urlEncode(host);
                        proxyStr += "&path=" + urlEncode(path.empty() ? "/" : path);
                        break;
                    case "xhttp"_hash:
                        if(!fake_type.empty())
                            proxyStr += "&headerType=" + urlEncode(fake_type);
                        if(!host.empty())
                            proxyStr += "&host=" + urlEncode(host);
                        proxyStr += "&path=" + urlEncode(path.empty() ? "/" : path);
                        if(!mode.empty())
                            proxyStr += "&mode=" + urlEncode(mode);
                        break;
                    case "grpc"_hash:
                        proxyStr += "&serviceName=" + urlEncode(path);
                        proxyStr += "&grpc-service-name=" + urlEncode(path);
                        if(!mode.empty())
                            proxyStr += "&mode=" + urlEncode(mode);
                        if(!public_key.empty())
                            proxyStr += "&pbk=" + urlEncode(public_key);
                        if(!short_id.empty())
                            proxyStr += "&sid=" + urlEncode(short_id);
                        if(!spider_x.empty())
                            proxyStr += "&spx=" + urlEncode(spider_x);
                        break;
                    case "quic"_hash:
                        if(!fake_type.empty())
                            proxyStr += "&headerType=" + fake_type;
                        proxyStr += "&quicSecurity=" + (host.empty() ? sni : host);
                        proxyStr += "&key=" + path;
                        break;
                    default:
                        break;
                }
            }
            if(tlssecure)
            {
                if(tls.empty() || tls == "none")
                    proxyStr += "&security=tls";
                if(!sni.empty())
                    proxyStr += "&sni=" + sni;
            }
            proxyStr += "#" + urlEncode(remark);
            break;
        default:
            continue;
        }
        allLinks += proxyStr + "\n";
    }

    if(ext.nodelist)
        return allLinks;
    else
        return base64Encode(allLinks);
}

std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes, extra_settings &ext)
{
    using namespace rapidjson_ext;
    rapidjson::Document base;

    auto &alloc = base.GetAllocator();

    base_conf = trimWhitespace(base_conf);
    if(base_conf.empty())
        base_conf = "{}";
    rapidjson::ParseResult result = base.Parse(base_conf.data());
    if (!result)
        writeLog(0, std::string("SIP008 base loader failed with error: ") + rapidjson::GetParseError_En(result.Code()) + " (" + std::to_string(result.Offset()) + ")", LOG_LEVEL_ERROR);

    rapidjson::Value proxies(rapidjson::kArrayType);
    for(Proxy &x : nodes)
    {
        std::string &remark = x.Remark;
        std::string &hostname = x.Hostname;
        std::string &password = x.Password;
        std::string &method = x.EncryptMethod;
        std::string &plugin = x.Plugin;
        std::string &pluginopts = x.PluginOption;
        std::string &protocol = x.Protocol;
        std::string &obfs = x.OBFS;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(plugin == "simple-obfs")
                plugin = "obfs-local";
            break;
        case ProxyType::ShadowsocksR:
            if(std::find(ss_ciphers.begin(), ss_ciphers.end(), method) == ss_ciphers.end() || protocol != "origin" || obfs != "plain")
                continue;
            break;
        default:
            continue;
        }
        rapidjson::Value proxy(rapidjson::kObjectType);
        proxy.CopyFrom(base, alloc)
        | AddMemberOrReplace("remarks", rapidjson::Value(remark.c_str(), remark.size()), alloc)
        | AddMemberOrReplace("server", rapidjson::Value(hostname.c_str(), hostname.size()), alloc)
        | AddMemberOrReplace("server_port", rapidjson::Value(x.Port), alloc)
        | AddMemberOrReplace("method", rapidjson::Value(method.c_str(), method.size()), alloc)
        | AddMemberOrReplace("password", rapidjson::Value(password.c_str(), password.size()), alloc)
        | AddMemberOrReplace("plugin", rapidjson::Value(plugin.c_str(), plugin.size()), alloc)
        | AddMemberOrReplace("plugin_opts", rapidjson::Value(pluginopts.c_str(), pluginopts.size()), alloc);
        proxies.PushBack(proxy, alloc);
    }
    return proxies | SerializeObject();
}

std::string proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    ini.store_any_line = true;
    if(!ext.nodelist && ini.parse(base_conf) != 0)
    {
        writeLog(0, "Quantumult base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuan(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if(ext.nodelist)
    {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("SERVER", "{NONAME}", allnodes);
        if(!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return base64Encode(allLinks);
    }
    return ini.to_string();
}

void proxyToQuan(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::string proxyStr;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("SERVER");
    ini.erase_section();
    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &password = x.Password, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &edge = x.Edge, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &plugin = x.Plugin, &pluginopts = x.PluginOption, &username = x.Username;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;
        tribool scv;

        switch(x.Type)
        {
        case ProxyType::VMess:
            scv = ext.skip_cert_verify;
            scv.define(x.AllowInsecure);

            if(method == "auto")
                method = "chacha20-ietf-poly1305";
            proxyStr = x.Remark + " = vmess, " + hostname + ", " + port + ", " + method + ", \"" + id + "\", group=" + x.Group;
            if(tlssecure)
            {
                proxyStr += ", over-tls=true, tls-host=" + host;
                if(!scv.is_undef())
                    proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
            }
            if(transproto == "ws")
            {
                proxyStr += ", obfs=ws, obfs-path=\"" + path + "\", obfs-header=\"Host: " + host;
                if(!edge.empty())
                    proxyStr += "[Rr][Nn]Edge: " + edge;
                proxyStr += "\"";
            }

            if(ext.nodelist)
                proxyStr = "vmess://" + urlSafeBase64Encode(proxyStr);
            break;
        case ProxyType::ShadowsocksR:
            if(ext.nodelist)
            {
                proxyStr = "ssr://" + urlSafeBase64Encode(hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" + urlSafeBase64Encode(password) \
                           + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(x.Remark) \
                           + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" + urlSafeBase64Encode(protoparam));
            }
            else
            {
                proxyStr = x.Remark + " = shadowsocksr, " + hostname + ", " + port + ", " + method + ", \"" + password + "\", group=" + x.Group + ", protocol=" + protocol + ", obfs=" + obfs;
                if(!protoparam.empty())
                    proxyStr += ", protocol_param=" + protoparam;
                if(!obfsparam.empty())
                    proxyStr += ", obfs_param=" + obfsparam;
            }
            break;
        case ProxyType::Shadowsocks:
            if(ext.nodelist)
            {
                proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                if(!plugin.empty() && !pluginopts.empty())
                {
                    proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                }
                proxyStr += "&group=" + urlSafeBase64Encode(x.Group) + "#" + urlEncode(x.Remark);
            }
            else
            {
                proxyStr = x.Remark + " = shadowsocks, " + hostname + ", " + port + ", " + method + ", \"" + password + "\", group=" + x.Group;
                if(plugin == "obfs-local" && !pluginopts.empty())
                {
                    proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                }
            }
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            proxyStr = x.Remark + " = http, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port + ", group=" + x.Group;
            if(!username.empty() && !password.empty())
                proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username + ", upstream-proxy-password=" + password;
            else
                proxyStr += ", upstream-proxy-auth=false";

            if(tlssecure)
            {
                proxyStr += ", over-tls=true";
                if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(!scv.is_undef())
                    proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
            }

            if(ext.nodelist)
                proxyStr = "http://" + urlSafeBase64Encode(proxyStr);
            break;
        case ProxyType::SOCKS5:
            proxyStr = x.Remark + " = socks, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port + ", group=" + x.Group;
            if(!username.empty() && !password.empty())
                proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username + ", upstream-proxy-password=" + password;
            else
                proxyStr += ", upstream-proxy-auth=false";

            if(tlssecure)
            {
                proxyStr += ", over-tls=true";
                if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(!scv.is_undef())
                    proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
            }

            if(ext.nodelist)
                proxyStr = "socks://" + urlSafeBase64Encode(proxyStr);
            break;
        default:
            continue;
        }

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if(ext.nodelist)
        return;

    ini.set_current_section("POLICY");
    ini.erase_section();

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string type;
        std::string singlegroup;
        std::string name, proxies;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::Fallback:
            type = "static";
            break;
        case ProxyGroupType::URLTest:
            type = "auto";
            break;
        case ProxyGroupType::LoadBalance:
            type = "balance, round-robin";
            break;
        case ProxyGroupType::SSID:
            {
                singlegroup = x.Name + " : wifi = " + x.Proxies[0];
                std::string content, celluar, celluar_matcher = R"(^(.*?),?celluar\s?=\s?(.*?)(,.*)$)", rem_a, rem_b;
                for(auto iter = x.Proxies.begin() + 1; iter != x.Proxies.end(); iter++)
                {
                    if(regGetMatch(*iter, celluar_matcher, 4, 0, &rem_a, &celluar, &rem_b))
                    {
                        content += *iter + "\n";
                        continue;
                    }
                    content += rem_a + rem_b + "\n";
                }
                if(!celluar.empty())
                    singlegroup += ", celluar = " + celluar;
                singlegroup += "\n" + replaceAllDistinct(trimOf(content, ','), ",", "\n");
                ini.set("{NONAME}", base64Encode(singlegroup)); //insert order
            }
            continue;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(filtered_nodelist.empty())
            filtered_nodelist.emplace_back("direct");

        if(filtered_nodelist.size() < 2) // force groups with 1 node to be static
            type = "static";

        proxies = join(filtered_nodelist, "\n");

        singlegroup = x.Name + " : " + type;
        if(type == "static")
            singlegroup += ", " + filtered_nodelist[0];
        singlegroup += "\n" + proxies + "\n";
        ini.set("{NONAME}", base64Encode(singlegroup));
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -2, ext.overwrite_original_rules, "");
}

std::string proxyToQuanX(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    ini.store_any_line = true;
    ini.add_direct_save_section("general");
    ini.add_direct_save_section("dns");
    ini.add_direct_save_section("rewrite_remote");
    ini.add_direct_save_section("rewrite_local");
    ini.add_direct_save_section("task_local");
    ini.add_direct_save_section("mitm");
    ini.add_direct_save_section("server_remote");
    if(!ext.nodelist && ini.parse(base_conf) != 0)
    {
        writeLog(0, "QuantumultX base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuanX(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if(ext.nodelist)
    {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("server_local", "{NONAME}", allnodes);
        if(!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return allLinks;
    }
    return ini.to_string();
}

void proxyToQuanX(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::string proxyStr;
    tribool udp, tfo, scv, tls13;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("server_local");
    ini.erase_section();
    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &password = x.Password, &plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &username = x.Username, &uuid = x.UUID, &sni = x.SNI, &publickey = x.PublicKey, &shortid = x.ShortID, &flow = x.Flow;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        udp = ext.udp;
        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        switch(x.Type)
        {
        case ProxyType::VMess:
            if(method == "auto")
                method = "chacha20-ietf-poly1305";
            proxyStr = "vmess = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
            if (x.AlterId != 0)
                proxyStr += ", aead=false";
            if(tlssecure && !tls13.is_undef())
                proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
            if(transproto == "ws")
            {
                if(tlssecure)
                    proxyStr += ", obfs=wss";
                else
                    proxyStr += ", obfs=ws";
                proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
            }
            else if(transproto == "http")
            {
                proxyStr += ", obfs=http";
                if(!host.empty())
                    proxyStr += ", obfs-host=" + host;
                if(!path.empty())
                    proxyStr += ", obfs-uri=" + path;
            }
            else if(tlssecure)
                proxyStr += ", obfs=over-tls, obfs-host=" + host;
            break;
        case ProxyType::Shadowsocks:
            proxyStr = "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password;
            if(!plugin.empty())
            {
                switch(hash_(plugin))
                {
                    case "simple-obfs"_hash:
                    case "obfs-local"_hash:
                        if(!pluginopts.empty())
                            proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                        break;
                    case "v2ray-plugin"_hash:
                        pluginopts = replaceAllDistinct(pluginopts, ";", "&");
                        plugin = getUrlArg(pluginopts, "mode") == "websocket" ? "ws" : "";
                        host = getUrlArg(pluginopts, "host");
                        path = getUrlArg(pluginopts, "path");
                        tlssecure = pluginopts.find("tls") != std::string::npos;
                        if(tlssecure && plugin == "ws")
                        {
                            plugin += 's';
                            if(!tls13.is_undef())
                                proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                        }
                        proxyStr += ", obfs=" + plugin;
                        if(!host.empty())
                            proxyStr += ", obfs-host=" + host;
                        if(!path.empty())
                            proxyStr += ", obfs-uri=" + path;
                        break;
                    default: continue;
                }
            }

            break;
        case ProxyType::ShadowsocksR:
            proxyStr = "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password + ", ssr-protocol=" + protocol;
            if(!protoparam.empty())
                proxyStr += ", ssr-protocol-param=" + protoparam;
            proxyStr += ", obfs=" + obfs;
            if(!obfsparam.empty())
                proxyStr += ", obfs-host=" + obfsparam;
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            proxyStr = "http = " + hostname + ":" + port + ", username=" + (username.empty() ? "none" : username) + ", password=" + (password.empty() ? "none" : password);
            if(tlssecure)
            {
                proxyStr += ", over-tls=true";
                if(!sni.empty())
                    proxyStr += ", tls-host=" + sni;
                else if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(!publickey.empty())
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                if(!tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
            }
            else
            {
                proxyStr += ", over-tls=false";
            }
            break;
        case ProxyType::Trojan:
            proxyStr = "trojan = " + hostname + ":" + port + ", password=" + password;
            if(tlssecure)
            {
                if(transproto == "ws")
                {
                    proxyStr += ", obfs=wss, obfs-host=" + host + ", obfs-uri=" + path;
                    if(!publickey.empty())
                    {
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if(!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                    }
                }
                else
                {
                    proxyStr += ", over-tls=true";
                    if(!sni.empty())
                        proxyStr += ", tls-host=" + sni;
                    else if(!host.empty())
                        proxyStr += ", tls-host=" + host;
                    if(!publickey.empty())
                    {
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if(!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                    }
                }
                if(!tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
            }
            else
            {
                proxyStr += ", over-tls=false";
            }
            break;
        case ProxyType::SOCKS5:
            proxyStr = "socks5 = " + hostname + ":" + port;
            if(!username.empty() && !password.empty())
                proxyStr += ", username=" + username + ", password=" + password;
            if(tlssecure)
            {
                proxyStr += ", over-tls=true";
                if(!sni.empty())
                    proxyStr += ", tls-host=" + sni;
                else if(!host.empty())
                    proxyStr += ", tls-host=" + host;
                if(!publickey.empty())
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
                if(!tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
            }
            else
            {
                proxyStr += ", over-tls=false";
            }
            break;
        case ProxyType::VLESS:
            method = "none";
            proxyStr = "vless = " + hostname + ":" + port + ", method=" + method + ", password=" + uuid;
            if(tlssecure && !tls13.is_undef())
                proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
            if(transproto == "ws")
            {
                if(tlssecure)
                    proxyStr += ", obfs=wss";
                else
                    proxyStr += ", obfs=ws";
                if(tlssecure && !publickey.empty() && !sni.empty())
                    proxyStr += ", obfs-host=" + sni;
                else if(!host.empty())
                    proxyStr += ", obfs-host=" + host;
                if(!path.empty())
                    proxyStr += ", obfs-uri=" + path;
                if(tlssecure && !publickey.empty() && !sni.empty())
                {
                    proxyStr += ", reality-base64-pubkey=" + publickey;
                    if(!shortid.empty())
                        proxyStr += ", reality-hex-shortid=" + shortid;
                }
            }
            else if(transproto == "http")
            {
                proxyStr += ", obfs=http";
                if(!host.empty())
                    proxyStr += ", obfs-host=" + host;
                if(!path.empty())
                        proxyStr += ", obfs-uri=" + path;
            }
            else if(transproto == "tcp")
            {
                if(tlssecure)
                {
                    proxyStr += ", obfs=over-tls";
                    if(!sni.empty())
                        proxyStr += ", obfs-host=" + sni;
                    else if(!host.empty())
                        proxyStr += ", obfs-host=" + host;
                    if(!publickey.empty())
                    {
                        proxyStr += ", reality-base64-pubkey=" + publickey;
                        if(!shortid.empty())
                            proxyStr += ", reality-hex-shortid=" + shortid;
                    }
                    if(!flow.empty())
                        proxyStr += ", vless-flow=" + flow;
                }
            }
            else if(tlssecure)
            {
                proxyStr += ", obfs=over-tls";
                if(!sni.empty())
                    proxyStr += ", obfs-host=" + sni;
            }
            break;
        case ProxyType::AnyTLS:
            proxyStr = "anytls = " + hostname + ":" + port + ", password=" + password;
            proxyStr += ", over-tls=true";
            if(!sni.empty())
                proxyStr += ", tls-host=" + sni;
            else if(!host.empty())
                proxyStr += ", tls-host=" + host;
            if(!publickey.empty())
            {
                proxyStr += ", reality-base64-pubkey=" + publickey;
                if(!shortid.empty())
                    proxyStr += ", reality-hex-shortid=" + shortid;
            }
            break;
        case ProxyType::Hysteria2:
            proxyStr = "hysteria2 = " + hostname + ":" + port + ", password=" + password;
            if(!x.Up.empty())
                proxyStr += ", up=" + x.Up;
            if(!x.Down.empty())
                proxyStr += ", down=" + x.Down;
            if(!x.OBFS.empty())
                proxyStr += ", obfs=" + x.OBFS;
            if(!x.OBFSParam.empty())
                proxyStr += ", obfs-password=" + x.OBFSParam;
            break;
        default:
            continue;
        }
        if(!tfo.is_undef())
            proxyStr += ", fast-open=" + tfo.get_str();
        if(!udp.is_undef())
            proxyStr += ", udp-relay=" + udp.get_str();
        if(tlssecure && !scv.is_undef() && (x.Type != ProxyType::Shadowsocks && x.Type != ProxyType::ShadowsocksR))
            proxyStr += ", tls-verification=" + scv.reverse().get_str();
        proxyStr += ", tag=" + x.Remark;

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if(ext.nodelist)
        return;

    string_multimap original_groups;
    ini.set_current_section("policy");
    ini.get_items(original_groups);
    ini.erase_section();

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        std::string type;
        string_array filtered_nodelist;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
            type = "static";
            break;
        case ProxyGroupType::URLTest:
            type = "url-latency-benchmark";
            break;
        case ProxyGroupType::Fallback:
            type = "available";
            break;
        case ProxyGroupType::LoadBalance:
            type = "round-robin";
            break;
        case ProxyGroupType::SSID:
            type = "ssid";
            for(const auto & proxy : x.Proxies)
                filtered_nodelist.emplace_back(replaceAllDistinct(proxy, "=", ":"));
            break;
        default:
            continue;
        }

        if(x.Type != ProxyGroupType::SSID)
        {
            for(const auto &y : x.Proxies)
                groupGenerate(y, nodelist, filtered_nodelist, true, ext);

            if(filtered_nodelist.empty())
                filtered_nodelist.emplace_back("direct");

            if(filtered_nodelist.size() < 2) // force groups with 1 node to be static
                type = "static";
        }

        auto iter = std::find_if(original_groups.begin(), original_groups.end(), [&](const string_multimap::value_type &n)
        {
            std::string groupdata = n.second;
            std::string::size_type cpos = groupdata.find(',');
            if(cpos != std::string::npos)
                return trim(groupdata.substr(0, cpos)) == x.Name;
            else
                return false;
        });
        if(iter != original_groups.end())
        {
            string_array vArray = split(iter->second, ",");
            if(vArray.size() > 1)
            {
                if(trim(vArray[vArray.size() - 1]).find("img-url") == 0)
                    filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
            }
        }

        std::string proxies = join(filtered_nodelist, ", ");

        std::string singlegroup = type + "=" + x.Name + ", " + proxies;
        if(x.Type != ProxyGroupType::Select && x.Type != ProxyGroupType::SSID)
        {
            singlegroup += ", check-interval=" + std::to_string(x.Interval);
            if(x.Tolerance > 0)
                singlegroup += ", tolerance=" + std::to_string(x.Tolerance);
        }
        ini.set("{NONAME}", singlegroup);
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -1, ext.overwrite_original_rules, ext.managed_config_prefix);
}

std::string proxyToSSD(std::vector<Proxy> &nodes, std::string &group, std::string &userinfo, extra_settings &ext)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    int index = 0;

    if(group.empty())
        group = "SSD";

    writer.StartObject();
    writer.Key("airport");
    writer.String(group.data());
    writer.Key("port");
    writer.Int(1);
    writer.Key("encryption");
    writer.String("aes-128-gcm");
    writer.Key("password");
    writer.String("password");
    if(!userinfo.empty())
    {
        std::string data = replaceAllDistinct(userinfo, "; ", "&");
        std::string upload = getUrlArg(data, "upload"), download = getUrlArg(data, "download"), total = getUrlArg(data, "total"), expiry = getUrlArg(data, "expire");
        double used = (to_number(upload, 0.0) + to_number(download, 0.0)) / std::pow(1024, 3) * 1.0, tot = to_number(total, 0.0) / std::pow(1024, 3) * 1.0;
        writer.Key("traffic_used");
        writer.Double(used);
        writer.Key("traffic_total");
        writer.Double(tot);
        if(!expiry.empty())
        {
            const time_t rawtime = to_int(expiry);
            char buffer[30];
            struct tm *dt = localtime(&rawtime);
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", dt);
            writer.Key("expiry");
            writer.String(buffer);
        }
    }
    writer.Key("servers");
    writer.StartArray();

    for(Proxy &x : nodes)
    {
        std::string &hostname = x.Hostname, &password = x.Password, &method = x.EncryptMethod, &plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &obfs = x.OBFS;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(plugin == "obfs-local")
                plugin = "simple-obfs";
            writer.StartObject();
            writer.Key("server");
            writer.String(hostname.data());
            writer.Key("port");
            writer.Int(x.Port);
            writer.Key("encryption");
            writer.String(method.data());
            writer.Key("password");
            writer.String(password.data());
            writer.Key("plugin");
            writer.String(plugin.data());
            writer.Key("plugin_options");
            writer.String(pluginopts.data());
            writer.Key("remarks");
            writer.String(x.Remark.data());
            writer.Key("id");
            writer.Int(index);
            writer.EndObject();
            break;
        case ProxyType::ShadowsocksR:
            if(std::count(ss_ciphers.begin(), ss_ciphers.end(), method) > 0 && protocol == "origin" && obfs == "plain")
            {
                writer.StartObject();
                writer.Key("server");
                writer.String(hostname.data());
                writer.Key("port");
                writer.Int(x.Port);
                writer.Key("encryption");
                writer.String(method.data());
                writer.Key("password");
                writer.String(password.data());
                writer.Key("remarks");
                writer.String(x.Remark.data());
                writer.Key("id");
                writer.Int(index);
                writer.EndObject();
                break;
            }
            else
                continue;
        default:
            continue;
        }
        index++;
    }
    writer.EndArray();
    writer.EndObject();
    return "ssd://" + base64Encode(sb.GetString());
}

std::string proxyToMellow(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    ini.store_any_line = true;
    if(ini.parse(base_conf) != 0)
    {
        writeLog(0, "Mellow base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToMellow(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    return ini.to_string();
}

void proxyToMellow(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    std::string proxy;
    std::string username, password, method;
    std::string plugin, pluginopts;
    std::string id, aid, transproto, faketype, host, path, quicsecure, quicsecret, tlssecure;
    std::string url;
    tribool tfo, scv;
    std::vector<Proxy> nodelist;
    string_array vArray, remarks_list;

    ini.set_current_section("Endpoint");

    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, port = std::to_string(x.Port);

        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            if(!x.Plugin.empty())
                continue;
            proxy = x.Remark + ", ss, ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
            break;
        case ProxyType::VMess:
            proxy = x.Remark + ", vmess1, vmess1://" + id + "@" + hostname + ":" + port;
            if(!path.empty())
                proxy += path;
            proxy += "?network=" + transproto;
            switch(hash_(transproto))
            {
            case "ws"_hash:
                proxy += "&ws.host=" + urlEncode(host);
                break;
            case "http"_hash:
                if(!host.empty())
                    proxy += "&http.host=" + urlEncode(host);
                break;
            case "quic"_hash:
                if(!quicsecure.empty())
                    proxy += "&quic.security=" + quicsecure + "&quic.key=" + quicsecret;
                break;
            case "kcp"_hash:
            case "tcp"_hash:
                break;
            }
            proxy += "&tls=" + tlssecure;
            if(tlssecure == "true")
            {
                if(!host.empty())
                    proxy += "&tls.servername=" + urlEncode(host);
            }
            if(!scv.is_undef())
                proxy += "&tls.allowinsecure=" + scv.get_str();
            if(!tfo.is_undef())
                proxy += "&sockopt.tcpfastopen=" + tfo.get_str();
            break;
        case ProxyType::SOCKS5:
            proxy = x.Remark + ", builtin, socks, address=" + hostname + ", port=" + port + ", user=" + username + ", pass=" + password;
            break;
        case ProxyType::HTTP:
            proxy = x.Remark + ", builtin, http, address=" + hostname + ", port=" + port + ", user=" + username + ", pass=" + password;
            break;
        default:
            continue;
        }

        ini.set("{NONAME}", proxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    ini.set_current_section("EndpointGroup");

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        url.clear();
        proxy.clear();

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Fallback:
        case ProxyGroupType::LoadBalance:
            break;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, false, ext);

        if(filtered_nodelist.empty())
        {
            if(remarks_list.empty())
                filtered_nodelist.emplace_back("DIRECT");
            else
                filtered_nodelist = remarks_list;
        }

        //don't process these for now
        /*
        proxy = vArray[1];
        for(std::string &x : filtered_nodelist)
            proxy += "," + x;
        if(vArray[1] == "url-test" || vArray[1] == "fallback" || vArray[1] == "load-balance")
            proxy += ",url=" + url;
        */

        proxy = x.Name + ", ";
        /*
        for(std::string &y : filtered_nodelist)
            proxy += y + ":";
        proxy = proxy.substr(0, proxy.size() - 1);
        */
        proxy += join(filtered_nodelist, ":");
        proxy += ", latency, interval=300, timeout=6"; //use hard-coded values for now

        ini.set("{NONAME}", proxy); //insert order
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, 0, ext.overwrite_original_rules, "");
}

std::string proxyToLoon(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;

    string_array remarks_list;

    ini.store_any_line = true;
    ini.add_direct_save_section("Plugin");
    if(ini.parse(base_conf) != INIREADER_EXCEPTION_NONE && !ext.nodelist)
    {
        writeLog(0, "Loon base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();

    for(Proxy &x : nodes)
    {
        if(ext.append_proxy_type)
        {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }
        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &username = x.Username, &password = x.Password, &method = x.EncryptMethod, &plugin = x.Plugin, &pluginopts = x.PluginOption, &transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, flow = x.Flow, pk = x.PublicKey, shortId = x.ShortID;
        std::string id = (x.Type == ProxyType::VLESS) ? x.UUID : x.UserId;
        std::string sni = (x.Type == ProxyType::VLESS || x.Type == ProxyType::Hysteria2 || x.Type == ProxyType::TUIC) ? x.SNI : x.ServerName;
        std::string port = std::to_string(x.Port), aid = std::to_string(x.AlterId);
        bool &tlssecure = x.TLSSecure;

        tribool scv = ext.skip_cert_verify;
        tribool udp = x.UDP.is_undef() ? ext.udp.is_undef() ? false : ext.udp.get() : x.UDP.get();
        scv.define(x.AllowInsecure);

        std::string proxy;

        switch(x.Type)
        {
        case ProxyType::Shadowsocks:
            proxy = "Shadowsocks," + hostname + "," + port + "," + method + ",\"" + password + "\"";
            if(plugin == "simple-obfs" || plugin == "obfs-local")
            {
                if(!pluginopts.empty())
                    proxy += "," + replaceAllDistinct(replaceAllDistinct(pluginopts, ";obfs-host=", ","), "obfs=", "");
            }
            else if(!plugin.empty())
                continue;
            if(!udp.is_undef())
                proxy += ",udp=" + std::string(udp.get() ? "true" : "false");
            break;
        case ProxyType::VMess:
            if(method == "auto")
                method = "chacha20-ietf-poly1305";

            proxy = "vmess," + hostname + "," + port + "," + method + ",\"" + id + "\",over-tls=" + (tlssecure ? "true" : "false");
            if (!sni.empty())
                host = sni;
            if(tlssecure)
                proxy += ",tls-name=" + host;
            switch(hash_(transproto))
            {
            case "tcp"_hash:
                proxy += ",transport=tcp";
                break;
            case "ws"_hash:
                proxy += ",transport=ws,path=" + path + ",host=" + host;
                break;
            case "http"_hash:
                proxy += ",transport=http,path=" + path + ",host=" + host;
                break;
            default:
                continue;
            }
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.AlpnList.empty())
                proxy += ",alpn=" + join(x.AlpnList, ",");
            break;
        case ProxyType::ShadowsocksR:
            proxy = "ShadowsocksR," + hostname + "," + port + "," + method + ",\"" + password + "\",protocol=" + protocol + ",protocol-param=" + protoparam + ",obfs=" + obfs + ",obfs-param=" + obfsparam;
            if(!udp.is_undef())
                proxy += ",udp=" + std::string(udp.get() ? "true" : "false");
            break;
        case ProxyType::HTTP:
            proxy = "http," + hostname + "," + port;
            if(!username.empty() && !password.empty())
                proxy += "," + username + ",\"" + password + "\"";
            break;
        case ProxyType::HTTPS:
            proxy = "https," + hostname + "," + port;
            if(!username.empty() && !password.empty())
                proxy += "," + username + ",\"" + password + "\"";
            if(!sni.empty())
                proxy += ",tls-name=" + sni;
            else if(!host.empty())
                proxy += ",tls-name=" + host;
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            break;
        case ProxyType::Trojan:
            proxy = "trojan," + hostname + "," + port + ",\"" + password + "\"";
            if(!host.empty())
                proxy += ",tls-name=" + host;
            switch (hash_(transproto)) {
                case "tcp"_hash:
                    proxy += ",transport=tcp";
                    break;
                case "ws"_hash:
                    proxy += ",transport=ws,path=" + path + ",host=" + host;
                    break;
                case "http"_hash:
                    proxy += ",transport=http,path=" + path + ",host=" + host;
                    break;
                default:
                    continue;
            }
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.AlpnList.empty())
                proxy += ",alpn=" + join(x.AlpnList, ",");
            break;
        case ProxyType::SOCKS5:
            proxy = "socks5," + hostname + "," + port;
            if (!username.empty() && !password.empty())
                proxy += "," + username + ",\"" + password + "\"";
            proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
            if (tlssecure)
            {
                if(!sni.empty())
                    proxy += ",tls-name=" + sni;
                else if(!host.empty())
                    proxy += ",tls-name=" + host;
                if(!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            }
            break;
        case ProxyType::WireGuard:
            proxy = "wireguard, interface-ip=" + x.SelfIP;
            if(!x.SelfIPv6.empty())
                proxy += ", interface-ipv6=" + x.SelfIPv6;
            proxy += ", private-key=" + x.PrivateKey;
            for(const auto &y : x.DnsServers)
            {
                if(isIPv4(y))
                    proxy += ", dns=" + y;
                else if(isIPv6(y))
                    proxy += ", dnsv6=" + y;
            }
            if(x.Mtu > 0)
                proxy += ", mtu=" + std::to_string(x.Mtu);
            if(x.KeepAlive > 0)
                proxy += ", keepalive=" + std::to_string(x.KeepAlive);
            proxy += ", peers=[{" + generatePeer(x, true) + "}]";
            break;
        case ProxyType::Hysteria2:
            proxy = "Hysteria2," + hostname + "," + port + ",\"" + password + "\"";
            if(!scv.is_undef())
                proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            if(!x.Fingerprint.empty())
                proxy += ",tls-cert-sha256=" + x.Fingerprint;
            if(!x.SNI.empty())
                proxy += ",tls-name=" + x.SNI;
            else if(!sni.empty())
                proxy += ",tls-name=" + sni;
            if(ext.tfo)
                proxy += ",fast-open=true";
            break;
        case ProxyType::VLESS:
            if(flow == "xtls-rprx-vision")
            {
                proxy = "VLESS," + hostname + "," + port + ",\"" + id + "\",flow=" + flow + ",public-key=\"" + pk + "\",short-id=" + shortId;
                proxy += ",udp=" + std::string(udp.get() ? "true" : "false");
                proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
                if(!sni.empty())
                    proxy += ",sni=" + sni;
                if(!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
            }
            else
            {
                proxy = "VLESS," + hostname + "," + port + ",\"" + id + "\"";
                switch(hash_(transproto))
                {
                    case "tcp"_hash:
                        proxy += ",transport=tcp";
                        if(tlssecure)
                        {
                            proxy += ",over-tls=true";
                            if(!sni.empty())
                                proxy += ",tls-name=" + sni;
                        }
                        break;
                    case "ws"_hash:
                        proxy += ",transport=ws,path=" + (path.empty() ? "/" : path) + ",host=" + host;
                        if(tlssecure)
                        {
                            proxy += ",over-tls=true";
                            if(!sni.empty())
                                proxy += ",tls-name=" + sni;
                        }
                        break;
                    case "http"_hash:
                        proxy += ",transport=http,path=" + (path.empty() ? "/" : path) + ",host=" + host;
                        if(tlssecure)
                        {
                            proxy += ",over-tls=true";
                            if(!sni.empty())
                                proxy += ",tls-name=" + sni;
                        }
                        break;
                    default:
                        continue;
                }
                proxy += ",udp=" + std::string(udp.get() ? "true" : "false");
                if(!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                if(!x.AlpnList.empty())
                    proxy += ",alpn=" + join(x.AlpnList, ",");
            }
            break;
        default:
            continue;
        }
        if(x.Type != ProxyType::Hysteria2)
        {
            if(ext.tfo && !udp.is_undef())
                proxy += ",fast-open=true";
        }
        if(ext.udp && proxy.find(",udp=") == std::string::npos)
            proxy += ",udp=true";

        if(ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else
        {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
            remarks_list.emplace_back(x.Remark);
        }
    }

    if(ext.nodelist)
        return output_nodelist;

    string_multimap original_groups;
    ini.set_current_section("Proxy Group");
    ini.get_items(original_groups);
    ini.erase_section();

    for(const ProxyGroupConfig &x : extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string group, group_extra;

        switch(x.Type)
        {
        case ProxyGroupType::Select:
        case ProxyGroupType::LoadBalance:
        case ProxyGroupType::URLTest:
        case ProxyGroupType::Fallback:
            break;
        case ProxyGroupType::SSID:
            if(x.Proxies.size() < 2)
                continue;
            group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
            group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
                ini.set("{NONAME}", x.Name + " = " + group); //insert order
            continue;
        default:
            continue;
        }

        for(const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if(filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        auto iter = std::find_if(original_groups.begin(), original_groups.end(), [&](const string_multimap::value_type &n)
        {
            return trim(n.first) == x.Name;
        });

        if(iter != original_groups.end())
        {
            string_array vArray = split(iter->second, ",");
            if(vArray.size() > 1)
            {
                if(trim(vArray[vArray.size() - 1]).find("img-url") == 0)
                    filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
            }
        }

        group = x.TypeStr() + ",";
        /*
        for(std::string &y : filtered_nodelist)
            group += "," + y;
        */
        group += join(filtered_nodelist, ",");
        if(x.Type != ProxyGroupType::Select)
        {
            group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
            if(x.Type == ProxyGroupType::LoadBalance)
            {
                group += ",algorithm=" + std::string(x.Strategy == BalanceStrategy::RoundRobin || x.Strategy == BalanceStrategy::StickySessions ? "round-robin" : "pcc");
                if(x.Timeout > 0)
                    group += ",max-timeout=" + std::to_string(x.Timeout);
            }
            if(x.Type == ProxyGroupType::URLTest)
            {
                if(x.Tolerance > 0)
                    group += ",tolerance=" + std::to_string(x.Tolerance);
            }
            if(x.Type == ProxyGroupType::Fallback)
                group += ",max-timeout=" + std::to_string(x.Timeout);
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if(ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -4, ext.overwrite_original_rules, ext.managed_config_prefix);

    return ini.to_string();
}

static std::string formatSingBoxInterval(Integer interval)
{
    std::string result;
    if(interval >= 3600)
    {
        result += std::to_string(interval / 3600) + "h";
        interval %= 3600;
    }
    if(interval >= 60)
    {
        result += std::to_string(interval / 60) + "m";
        interval %= 60;
    }
    if(interval > 0)
        result += std::to_string(interval) + "s";
    return result;
}

static rapidjson::Value buildSingBoxTransport(const Proxy& proxy, rapidjson::MemoryPoolAllocator<>& allocator)
{
    rapidjson::Value transport(rapidjson::kObjectType);
    switch (hash_(proxy.TransferProtocol))
    {
        case "http"_hash:
        {
            if (!proxy.Host.empty())
                transport.AddMember("host", rapidjson::StringRef(proxy.Host.c_str()), allocator);
            [[fallthrough]];
        }
        case "ws"_hash:
        {
            transport.AddMember("type", rapidjson::StringRef(proxy.TransferProtocol.c_str()), allocator);
            if (proxy.Path.empty())
                transport.AddMember("path", "/", allocator);
            else
                transport.AddMember("path", rapidjson::StringRef(proxy.Path.c_str()), allocator);

            rapidjson::Value headers(rapidjson::kObjectType);
            if (!proxy.Host.empty())
                headers.AddMember("Host", rapidjson::StringRef(proxy.Host.c_str()), allocator);
            if (!proxy.Edge.empty())
                headers.AddMember("Edge", rapidjson::StringRef(proxy.Edge.c_str()), allocator);
            transport.AddMember("headers", headers, allocator);
            break;
        }
        case "grpc"_hash:
        {
            transport.AddMember("type", "grpc", allocator);
            if (!proxy.Path.empty())
                transport.AddMember("service_name", rapidjson::StringRef(proxy.Path.c_str()), allocator);
            break;
        }
        default:
            break;
    }
    return transport;
}

static void addSingBoxCommonMembers(rapidjson::Value &proxy, const Proxy &x, const rapidjson::GenericStringRef<rapidjson::Value::Ch> &type, rapidjson::MemoryPoolAllocator<> &allocator)
{
    proxy.AddMember("type", type, allocator);
    proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
    proxy.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()), allocator);
    proxy.AddMember("server_port", x.Port, allocator);
}

static void addHeaders(rapidjson::Value &transport, const Proxy &x, rapidjson::MemoryPoolAllocator<> &allocator)
{
    rapidjson::Value headers(rapidjson::kObjectType);
    if(!x.Host.empty())
        headers.AddMember("Host", rapidjson::StringRef(x.Host.c_str()), allocator);
    if(!x.Edge.empty())
        headers.AddMember("Edge", rapidjson::StringRef(x.Edge.c_str()), allocator);
    transport.AddMember("headers", headers, allocator);
}

static rapidjson::Value vectorToJsonArray(const std::vector<std::string> &array, rapidjson::MemoryPoolAllocator<> &allocator)
{
    rapidjson::Value result(rapidjson::kArrayType);
    for(const auto &x : array)
        result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
    return result;
}

static rapidjson::Value stringArrayToJsonArray(const std::string &array, const std::string &delimiter, rapidjson::MemoryPoolAllocator<> &allocator)
{
    rapidjson::Value result(rapidjson::kArrayType);
    string_array vArray = split(array, delimiter);
    for (const auto &x : vArray)
        result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
    return result;
}

static rapidjson::Value buildSingBoxHysteria2ServerPorts(const std::string &ports, rapidjson::MemoryPoolAllocator<> &allocator)
{
    rapidjson::Value result(rapidjson::kArrayType);
    string_array port_list = split(ports, ",");
    for (const auto &raw_port : port_list)
    {
        std::string port_entry = trim(raw_port);
        if (port_entry.empty())
            continue;

        const bool is_single_port = std::all_of(port_entry.begin(), port_entry.end(), [](unsigned char ch) { return std::isdigit(ch); });
        if (is_single_port)
            port_entry = port_entry + ":" + port_entry;

        result.PushBack(rapidjson::Value(port_entry.c_str(), allocator), allocator);
    }
    return result;
}

void proxyToSingBox(std::vector<Proxy> &nodes, rapidjson::Document &json, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document::AllocatorType &allocator = json.GetAllocator();
    rapidjson::Value outbounds(rapidjson::kArrayType), route(rapidjson::kArrayType);
    std::vector<Proxy> nodelist;
    string_array remarks_list;
    std::vector<std::string> Alpn;

    if (!ext.nodelist)
    {
        auto direct = buildObject(allocator, "type", "direct", "tag", "DIRECT");
        outbounds.PushBack(direct, allocator);
        auto reject = buildObject(allocator, "type", "block", "tag", "REJECT");
        outbounds.PushBack(reject, allocator);
        auto dns = buildObject(allocator, "type", "dns", "tag", "dns-out");
        outbounds.PushBack(dns, allocator);
    }

    for (Proxy &x : nodes)
    {
        std::string type = getProxyTypeName(x.Type);
        if (ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, xudp = ext.xudp;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        xudp.define(x.XUDP);
        rapidjson::Value proxy(rapidjson::kObjectType);
        switch (x.Type)
        {
            case ProxyType::Shadowsocks:
            {
                addSingBoxCommonMembers(proxy, x, "shadowsocks", allocator);
                proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if(!x.Plugin.empty() && !x.PluginOption.empty())
                {
                    std::string pluginName = x.Plugin;
                    if(pluginName == "simple-obfs" || pluginName == "obfs")
                        pluginName = "obfs-local";
                    else if(pluginName == "xray-plugin")
                        pluginName = "v2ray-plugin";
                    static const std::unordered_set<std::string> allowedPlugins = {"obfs-local", "v2ray-plugin", "shadow-tls", "relay"};
                    if(allowedPlugins.count(pluginName))
                    {
                        proxy.AddMember("plugin", rapidjson::StringRef(pluginName.c_str()), allocator);
                        proxy.AddMember("plugin_opts", rapidjson::StringRef(x.PluginOption.c_str()), allocator);
                    }
                }
                break;
            }
            case ProxyType::ShadowsocksR:
            {
                addSingBoxCommonMembers(proxy, x, "shadowsocksr", allocator);
                proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                proxy.AddMember("protocol", rapidjson::StringRef(x.Protocol.c_str()), allocator);
                proxy.AddMember("protocol_param", rapidjson::StringRef(x.ProtocolParam.c_str()), allocator);
                proxy.AddMember("obfs", rapidjson::StringRef(x.OBFS.c_str()), allocator);
                proxy.AddMember("obfs_param", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
                break;
            }
            case ProxyType::VMess:
            {
                addSingBoxCommonMembers(proxy, x, "vmess", allocator);
                proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()), allocator);
                proxy.AddMember("alter_id", x.AlterId, allocator);
                proxy.AddMember("security", rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);
                break;
            }
            case ProxyType::Trojan:
            {
                addSingBoxCommonMembers(proxy, x, "trojan", allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);

                auto transport = buildSingBoxTransport(x, allocator);
                if (!transport.ObjectEmpty())
                    proxy.AddMember("transport", transport, allocator);
                break;
            }
            case ProxyType::WireGuard:
            {
                proxy.AddMember("type", "wireguard", allocator);
                proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
                rapidjson::Value addresses(rapidjson::kArrayType);
                if(!x.SelfIP.empty())
                    addresses.PushBack(rapidjson::StringRef(x.SelfIP.c_str()), allocator);
                if(!x.SelfIPv6.empty())
                    addresses.PushBack(rapidjson::StringRef(x.SelfIPv6.c_str()), allocator);
                if(!addresses.Empty())
                    proxy.AddMember("local_address", addresses, allocator);
                proxy.AddMember("private_key", rapidjson::StringRef(x.PrivateKey.c_str()), allocator);

                rapidjson::Value peer(rapidjson::kObjectType);
                peer.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()), allocator);
                peer.AddMember("server_port", x.Port, allocator);
                peer.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                if (!x.PreSharedKey.empty())
                    peer.AddMember("pre_shared_key", rapidjson::StringRef(x.PreSharedKey.c_str()), allocator);

                if (!x.AllowedIPs.empty())
                {
                    auto allowed_ips = stringArrayToJsonArray(x.AllowedIPs, ",", allocator);
                    peer.AddMember("allowed_ips", allowed_ips, allocator);
                }

                if (!x.ClientId.empty())
                {
                    auto reserved = stringArrayToJsonArray(x.ClientId, ",", allocator);
                    peer.AddMember("reserved", reserved, allocator);
                }
                rapidjson::Value peers(rapidjson::kArrayType);
                peers.PushBack(peer, allocator);
                proxy.AddMember("peers", peers, allocator);
                if(x.Mtu)
                    proxy.AddMember("mtu", x.Mtu, allocator);
                break;
            }
            case ProxyType::Hysteria:
            {
                addSingBoxCommonMembers(proxy, x, "hysteria", allocator);
                if (!x.Up.empty())
                    proxy.AddMember("up_mbps", x.UpSpeed, allocator);
                if (!x.Down.empty())
                    proxy.AddMember("down_mbps", x.DownSpeed, allocator);
                if (!x.OBFS.empty())
                {
                    proxy.AddMember("obfs", rapidjson::StringRef(x.OBFS.c_str()), allocator);
                }

                if (!x.AuthStr.empty())
                {
                    proxy.AddMember("auth_str", rapidjson::StringRef(x.AuthStr.c_str()), allocator);
                    rapidjson::Value auth_str;
                    auth_str.SetString(base64Encode(x.AuthStr).c_str(), allocator);
                    proxy.AddMember("auth", auth_str, allocator);
                }
                if (x.RecvWindowConn)
                    proxy.AddMember("recv_window_conn", x.RecvWindowConn, allocator);
                if (x.RecvWindow)
                    proxy.AddMember("recv_window", x.RecvWindow, allocator);
                if (!x.DisableMtuDiscovery.is_undef())
                    proxy.AddMember("disable_mtu_discovery", x.DisableMtuDiscovery.get(), allocator);

                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if (!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    alpn.PushBack(rapidjson::StringRef(x.Alpn.c_str()), allocator);
                    tls.AddMember("alpn", alpn, allocator);
                }
                if (!x.Ca.empty())
                {
                    rapidjson::Value ca_str;
                    ca_str.SetString(x.Ca.c_str(), allocator);
                    tls.AddMember("certificate", ca_str, allocator);
                }
                if (!x.CaStr.empty())
                    tls.AddMember("certificate", rapidjson::StringRef(x.CaStr.c_str()), allocator);
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::Hysteria2:
            {
                addSingBoxCommonMembers(proxy, x, "hysteria2", allocator);
                if (!x.Ports.empty())
                    proxy.AddMember("server_ports", buildSingBoxHysteria2ServerPorts(x.Ports, allocator), allocator);
                if (!x.Up.empty())
                    proxy.AddMember("up_mbps", x.UpSpeed, allocator);
                if (!x.Down.empty())
                    proxy.AddMember("down_mbps", x.DownSpeed, allocator);
                if (!x.OBFS.empty())
                {
                    rapidjson::Value obfs(rapidjson::kObjectType);
                    obfs.AddMember("type", rapidjson::StringRef(x.OBFS.c_str()), allocator);
                    if (!x.OBFSParam.empty())
                        obfs.AddMember("password", rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
                    proxy.AddMember("obfs", obfs, allocator);
                }
                if (!x.Password.empty())
                    proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if (x.HopInterval)
                    proxy.AddMember("hop_interval", rapidjson::Value(formatSingBoxInterval(x.HopInterval).c_str(), allocator), allocator);
                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if (!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if (!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    alpn.PushBack(rapidjson::StringRef(x.Alpn.c_str()), allocator);
                    tls.AddMember("alpn", alpn, allocator);
                }
                if (!x.Ca.empty())
                {
                    rapidjson::Value ca_str(rapidjson::kStringType);
                    ca_str.SetString(x.Ca.c_str(), allocator);
                    tls.AddMember("certificate", ca_str, allocator);
                }
                if (!x.CaStr.empty())
                    tls.AddMember("certificate", rapidjson::StringRef(x.CaStr.c_str()), allocator);
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::TUIC:
            {
                addSingBoxCommonMembers(proxy, x, "tuic", allocator);
                if(!x.UUID.empty())
                    proxy.AddMember("uuid", rapidjson::StringRef(x.UUID.c_str()), allocator);
                if(!x.Password.empty())
                    proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if(!x.HeartbeatInterval.empty())
                    proxy.AddMember("heartbeat", rapidjson::StringRef(x.HeartbeatInterval.c_str()), allocator);
                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if(!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if(!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    string_array alpnItems = split(x.Alpn, ",");
                    if(alpnItems.empty()) alpnItems.push_back(x.Alpn);
                    for(auto &s : alpnItems)
                    {
                        std::string trimmed = trim(s);
                        if(!trimmed.empty())
                            alpn.PushBack(rapidjson::StringRef(trimmed.c_str()), allocator);
                    }
                    if(!alpn.Empty())
                        tls.AddMember("alpn", alpn, allocator);
                }
                if(!x.UdpRelayMode.empty())
                    proxy.AddMember("udp_relay_mode", rapidjson::StringRef(x.UdpRelayMode.c_str()), allocator);
                if(!x.CongestionController.empty())
                    proxy.AddMember("congestion_controller", rapidjson::StringRef(x.CongestionController.c_str()), allocator);
                if(!x.SNI.empty())
                    proxy.AddMember("sni", rapidjson::StringRef(x.SNI.c_str()), allocator);
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::AnyTLS:
            {
                addSingBoxCommonMembers(proxy, x, "anytls", allocator);
                if(!x.Password.empty())
                    proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                if(!x.SNI.empty())
                    proxy.AddMember("sni", rapidjson::StringRef(x.SNI.c_str()), allocator);
                if(x.IdleSessionCheckInterval)
                    proxy.AddMember("idle_session_check_interval", rapidjson::Value(formatSingBoxInterval(x.IdleSessionCheckInterval).c_str(), allocator), allocator);
                if(x.IdleSessionTimeout)
                    proxy.AddMember("idle_session_timeout", rapidjson::Value(formatSingBoxInterval(x.IdleSessionTimeout).c_str(), allocator), allocator);
                if(x.MinIdleSession)
                    proxy.AddMember("min_idle_session", rapidjson::Value(formatSingBoxInterval(x.MinIdleSession).c_str(), allocator), allocator);
                if(!x.Reuse.is_undef())
                    proxy.AddMember("reuse", x.Reuse.get(), allocator);
                rapidjson::Value tls(rapidjson::kObjectType);
                tls.AddMember("enabled", true, allocator);
                if(!scv.is_undef())
                    tls.AddMember("insecure", scv.get(), allocator);
                if(!x.Fingerprint.empty())
                {
                    rapidjson::Value utls(rapidjson::kObjectType);
                    utls.AddMember("enabled", true, allocator);
                    utls.AddMember("fingerprint", rapidjson::StringRef(x.Fingerprint.c_str()), allocator);
                    tls.AddMember("utls", utls, allocator);
                }
                if(!x.Alpn.empty())
                {
                    rapidjson::Value alpn(rapidjson::kArrayType);
                    for(const auto& item : x.Alpn)
                    {
                        std::string alpn_item(1, item);
                        alpn.PushBack(rapidjson::StringRef(alpn_item.c_str()), allocator);
                    }
                    tls.AddMember("alpn", alpn, allocator);
                }
                proxy.AddMember("tls", tls, allocator);
                break;
            }
            case ProxyType::VLESS:
            {
                addSingBoxCommonMembers(proxy, x, "vless", allocator);
                if(!x.UUID.empty())
                    proxy.AddMember("uuid", rapidjson::StringRef(x.UUID.c_str()), allocator);
                if (!x.Encryption.empty() && x.Encryption != "none")
                    proxy.AddMember("encryption", rapidjson::StringRef(x.Encryption.c_str()), allocator);
                if(!x.PacketEncoding.empty())
                    proxy.AddMember("packet_encoding", rapidjson::StringRef(x.PacketEncoding.c_str()), allocator);
                else if(xudp && udp)
                    proxy.AddMember("packet_encoding", "xudp", allocator);
                if(!x.Flow.empty())
                    proxy.AddMember("flow", rapidjson::StringRef(x.Flow.c_str()), allocator);
                rapidjson::Value vlesstransport(rapidjson::kObjectType);
                rapidjson::Value vlessheaders(rapidjson::kObjectType);
                switch(hash_(x.TransferProtocol))
                {
                    case "tcp"_hash:
                        break;
                    case "ws"_hash:
                        if(x.Path.empty())
                            vlesstransport.AddMember("path", "/", allocator);
                        else
                            vlesstransport.AddMember("path", rapidjson::StringRef(x.Path.c_str()), allocator);
                        if(!x.Host.empty())
                            vlessheaders.AddMember("Host", rapidjson::StringRef(x.Host.c_str()), allocator);
                        if(!x.Edge.empty())
                            vlessheaders.AddMember("Edge", rapidjson::StringRef(x.Edge.c_str()), allocator);
                        vlesstransport.AddMember("type", rapidjson::StringRef("ws"), allocator);
                        addHeaders(vlesstransport, x, allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    case "http"_hash:
                        vlesstransport.AddMember("type", rapidjson::StringRef("http"), allocator);
                        vlesstransport.AddMember("host", rapidjson::StringRef(x.Host.c_str()), allocator);
                        vlesstransport.AddMember("method", rapidjson::StringRef("GET"), allocator);
                        vlesstransport.AddMember("path", rapidjson::StringRef(x.Path.c_str()), allocator);
                        addHeaders(vlesstransport, x, allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    case "h2"_hash:
                        vlesstransport.AddMember("type", rapidjson::StringRef("httpupgrade"), allocator);
                        vlesstransport.AddMember("host", rapidjson::StringRef(x.Host.c_str()), allocator);
                        vlesstransport.AddMember("path", rapidjson::StringRef(x.Path.c_str()), allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    case "grpc"_hash:
                        vlesstransport.AddMember("type", rapidjson::StringRef("grpc"), allocator);
                        vlesstransport.AddMember("service_name", rapidjson::StringRef(x.GrpcServiceName.c_str()), allocator);
                        proxy.AddMember("transport", vlesstransport, allocator);
                        break;
                    default:
                        continue;
                }
                if(x.TLSSecure && !proxy.HasMember("tls"))
                {
                    rapidjson::Value tls(rapidjson::kObjectType);
                    tls.AddMember("enabled", true, allocator);
                    if(!x.ServerName.empty())
                        tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
                    else if(!x.Host.empty())
                        tls.AddMember("server_name", rapidjson::StringRef(x.Host.c_str()), allocator);
                    if(!scv.is_undef())
                        tls.AddMember("insecure", scv.get(), allocator);
                    if(!x.Alpn.empty())
                    {
                        auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
                        if(!alpns.Empty())
                            tls.AddMember("alpn", alpns, allocator);
                    }
                    if(!x.PublicKey.empty())
                    {
                        rapidjson::Value reality(rapidjson::kObjectType);
                        reality.AddMember("enabled", true, allocator);
                        reality.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()), allocator);
                        if(!x.ShortID.empty())
                            reality.AddMember("short_id", rapidjson::StringRef(x.ShortID.c_str()), allocator);
                        tls.AddMember("reality", reality, allocator);
                        rapidjson::Value utls(rapidjson::kObjectType);
                        utls.AddMember("enabled", true, allocator);
                        if(!x.Fingerprint.empty())
                            utls.AddMember("fingerprint", rapidjson::StringRef(x.Fingerprint.c_str()), allocator);
                        else
                            utls.AddMember("fingerprint", "chrome", allocator);
                        tls.AddMember("utls", utls, allocator);
                    }
                    else if(!x.Fingerprint.empty())
                        tls.AddMember("fingerprint", rapidjson::StringRef(x.Fingerprint.c_str()), allocator);
                    proxy.AddMember("tls", tls, allocator);
                }
                break;
            }
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
            {
                addSingBoxCommonMembers(proxy, x, "http", allocator);
                proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                break;
            }
            case ProxyType::SOCKS5:
            {
                addSingBoxCommonMembers(proxy, x, "socks", allocator);
                proxy.AddMember("version", "5", allocator);
                proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()), allocator);
                proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()), allocator);
                break;
            }
            default:
                continue;
        }
        if (x.TLSSecure && !proxy.HasMember("tls"))
        {
            rapidjson::Value tls(rapidjson::kObjectType);
            tls.AddMember("enabled", true, allocator);
            if (!x.ServerName.empty())
                tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()), allocator);
            if (!x.AlpnList.empty())
            {
                auto alpns = vectorToJsonArray(x.AlpnList, allocator);
                tls.AddMember("alpn", alpns, allocator);
            }
            else if(!x.Alpn.empty())
            {
                auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
                tls.AddMember("alpn", alpns, allocator);
            }
            tls.AddMember("insecure", buildBooleanValue(scv), allocator);
            proxy.AddMember("tls", tls, allocator);
        }
        if (!x.UnderlyingProxy.empty()) {
            proxy.AddMember("detour", rapidjson::Value(x.UnderlyingProxy.c_str(), allocator), allocator);
        }
        if (!udp.is_undef() && !udp)
        {
            proxy.AddMember("network", "tcp", allocator);
        }
        if (!tfo.is_undef())
        {
            proxy.AddMember("tcp_fast_open", buildBooleanValue(tfo), allocator);
        }
        nodelist.push_back(x);
        remarks_list.emplace_back(x.Remark);
        outbounds.PushBack(proxy, allocator);
    }

    if (ext.nodelist)
    {
        json | AddMemberOrReplace("outbounds", outbounds, allocator);
        return;
    }

    for (const ProxyGroupConfig &x: extra_proxy_group)
    {
        string_array filtered_nodelist;
        std::string type;
        switch (x.Type)
        {
            case ProxyGroupType::Select:
            {
                type = "selector";
                break;
            }
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
            case ProxyGroupType::LoadBalance:
            {
                type = "urltest";
                break;
            }
            default:
                continue;
        }
        for (const auto &y : x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        rapidjson::Value group(rapidjson::kObjectType);

        group.AddMember("type", rapidjson::Value(type.c_str(), allocator), allocator);
        group.AddMember("tag", rapidjson::Value(x.Name.c_str(), allocator), allocator);

        rapidjson::Value group_outbounds(rapidjson::kArrayType);
        for (const std::string& y: filtered_nodelist)
        {
            group_outbounds.PushBack(rapidjson::Value(y.c_str(), allocator), allocator);
        }
        group.AddMember("outbounds", group_outbounds, allocator);

        if (x.Type == ProxyGroupType::URLTest)
        {
            group.AddMember("url", rapidjson::Value(x.Url.c_str(), allocator), allocator);
            group.AddMember("interval", rapidjson::Value(formatSingBoxInterval(x.Interval).c_str(), allocator), allocator);
            if (x.Tolerance > 0)
                group.AddMember("tolerance", x.Tolerance, allocator);
        }
        outbounds.PushBack(group, allocator);
    }

    if (global.singBoxAddClashModes)
    {
        auto global_group = rapidjson::Value(rapidjson::kObjectType);
        global_group.AddMember("type", "selector", allocator);
        global_group.AddMember("tag", "GLOBAL", allocator);
        global_group.AddMember("outbounds", rapidjson::Value(rapidjson::kArrayType), allocator);
        global_group["outbounds"].PushBack("DIRECT", allocator);
        for (auto &x: remarks_list)
        {
            global_group["outbounds"].PushBack(rapidjson::Value(x.c_str(), allocator), allocator);
        }
        outbounds.PushBack(global_group, allocator);
    }

    json | AddMemberOrReplace("outbounds", outbounds, allocator);
}

std::string proxyToSingBox(std::vector<Proxy> &nodes, const std::string &base_conf, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext)
{
    using namespace rapidjson_ext;
    rapidjson::Document json;

    if (!ext.nodelist)
    {
        json.Parse(base_conf.data());
        if (json.HasParseError())
        {
            writeLog(0, "sing-box base loader failed with error: " +
                        std::string(rapidjson::GetParseError_En(json.GetParseError())), LOG_LEVEL_ERROR);
            return "";
        }
    }
    else
    {
        json.SetObject();
    }

    proxyToSingBox(nodes, json, ruleset_content_array, extra_proxy_group, ext);

    if(ext.nodelist || !ext.enable_rule_generator)
        return json | SerializeObject();

    rulesetToSingBox(json, ruleset_content_array, ext.overwrite_original_rules);

    return json | SerializeObject();
}
