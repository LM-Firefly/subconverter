#include <string>
#include <map>
#include <sstream>

#include "utils/base64/base64.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "config/proxy.h"
#include "handler/settings.h"
#include "subparser.h"

using namespace rapidjson;
using namespace rapidjson_ext;
using namespace YAML;

string_array ss_ciphers = {"rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "xchacha20", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305", "2022-blake3-chacha8-poly1305"};
string_array ssr_ciphers = {"none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"};

std::map<std::string, std::string> parsedMD5;
std::string modSSMD5 = "f7653207090ce3389115e9c88541afe0";

//remake from speedtestutil

void commonConstruct(Proxy &node, ProxyType type, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const tribool &udp, const tribool &tfo, const tribool &scv, const tribool &tls13,  const std::string& underlying_proxy)
{
    node.Type = type;
    node.Group = group;
    node.Remark = remarks;
    node.Hostname = server;
    node.UnderlyingProxy = underlying_proxy;
    node.Port = to_int(port);
    node.UDP = udp;
    node.TCPFastOpen = tfo;
    node.AllowInsecure = scv;
    node.TLS13 = tls13;
}

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &sni, const std::vector<std::string> &alpnList, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, const std::string &fingerprint, const std::string &clientFingerprint, tribool v2ray_http_upgrade, tribool v2ray_http_upgrade_fast_open)
{
    commonConstruct(node, ProxyType::VMess, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UserId = id.empty() ? "00000000-0000-0000-0000-000000000000" : id;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.TransferProtocol = net.empty() ? "tcp" : net;
    node.Edge = edge;
    node.ServerName = sni;
    node.Fingerprint = fingerprint;
    node.ClientFingerprint = clientFingerprint;
    // preserve ALPN list if provided
    if(!alpnList.empty())
        node.AlpnList = alpnList;

    if(net == "quic")
    {
        node.QUICSecure = host;
        node.QUICSecret = path;
    }
    else
    {
        node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
        node.Path = path.empty() ? "/" : trim(path);
        node.WsPath = path;
    }
    node.FakeType = type;
    node.TLSSecure = tls == "tls";
    node.TLSStr = tls;
    if(!path.empty() && net == "ws")
    {
        std::string::size_type pos = path.find("?");
        if(pos != std::string::npos)
        {
            std::string query = path.substr(pos + 1);
            node.Path = path.substr(0, pos);
            if(query.find("ed=") != std::string::npos)
            {
                node.WsEarlyDataHeaderName = "Sec-WebSocket-Protocol";
                std::string::size_type ed_pos = query.find("ed=");
                if(ed_pos != std::string::npos)
                {
                    std::string ed_param = query.substr(ed_pos + 3);
                    std::string::size_type next_param = ed_param.find("&");
                    if(next_param != std::string::npos)
                    {
                        ed_param = ed_param.substr(0, next_param);
                    }
                        node.WsMaxEarlyData = to_int(ed_param, 0);
                }
            }
        }
    }
    // preserve v2ray http upgrade flags if provided
    node.V2rayHttpUpgrade = v2ray_http_upgrade;
    node.V2rayHttpUpgradeFastOpen = v2ray_http_upgrade_fast_open;
}

void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &protocol, const std::string &method, const std::string &obfs, const std::string &password, const std::string &obfsparam, const std::string &protoparam, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::ShadowsocksR, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Protocol = protocol;
    node.ProtocolParam = protoparam;
    node.OBFS = obfs;
    node.OBFSParam = obfsparam;
}

void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &method, const std::string &plugin, const std::string &pluginopts, tribool udp, tribool tfo, tribool scv, tribool udp_over_tcp, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::Shadowsocks, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Plugin = plugin;
    node.PluginOption = pluginopts;
    node.UDPoverTCP = udp_over_tcp;
    std::string fingerprint = getUrlArg(pluginopts, "fingerprint");
    if(!fingerprint.empty())
        node.Fingerprint = fingerprint;
}

void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::SOCKS5, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Username = username;
    node.Password = password;
}

void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, bool tls, tribool tfo, tribool scv, tribool tls13, const std::string& underlying_proxy)
{
    commonConstruct(node, tls ? ProxyType::HTTPS : ProxyType::HTTP, group, remarks, server, port, tribool(), tfo, scv, tls13, underlying_proxy);
    node.Username = username;
    node.Password = password;
    node.TLSSecure = tls;
}

void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &network, const std::string &host, const std::string &path, const std::string &fp, const std::string &sni, const std::vector<std::string> &alpnList, bool tlssecure, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, tribool v2ray_http_upgrade, tribool v2ray_http_upgrade_fast_open)
{
    commonConstruct(node, ProxyType::Trojan, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.Host = host;
    node.TLSSecure = tlssecure;
    node.TransferProtocol = network.empty() ? "tcp" : network;
    node.Path = path;
    node.ClientFingerprint = fp;
    node.ServerName = sni;
    node.AlpnList = alpnList;
    if(network == "grpc")
    {
        node.GrpcServiceName = path;
    }
    else if(network == "ws")
    {
        node.WsPath = path;
        // Do not automatically copy `host` into `WsHeaders` here.
        // WsHeaders should only be set when the source explicitly provides WS header info.
        // This avoids introducing implicit Host headers during parsing.
    }
    // preserve v2ray http upgrade flags if provided
    node.V2rayHttpUpgrade = v2ray_http_upgrade;
    node.V2rayHttpUpgradeFastOpen = v2ray_http_upgrade_fast_open;
}

void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &obfs, const std::string &host, uint16_t version, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::Snell, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.OBFS = obfs;
    node.Host = host;
    node.SnellVersion = version;
}

void wireguardConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &selfIp, const std::string &selfIpv6, const std::string &privKey, const std::string &pubKey, const std::string &psk, const string_array &dns, const std::string &mtu, const std::string &keepalive, const std::string &testUrl, const std::string &clientId, const tribool &udp, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::WireGuard, group, remarks, server, port, udp, tribool(), tribool(), tribool(), underlying_proxy);
    node.SelfIP = selfIp;
    node.SelfIPv6 = selfIpv6;
    node.PrivateKey = privKey;
    node.PublicKey = pubKey;
    node.PreSharedKey = psk;
    node.DnsServers = dns;
    node.Mtu = to_int(mtu);
    node.KeepAlive = to_int(keepalive);
    node.TestUrl = testUrl;
    node.ClientId = clientId;
}

void hysteriaConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &ports, const std::string &protocol, const std::string &obfs_protocol, const std::string &up, const std::string &up_speed, const std::string &down, const std::string &down_speed, const std::string &auth, const std::string &auth_str, const std::string &obfs, const std::string &sni, const std::string &fingerprint, const std::string &ca, const std::string &ca_str, const std::string &recv_window_conn, const std::string &recv_window, const std::string &disable_mtu_discovery, const std::string &hop_interval, const std::vector<std::string> &alpnList, const std::string &alpn, tribool tfo, tribool scv, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Hysteria, group, remarks, server, port, tribool(), tfo, scv, tribool(), underlying_proxy);
    node.Ports = ports;
    node.Protocol = protocol;
    node.OBFSParam = obfs_protocol;
    if (!up.empty())
    {
        if (up.length() > 4 && up.find("bps") == up.length() - 3)
            node.Up = up;
        else if (to_int(up))
        {
            node.UpSpeed = to_int(up);
            node.Up = up + " Mbps";
        }
    }
    if (!up_speed.empty())
        node.UpSpeed = to_int(up_speed);
    if (!down.empty())
    {
        if (down.length() > 4 && down.find("bps") == down.length() - 3)
            node.Down = down;
        else if (to_int(down))
        {
            node.DownSpeed = to_int(down);
            node.Down = down + " Mbps";
        }
    }
    if (!down_speed.empty())
        node.DownSpeed = to_int(down_speed);
    if (!auth.empty())
        node.Auth = auth;
    if (!auth_str.empty())
        node.AuthStr = auth_str;
    node.OBFS = obfs;
    node.SNI = sni;
    node.Fingerprint = fingerprint;
    node.Ca = ca;
    node.CaStr = ca_str;
    node.RecvWindowConn = to_int(recv_window_conn);
    node.RecvWindow = to_int(recv_window);
    node.DisableMtuDiscovery = disable_mtu_discovery;
    node.HopInterval = to_int(hop_interval);
    if (!alpnList.empty())
    {
        node.AlpnList = alpnList;
    }
    else if (!alpn.empty())
    {
        node.Alpn = alpn;
    }
}

void hysteria2Construct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &ports, const std::string &up, const std::string &down, const std::string &password, const std::string &auth, const std::string &obfs, const std::string &obfs_password, const std::string &sni, const std::string &fingerprint, const std::string &alpn, const std::string &ca, const std::string &ca_str, const std::string &cwnd, const std::string &hop_interval, const std::string &ech_enable, const std::string &ech_config, const std::string &initial_stream_receive_window, const std::string &max_stream_receive_window, const std::string &initial_connection_receive_window, const std::string &max_connection_receive_window, tribool udp, tribool tfo, tribool scv, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Hysteria2, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    if(!up.empty())
    {
        if(up.find("bps") != std::string::npos || up.find("Mbps") != std::string::npos || up.find("Kbps") != std::string::npos || up.find("Gbps") != std::string::npos)
        {
            node.Up = up;
            std::string speed_val = up;
            speed_val = regReplace(speed_val, " ?(\\w*bps)", "");
            node.UpSpeed = to_int(speed_val);
        }
        else
        {
            node.UpSpeed = to_int(up);
        }
    }
    if(!down.empty())
    {
        if(down.find("bps") != std::string::npos || down.find("Mbps") != std::string::npos || down.find("Kbps") != std::string::npos || down.find("Gbps") != std::string::npos)
        {
            node.Down = down;
            std::string speed_val = down;
            speed_val = regReplace(speed_val, " ?(\\w*bps)", "");
            node.DownSpeed = to_int(speed_val);
        }
        else
        {
            node.DownSpeed = to_int(down);
        }
    }
    node.Ports = ports;
    node.Password = password;
    node.Auth = auth;
    if(node.Password.empty() && !node.Auth.empty())
    {
        node.Password = node.Auth;
    }
    if(!obfs.empty() && obfs != "none")
    {
        node.OBFS = obfs;
        node.OBFSParam = obfs_password;
    }
    node.SNI = sni;
    node.Fingerprint = fingerprint;
    if(!alpn.empty())
        node.Alpn = alpn;
    node.Ca = ca;
    node.CaStr = ca_str;
    node.CWND = to_int(cwnd);
    node.HopInterval = to_int(hop_interval);
    if(!ech_enable.empty())
    {
        node.EchEnable = tribool(ech_enable);
    }
    if(!ech_config.empty())
    {
        node.EchConfig = ech_config;
    }
    if(!initial_stream_receive_window.empty())
    {
        node.InitialStreamReceiveWindow = to_int(initial_stream_receive_window);
    }
    if(!max_stream_receive_window.empty())
    {
        node.MaxStreamReceiveWindow = to_int(max_stream_receive_window);
    }
    if(!initial_connection_receive_window.empty())
    {
        node.InitialConnectionReceiveWindow = to_int(initial_connection_receive_window);
    }
    if(!max_connection_receive_window.empty())
    {
        node.MaxConnectionReceiveWindow = to_int(max_connection_receive_window);
    }
}

void TUICConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &uuid, const std::string &password, const std::string &ip, const std::string &heartbeat_interval, const std::string &alpn, const std::string &disable_sni, const std::string &reduce_rtt, const std::string &request_timeout, const std::string &udp_relay_mode, const std::string &congestion_controller, const std::string &max_udp_relay_packet_size, const std::string &max_open_streams, const std::string &sni, const std::string &fast_open, const std::string &version, tribool tfo, tribool scv, const std::string &underlying_proxy)
{
    commonConstruct(node, ProxyType::TUIC, group, remarks, server, port, tribool(), tfo, scv, tribool(), underlying_proxy);
        node.Password = password;
        node.UUID = uuid;
        node.IP = ip;
        node.HeartbeatInterval = heartbeat_interval;
        if(!alpn.empty())
        {
            node.Alpn = alpn;
        }
        node.DisableSNI= disable_sni;
        node.ReduceRTT = reduce_rtt;
        node.RequestTimeout = to_int(request_timeout);
        node.UdpRelayMode = udp_relay_mode;
        node.CongestionController = congestion_controller;
        node.MaxUdpRelayPacketSize = to_int(max_udp_relay_packet_size);
        node.MaxOpenStreams =  to_int(max_open_streams);
        node.SNI = sni;
        node.FastOpen = tribool(fast_open);
        node.TuicVersion = to_int(version, 0);
}

void anyTLSConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &sni, const std::string &alpn, const std::string &fingerprint, const std::string &idle_session_check_interval, const std::string &idle_session_timeout, const std::string &min_idle_session, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy)
{
    commonConstruct(node, ProxyType::AnyTLS, group, remarks, server, port, tribool(), tfo, scv, tls13, underlying_proxy);
        node.Password = password;
        node.SNI = sni;
        if(!alpn.empty())
        {
            node.Alpn = alpn;
        }
        node.Fingerprint = fingerprint;
        node.IdleSessionCheckInterval = to_int(idle_session_check_interval);
        node.IdleSessionTimeout = to_int(idle_session_timeout);
        node.MinIdleSession = to_int(min_idle_session);
}

void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &uuid, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &public_key, const std::string &short_id, const std::string &fingerprint, const std::string &sni, const std::vector<std::string> &alpnList, const std::string &packet_encoding, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, tribool v2ray_http_upgrade, tribool v2ray_http_upgrade_fast_open)
{
    commonConstruct(node, ProxyType::VLESS, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UUID = uuid;
    node.SNI = sni;
    node.TransferProtocol = net.empty() ? "tcp" : type == "http" ? "http" : net;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.Edge = edge;
    node.Flow = flow;
    node.FakeType = type;
    node.TLSSecure = tls == "tls" || tls == "xtls" || tls == "reality";
    if(flow == "xtls-rprx-vision" || flow.find("vision") != std::string::npos)
        node.XTLS = 2;
    node.PublicKey = public_key;
    node.ShortID = short_id;
    node.Fingerprint = fingerprint;
    if(node.ClientFingerprint.empty())
        node.ClientFingerprint = fingerprint;
    node.AlpnList = alpnList;
    node.PacketEncoding = packet_encoding;
    node.TLSStr = tls;
    node.V2rayHttpUpgrade = v2ray_http_upgrade;
    node.V2rayHttpUpgradeFastOpen = v2ray_http_upgrade_fast_open;
    node.Host = host;
    switch (hash_(net))
    {
        case "grpc"_hash:
            node.Host = host;
            node.GRPCMode = mode.empty() ? "gun" : mode;
            node.GrpcServiceName = path.empty() ? "/" : urlEncode(urlDecode(trim(path)));
            break;
        case "http"_hash:
        case "h2"_hash:
            node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
            node.Path = path.empty() ? "/" : trim(path);
            break;
        case "quic"_hash:
            node.QUICSecure = host;
            node.QUICSecret = path.empty() ? "/" : trim(path);
            break;
        case "tcp"_hash:
            node.Host = trim(host);
            node.Path = trim(path);
            break;
        case "ws"_hash:
        default:
            node.Host = trim(host);
            node.Path = trim(path);
            break;
    }
}

void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &port, const std::string &password, const std::string &host, const std::string &ports, const std::string &username, const std::string &multiplexing, const std::string &transfer_protocol, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy)
{
    commonConstruct(node, ProxyType::Mieru, group, remarks, host, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Host = trim(host);
    node.Password = password;
    node.Ports = ports;
    node.TransferProtocol = transfer_protocol.empty()? "TCP" : trim(transfer_protocol);
    node.Username = username;
    node.Multiplexing = multiplexing.empty() ? "MULTIPLEXING_LOW" : trim(multiplexing);
}

void explodeVmess(std::string vmess, Proxy &node)
{
    std::string version, ps, add, port, type, id, aid, net, path, host, tls, sni;
    Document jsondata;
    std::vector<std::string> vArray;

    if(regMatch(vmess, "vmess://([A-Za-z0-9-_]+)\\?(.*)")) //shadowrocket style link
    {
        explodeShadowrocket(vmess, node);
        return;
    }
    else if(regMatch(vmess, "vmess://(.*?)@(.*)"))
    {
        explodeStdVMess(vmess, node);
        return;
    }
    else if(regMatch(vmess, "vmess1://(.*?)\\?(.*)")) //kitsunebi style link
    {
        explodeKitsunebi(vmess, node);
        return;
    }
    vmess = urlSafeBase64Decode(regReplace(vmess, "(vmess|vmess1)://", ""));
    if(regMatch(vmess, "(.*?) = (.*)"))
    {
        explodeQuan(vmess, node);
        return;
    }
    jsondata.Parse(vmess.data());
    if(jsondata.HasParseError() || !jsondata.IsObject())
        return;

    version = "1"; //link without version will treat as version 1
    GetMember(jsondata, "v", version); //try to get version

    GetMember(jsondata, "ps", ps);
    GetMember(jsondata, "add", add);
    port = GetMember(jsondata, "port");
    if(port == "0")
        return;
    GetMember(jsondata, "type", type);
    GetMember(jsondata, "id", id);
    GetMember(jsondata, "aid", aid);
    GetMember(jsondata, "net", net);
    GetMember(jsondata, "tls", tls);

    GetMember(jsondata, "host", host);
    GetMember(jsondata, "sni", sni);
    switch(to_int(version))
    {
    case 1:
        if(!host.empty())
        {
            vArray = split(host, ";");
            if(vArray.size() == 2)
            {
                host = vArray[0];
                path = vArray[1];
            }
        }
        break;
    case 2:
        path = GetMember(jsondata, "path");
        break;
    }

    add = trim(add);

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, "auto", path, host, "", tls, sni, std::vector<std::string>{});
}

void explodeVmessConf(std::string content, std::vector<Proxy> &nodes)
{
    Document json;
    rapidjson::Value nodejson, settings;
    std::string group, ps, add, port, type, id, aid, net, path, host, edge, tls, cipher, subid, sni;
    tribool udp, tfo, scv;
    int configType;
    uint32_t index = nodes.size();
    std::map<std::string, std::string> subdata;
    std::map<std::string, std::string>::iterator iter;
    std::string streamset = "streamSettings", tcpset = "tcpSettings", wsset = "wsSettings";
    regGetMatch(content, "((?i)streamsettings)", 2, 0, &streamset);
    regGetMatch(content, "((?i)tcpsettings)", 2, 0, &tcpset);
    regGetMatch(content, "((?1)wssettings)", 2, 0, &wsset);

    json.Parse(content.data());
    if(json.HasParseError() || !json.IsObject())
        return;
    try
    {
        if(json.HasMember("outbounds")) //single config
        {
            if(json["outbounds"].Size() > 0 && json["outbounds"][0].HasMember("settings") && json["outbounds"][0]["settings"].HasMember("vnext") && json["outbounds"][0]["settings"]["vnext"].Size() > 0)
            {
                Proxy node;
                nodejson = json["outbounds"][0];
                add = GetMember(nodejson["settings"]["vnext"][0], "address");
                port = GetMember(nodejson["settings"]["vnext"][0], "port");
                if(port == "0")
                    return;
                if(nodejson["settings"]["vnext"][0]["users"].Size())
                {
                    id = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "id");
                    aid = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "alterId");
                    cipher = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "security");
                }
                if(nodejson.HasMember(streamset.data()))
                {
                    net = GetMember(nodejson[streamset.data()], "network");
                    tls = GetMember(nodejson[streamset.data()], "security");
                    if(net == "ws")
                    {
                        if(nodejson[streamset.data()].HasMember(wsset.data()))
                            settings = nodejson[streamset.data()][wsset.data()];
                        else
                            settings.RemoveAllMembers();
                        path = GetMember(settings, "path");
                        if(settings.HasMember("headers"))
                        {
                            host = GetMember(settings["headers"], "Host");
                            edge = GetMember(settings["headers"], "Edge");
                        }
                    }
                    if(nodejson[streamset.data()].HasMember(tcpset.data()))
                        settings = nodejson[streamset.data()][tcpset.data()];
                    else
                        settings.RemoveAllMembers();
                    if(settings.IsObject() && settings.HasMember("header"))
                    {
                        type = GetMember(settings["header"], "type");
                        if(type == "http")
                        {
                            if(settings["header"].HasMember("request"))
                            {
                                if(settings["header"]["request"].HasMember("path") && settings["header"]["request"]["path"].Size())
                                    settings["header"]["request"]["path"][0] >> path;
                                if(settings["header"]["request"].HasMember("headers"))
                                {
                                    host = GetMember(settings["header"]["request"]["headers"], "Host");
                                    edge = GetMember(settings["header"]["request"]["headers"], "Edge");
                                }
                            }
                        }
                    }
                }
                vmessConstruct(node, V2RAY_DEFAULT_GROUP, add + ":" + port, add, port, type, id, aid, net, cipher, path, host, edge, tls, "", std::vector<std::string>{}, udp, tfo, scv);
                nodes.emplace_back(std::move(node));
            }
            return;
        }
    }
    catch(std::exception & e)
    {
        //writeLog(0, "VMessConf parser throws an error. Leaving...", LOG_LEVEL_WARNING);
        //return;
        //ignore
        throw;
    }
    //read all subscribe remark as group name
    for(uint32_t i = 0; i < json["subItem"].Size(); i++)
        subdata.insert(std::pair<std::string, std::string>(json["subItem"][i]["id"].GetString(), json["subItem"][i]["remarks"].GetString()));

    for(uint32_t i = 0; i < json["vmess"].Size(); i++)
    {
        Proxy node;
        if(json["vmess"][i]["address"].IsNull() || json["vmess"][i]["port"].IsNull() || json["vmess"][i]["id"].IsNull())
            continue;

        //common info
        json["vmess"][i]["remarks"] >> ps;
        json["vmess"][i]["address"] >> add;
        port = GetMember(json["vmess"][i], "port");
        if(port == "0")
            continue;
        json["vmess"][i]["subid"] >> subid;

        if(!subid.empty())
        {
            iter = subdata.find(subid);
            if(iter != subdata.end())
                group = iter->second;
        }
        if(ps.empty())
            ps = add + ":" + port;

        scv = GetMember(json["vmess"][i], "allowInsecure");
        json["vmess"][i]["configType"] >> configType;
        switch(configType)
        {
        case 1: //vmess config
            json["vmess"][i]["headerType"] >> type;
            json["vmess"][i]["id"] >> id;
            json["vmess"][i]["alterId"] >> aid;
            json["vmess"][i]["network"] >> net;
            json["vmess"][i]["path"] >> path;
            json["vmess"][i]["requestHost"] >> host;
            json["vmess"][i]["streamSecurity"] >> tls;
            json["vmess"][i]["security"] >> cipher;
            json["vmess"][i]["sni"] >> sni;
            vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, cipher, path, host, "", tls, sni, std::vector<std::string>{}, udp, tfo, scv);
            break;
        case 3: //ss config
            json["vmess"][i]["id"] >> id;
            json["vmess"][i]["security"] >> cipher;
            ssConstruct(node, SS_DEFAULT_GROUP, ps, add, port, id, cipher, "", "", udp, tfo, scv);
            break;
        case 4: //socks config
            socksConstruct(node, SOCKS_DEFAULT_GROUP, ps, add, port, "", "", udp, tfo, scv);
            break;
        default:
            continue;
        }
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSS(std::string ss, Proxy &node)
{
    std::string ps, password, method, server, port, plugins, plugin, pluginopts, addition, group = SS_DEFAULT_GROUP, secret;
    //std::vector<std::string> args, secret;
    ss = replaceAllDistinct(ss.substr(5), "/?", "?");
    if(strFind(ss, "#"))
    {
        auto sspos = ss.find('#');
        ps = urlDecode(ss.substr(sspos + 1));
        ss.erase(sspos);
    }

    if(strFind(ss, "?"))
    {
        addition = ss.substr(ss.find('?') + 1);
        plugins = urlDecode(getUrlArg(addition, "plugin"));
        auto pluginpos = plugins.find(';');
        plugin = plugins.substr(0, pluginpos);
        pluginopts = plugins.substr(pluginpos + 1);
        group = getUrlArg(addition, "group");
        if(!group.empty())
            group = urlSafeBase64Decode(group);
        ss.erase(ss.find('?'));
    }
    if(strFind(ss, "@"))
    {
        if(regGetMatch(ss, "(\\S+?)@(\\S+):(\\d+)", 4, 0, &secret, &server, &port))
            return;
        if(regGetMatch(urlSafeBase64Decode(secret), "(\\S+?):(\\S+)", 3, 0, &method, &password))
            return;
    }
    else
    {
        if(regGetMatch(urlSafeBase64Decode(ss), "(\\S+?):(\\S+)@(\\S+):(\\d+)", 5, 0, &method, &password, &server, &port))
            return;
    }
    if(port == "0")
        return;
    if(ps.empty())
        ps = server + ":" + port;

    ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
}

void explodeSSD(std::string link, std::vector<Proxy> &nodes)
{
    Document jsondata;
    uint32_t index = nodes.size(), listType = 0, listCount = 0;
    std::string group, port, method, password, server, remarks;
    std::string plugin, pluginopts;
    std::map<uint32_t, std::string> node_map;

    link = urlSafeBase64Decode(link.substr(6));
    jsondata.Parse(link.c_str());
    if(jsondata.HasParseError() || !jsondata.IsObject())
        return;
    if(!jsondata.HasMember("servers"))
        return;
    GetMember(jsondata, "airport", group);

    if(jsondata["servers"].IsArray())
    {
        listType = 0;
        listCount = jsondata["servers"].Size();
    }
    else if(jsondata["servers"].IsObject())
    {
        listType = 1;
        listCount = jsondata["servers"].MemberCount();
        uint32_t node_index = 0;
        for(rapidjson::Value::MemberIterator iter = jsondata["servers"].MemberBegin(); iter != jsondata["servers"].MemberEnd(); iter++)
        {
            node_map.emplace(node_index, iter->name.GetString());
            node_index++;
        }
    }
    else
        return;

    rapidjson::Value singlenode;
    for(uint32_t i = 0; i < listCount; i++)
    {
        //get default info
        port = GetMember(jsondata, "port");
        method = GetMember(jsondata, "encryption");
        password = GetMember(jsondata, "password");
        plugin = GetMember(jsondata, "plugin");
        pluginopts = GetMember(jsondata, "plugin_options");

        //get server-specific info
        switch(listType)
        {
        case 0:
            singlenode = jsondata["servers"][i];
            break;
        case 1:
            singlenode = jsondata["servers"].FindMember(node_map[i].data())->value;
            break;
        default:
            continue;
        }
        singlenode["server"] >> server;
        GetMember(singlenode, "remarks", remarks);
        GetMember(singlenode, "port", port);
        GetMember(singlenode, "encryption", method);
        GetMember(singlenode, "password", password);
        GetMember(singlenode, "plugin", plugin);
        GetMember(singlenode, "plugin_options", pluginopts);

        if(port == "0")
            continue;

        Proxy node;
        ssConstruct(node, group, remarks, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSAndroid(std::string ss, std::vector<Proxy> &nodes)
{
    std::string ps, password, method, server, port, group = SS_DEFAULT_GROUP;
    std::string plugin, pluginopts;

    Document json;
    auto index = nodes.size();
    //first add some extra data before parsing
    ss = "{\"nodes\":" + ss + "}";
    json.Parse(ss.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    for(uint32_t i = 0; i < json["nodes"].Size(); i++)
    {
        Proxy node;
        server = GetMember(json["nodes"][i], "server");
        if(server.empty())
            continue;
        ps = GetMember(json["nodes"][i], "remarks");
        port = GetMember(json["nodes"][i], "server_port");
        if(port == "0")
            continue;
        if(ps.empty())
            ps = server + ":" + port;
        password = GetMember(json["nodes"][i], "password");
        method = GetMember(json["nodes"][i], "method");
        plugin = GetMember(json["nodes"][i], "plugin");
        pluginopts = GetMember(json["nodes"][i], "plugin_opts");

        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSConf(std::string content, std::vector<Proxy> &nodes)
{
    Document json;
    std::string ps, password, method, server, port, plugin, pluginopts, group = SS_DEFAULT_GROUP;
    auto index = nodes.size();

    json.Parse(content.data());
    if(json.HasParseError() || !json.IsObject())
        return;
    const char *section = json.HasMember("version") && json.HasMember("servers") ? "servers" : "configs";
    if(!json.HasMember(section))
        return;
    GetMember(json, "remarks", group);

    for(uint32_t i = 0; i < json[section].Size(); i++)
    {
        Proxy node;
        ps = GetMember(json[section][i], "remarks");
        port = GetMember(json[section][i], "server_port");
        if(port == "0")
            continue;
        if(ps.empty())
            ps = server + ":" + port;

        password = GetMember(json[section][i], "password");
        method = GetMember(json[section][i], "method");
        server = GetMember(json[section][i], "server");
        plugin = GetMember(json[section][i], "plugin");
        pluginopts = GetMember(json[section][i], "plugin_opts");

        node.Id = index;
        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSR(std::string ssr, Proxy &node)
{
    std::string strobfs;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam;
    ssr = replaceAllDistinct(ssr.substr(6), "\r", "");
    ssr = urlSafeBase64Decode(ssr);
    if(strFind(ssr, "/?"))
    {
        strobfs = ssr.substr(ssr.find("/?") + 2);
        ssr = ssr.substr(0, ssr.find("/?"));
        group = urlSafeBase64Decode(getUrlArg(strobfs, "group"));
        remarks = urlSafeBase64Decode(getUrlArg(strobfs, "remarks"));
        obfsparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "obfsparam")), "\\s", "");
        protoparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "protoparam")), "\\s", "");
    }

    if(regGetMatch(ssr, "(\\S+):(\\d+?):(\\S+?):(\\S+?):(\\S+?):(\\S+)", 7, 0, &server, &port, &protocol, &method, &obfs, &password))
        return;
    password = urlSafeBase64Decode(password);
    if(port == "0")
        return;

    if(group.empty())
        group = SSR_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;

    if(find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin"))
    {
        ssConstruct(node, group, remarks, server, port, password, method, "", "");
    }
    else
    {
        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
    }
}

void explodeSSRConf(std::string content, std::vector<Proxy> &nodes)
{
    Document json;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam, plugin, pluginopts;
    auto index = nodes.size();

    json.Parse(content.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    if(json.HasMember("local_port") && json.HasMember("local_address")) //single libev config
    {
        Proxy node;
        server = GetMember(json, "server");
        port = GetMember(json, "server_port");
        remarks = server + ":" + port;
        method = GetMember(json, "method");
        obfs = GetMember(json, "obfs");
        protocol = GetMember(json, "protocol");
        if(find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin"))
        {
            plugin = GetMember(json, "plugin");
            pluginopts = GetMember(json, "plugin_opts");
            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts);
        }
        else
        {
            protoparam = GetMember(json, "protocol_param");
            obfsparam = GetMember(json, "obfs_param");
            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
        }
        nodes.emplace_back(std::move(node));
        return;
    }

    for(uint32_t i = 0; i < json["configs"].Size(); i++)
    {
        Proxy node;
        group = GetMember(json["configs"][i], "group");
        if(group.empty())
            group = SSR_DEFAULT_GROUP;
        remarks = GetMember(json["configs"][i], "remarks");
        server = GetMember(json["configs"][i], "server");
        port = GetMember(json["configs"][i], "server_port");
        if(port == "0")
            continue;
        if(remarks.empty())
            remarks = server + ":" + port;

        password = GetMember(json["configs"][i], "password");
        method = GetMember(json["configs"][i], "method");

        protocol = GetMember(json["configs"][i], "protocol");
        protoparam = GetMember(json["configs"][i], "protocolparam");
        obfs = GetMember(json["configs"][i], "obfs");
        obfsparam = GetMember(json["configs"][i], "obfsparam");

        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSocks(std::string link, Proxy &node)
{
    std::string group, remarks, server, port, username, password;
    if(strFind(link, "socks://")) //v2rayn socks link
    {
        if(strFind(link, "#"))
        {
            auto pos = link.find('#');
            remarks = urlDecode(link.substr(pos + 1));
            link.erase(pos);
        }
        link = urlSafeBase64Decode(link.substr(8));
        if(strFind(link, "@"))
        {
            auto userinfo = split(link, '@');
            if(userinfo.size() < 2)
                return;
            link = userinfo[1];
            userinfo = split(userinfo[0], ':');
            if(userinfo.size() < 2)
                return;
            username = userinfo[0];
            password = userinfo[1];
        }
        auto arguments = split(link, ':');
        if(arguments.size() < 2)
            return;
        server = arguments[0];
        port = arguments[1];
    }
    else if(strFind(link, "https://t.me/socks") || strFind(link, "tg://socks")) //telegram style socks link
    {
        server = getUrlArg(link, "server");
        port = getUrlArg(link, "port");
        username = urlDecode(getUrlArg(link, "user"));
        password = urlDecode(getUrlArg(link, "pass"));
        remarks = urlDecode(getUrlArg(link, "remarks"));
        group = urlDecode(getUrlArg(link, "group"));
    }
    if(group.empty())
        group = SOCKS_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;
    if(port == "0")
        return;

    socksConstruct(node, group, remarks, server, port, username, password);
}

void explodeHTTP(const std::string &link, Proxy &node)
{
    std::string group, remarks, server, port, username, password;
    server = getUrlArg(link, "server");
    port = getUrlArg(link, "port");
    username = urlDecode(getUrlArg(link, "user"));
    password = urlDecode(getUrlArg(link, "pass"));
    remarks = urlDecode(getUrlArg(link, "remarks"));
    group = urlDecode(getUrlArg(link, "group"));

    if(group.empty())
        group = HTTP_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;
    if(port == "0")
        return;

    httpConstruct(node, group, remarks, server, port, username, password, strFind(link, "/https"));
}

void explodeHTTPSub(std::string link, Proxy &node)
{
    std::string group, remarks, server, port, username, password;
    std::string addition;
    bool tls = strFind(link, "https://");
    auto pos = link.find('?');
    if(pos != std::string::npos)
    {
        addition = link.substr(pos + 1);
        link.erase(pos);
        remarks = urlDecode(getUrlArg(addition, "remarks"));
        group = urlDecode(getUrlArg(addition, "group"));
    }
    link.erase(0, link.find("://") + 3);
    link = urlSafeBase64Decode(link);
    if(strFind(link, "@"))
    {
        if(regGetMatch(link, "(.*?):(.*?)@(.*):(.*)", 5, 0, &username, &password, &server, &port))
            return;
    }
    else
    {
        if(regGetMatch(link, "(.*):(.*)", 3, 0, &server, &port))
            return;
    }

    if(group.empty())
        group = HTTP_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;
    if(port == "0")
        return;

    httpConstruct(node, group, remarks, server, port, username, password, tls);
}

void explodeTrojan(std::string trojan, Proxy &node)
{
    std::string server, port, psk, addition, group, remark, host, path, network, fp, sni;
    tribool tfo, scv;
    if (startsWith(trojan, "trojan://"))
        trojan.erase(0, 9);
    if (startsWith(trojan, "trojan-go://"))
        trojan.erase(0, 12);
    string_size pos = trojan.rfind('#');

    if(pos != std::string::npos)
    {
        remark = urlDecode(trojan.substr(pos + 1));
        trojan.erase(pos);
    }
    pos = trojan.find('?');
    if(pos != std::string::npos)
    {
        addition = trojan.substr(pos + 1);
        trojan.erase(pos);
    }

    if(regGetMatch(trojan, "(.*?)@(.*):(.*)", 4, 0, &psk, &server, &port))
        return;
    if(port == "0")
        return;

    host = getUrlArg(addition, "sni");
    sni = getUrlArg(addition, "sni");
    if(host.empty())
        host = getUrlArg(addition, "peer");
    tfo = getUrlArg(addition, "tfo");
    scv = getUrlArg(addition, "allowInsecure");
    group = urlDecode(getUrlArg(addition, "group"));

    if(getUrlArg(addition, "ws") == "1")
    {
        path = getUrlArg(addition, "wspath");
        network = "ws";
    }
    // support the trojan link format used by v2ryaN and X-ui.
    // format: trojan://{password}@{server}:{port}?type=ws&security=tls&path={path (urlencoded)}&sni={host}#{name}
    else if(getUrlArg(addition, "type") == "ws")
    {
        path = getUrlArg(addition, "path");
        if(path.substr(0, 3) == "%2F")
            path = urlDecode(path);
        network = "ws";
    }
    else if(getUrlArg(addition, "type") == "grpc")
    {
        path = getUrlArg(addition, "serviceName");
        if(path.empty())
            path = getUrlArg(addition, "path");
        network = "grpc";
    }
    fp = getUrlArg(addition, "fp");
    if(fp.empty())
        fp = getUrlArg(addition, "client-fingerprint");
    if(!fp.empty())
        node.ClientFingerprint = fp;
    std::string fingerprint = getUrlArg(addition, "fingerprint");
    if(!fingerprint.empty())
        node.Fingerprint = fingerprint;
    std::string flow = getUrlArg(addition, "flow");
    if(!flow.empty())
        node.Flow = flow;
    if(remark.empty())
        remark = server + ":" + port;
    if(group.empty())
        group = TROJAN_DEFAULT_GROUP;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
    {
        string_size pos = 0, next_pos = 0;
        while((next_pos = alpn.find(',', pos)) != std::string::npos)
        {
            std::string value = trim(alpn.substr(pos, next_pos - pos));
            if(!value.empty())
                alpnList.push_back(value);
            pos = next_pos + 1;
        }
        std::string value = trim(alpn.substr(pos));
        if(!value.empty())
            alpnList.push_back(value);
    }

    trojanConstruct(node, group, remark, server, port, psk, network, host, path, fp, sni, alpnList, true, tribool(), tfo, scv);
}

void explodeHysteria(std::string hysteria, Proxy &node)
{
    hysteria = regReplace(hysteria, "(hysteria|hy)://", "hysteria://");
    if(regMatch(hysteria, "hysteria://(.*?)[:](.*)"))
    {
        explodeStdHysteria(hysteria, node);
        return;
    }
}

void explodeTUIC(std::string TUIC, Proxy &node)
{
    TUIC = regReplace(TUIC, "(tuic)://", "tuic://");

    TUIC = regReplace(TUIC, "/\\?", "?", true, false);
    if(regMatch(TUIC, "tuic://(.*?)[:](.*)"))
    {
        explodeStdTUIC(TUIC, node);
        return;
    }
}

void explodeMierus(std::string mierus, Proxy &node)
{
    if(strFind(mierus, "mierus://"))
    {
        if(regMatch(mierus, "mierus://(.*?)@(.*)"))
        {
            explodeStdMieru(mierus.substr(9), node);
        }
        else
        {
            mierus = urlSafeBase64Decode(mierus.substr(9));
            explodeStdMieru("mierus://" + mierus, node);
        }
    }
    else if(strFind(mierus, "mieru://"))
    {
        if(regMatch(mierus, "mierus://(.*?)@(.*)"))
        {
            explodeStdMieru(mierus.substr(8), node);
        }
        else
        {
            mierus = urlSafeBase64Decode(mierus.substr(8));
            explodeStdMieru("mierus://" + mierus, node);
        }
    }
}

void explodeQuan(const std::string &quan, Proxy &node)
{
    std::string strTemp, itemName, itemVal;
    std::string group = V2RAY_DEFAULT_GROUP, ps, add, port, cipher, type = "none", id, aid = "0", net = "tcp", path, host, edge, tls;
    string_array configs, vArray, headers;
    strTemp = regReplace(quan, "(.*?) = (.*)", "$1,$2");
    configs = split(strTemp, ",");

    if(configs[1] == "vmess")
    {
        if(configs.size() < 6)
            return;
        ps = trim(configs[0]);
        add = trim(configs[2]);
        port = trim(configs[3]);
        if(port == "0")
            return;
        cipher = trim(configs[4]);
        id = trim(replaceAllDistinct(configs[5], "\"", ""));

        //read link
        for(uint32_t i = 6; i < configs.size(); i++)
        {
            vArray = split(configs[i], "=");
            if(vArray.size() < 2)
                continue;
            itemName = trim(vArray[0]);
            itemVal = trim(vArray[1]);
            switch(hash_(itemName))
            {
            case "group"_hash:
                group = itemVal;
                break;
            case "over-tls"_hash:
                tls = itemVal == "true" ? "tls" : "";
                break;
            case "tls-host"_hash:
                host = itemVal;
                break;
            case "obfs-path"_hash:
                path = replaceAllDistinct(itemVal, "\"", "");
                break;
            case "obfs-header"_hash:
                headers = split(replaceAllDistinct(replaceAllDistinct(itemVal, "\"", ""), "[Rr][Nn]", "|"), "|");
                for(std::string &x : headers)
                {
                    if(regFind(x, "(?i)Host: "))
                        host = x.substr(6);
                    else if(regFind(x, "(?i)Edge: "))
                        edge = x.substr(6);
                }
                break;
            case "obfs"_hash:
                if(itemVal == "ws")
                    net = "ws";
                break;
            default:
                continue;
            }
        }
        if(path.empty())
            path = "/";

        vmessConstruct(node, group, ps, add, port, type, id, aid, net, cipher, path, host, edge, tls, "", std::vector<std::string>{});
    }
}

void explodeNetch(std::string netch, Proxy &node)
{
    Document json;
    std::string type, group, remark, address, port, username, password, method, plugin, pluginopts;
    std::string protocol, protoparam, obfs, obfsparam, id, aid, transprot, faketype, host, edge, path, tls, sni, fp;
    tribool udp, tfo, scv;
    netch = urlSafeBase64Decode(netch.substr(8));

    json.Parse(netch.data());
    if(json.HasParseError() || !json.IsObject())
        return;
    type = GetMember(json, "Type");
    group = GetMember(json, "Group");
    remark = GetMember(json, "Remark");
    address = GetMember(json, "Hostname");
    udp = GetMember(json, "EnableUDP");
    tfo = GetMember(json, "EnableTFO");
    scv = GetMember(json, "AllowInsecure");
    port = GetMember(json, "Port");
    fp = GetMember(json, "FingerPrint");
    if(port == "0")
        return;
    method = GetMember(json, "EncryptMethod");
    password = GetMember(json, "Password");
    if(remark.empty())
        remark = address + ":" + port;
    switch(hash_(type))
    {
    case "SS"_hash:
        plugin = GetMember(json, "Plugin");
        pluginopts = GetMember(json, "PluginOption");
        if(group.empty())
            group = SS_DEFAULT_GROUP;
        ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
        break;
    case "SSR"_hash:
        protocol = GetMember(json, "Protocol");
        obfs = GetMember(json, "OBFS");
        if(find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin"))
        {
            plugin = GetMember(json, "Plugin");
            pluginopts = GetMember(json, "PluginOption");
            if(group.empty())
                group = SS_DEFAULT_GROUP;
            ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
        }
        else
        {
            protoparam = GetMember(json, "ProtocolParam");
            obfsparam = GetMember(json, "OBFSParam");
            if(group.empty())
                group = SSR_DEFAULT_GROUP;
            ssrConstruct(node, group, remark, address, port, protocol, method, obfs, password, obfsparam, protoparam, udp, tfo, scv);
        }
        break;
    case "VMess"_hash:
        id = GetMember(json, "UserID");
        aid = GetMember(json, "AlterID");
        transprot = GetMember(json, "TransferProtocol");
        faketype = GetMember(json, "FakeType");
        host = GetMember(json, "Host");
        path = GetMember(json, "Path");
        edge = GetMember(json, "Edge");
        tls = GetMember(json, "TLSSecure");
        sni = GetMember(json, "ServerName");
        if(group.empty())
            group = V2RAY_DEFAULT_GROUP;
        vmessConstruct(node, group, remark, address, port, faketype, id, aid, transprot, method, path, host, edge, tls, sni, std::vector<std::string>{}, udp, tfo, scv);
        break;
    case "Socks5"_hash:
        username = GetMember(json, "Username");
        if(group.empty())
            group = SOCKS_DEFAULT_GROUP;
        socksConstruct(node, group, remark, address, port, username, password, udp, tfo, scv);
        break;
    case "HTTP"_hash:
    case "HTTPS"_hash:
        if(group.empty())
            group = HTTP_DEFAULT_GROUP;
        httpConstruct(node, group, remark, address, port, username, password, type == "HTTPS", tfo, scv);
        break;
    case "Trojan"_hash:
        host = GetMember(json, "Host");
        path = GetMember(json, "Path");
        transprot = GetMember(json, "TransferProtocol");
        tls = GetMember(json, "TLSSecure");
        sni = host;
        if(group.empty())
            group = TROJAN_DEFAULT_GROUP;
        trojanConstruct(node, group, remark, address, port, password, transprot, host, path, fp, sni, std::vector<std::string>{}, tls == "true", udp, tfo, scv);
        break;
    case "Snell"_hash:
        obfs = GetMember(json, "OBFS");
        host = GetMember(json, "Host");
        aid = GetMember(json, "SnellVersion");
        if(group.empty())
            group = SNELL_DEFAULT_GROUP;
        snellConstruct(node, group, remark, address, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv);
        break;
    default:
        return;
    }
}

void explodeClash(Node yamlnode, std::vector<Proxy> &nodes)
{
    std::string proxytype, ps, server, port, cipher, group, password, underlying_proxy; //common
    std::string type, id, aid, net, path, host, edge, tls, sni; //vmess
    std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux, pluginopts_version, pluginopts_password; //ss
    std::string protocol, protoparam, obfs, obfsparam; //ssr
    std::string fp, flow, mode, clientFingerprint; //trojan
    std::string user, ip_version; //socks
    std::string ip, ipv6, private_key, public_key, mtu; //wireguard
    std::string ports, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, /* obfs, sni,*/ fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpn; //hysteria
    std::string obfs_password, cwnd, ech_enable, ech_config, initial_stream_receive_window, max_stream_receive_window, initial_connection_receive_window, max_connection_receive_window; //hysteria2
    std::string uuid, heartbeat_interval, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, fast_open, version;   //tuic
    std::string idle_session_check_interval, idle_session_timeout, min_idle_session; // anytls
    std::string multiplexing, transfer_protocol; // mieru
    std::string sid, packet_encoding, encryption; // vless
    string_array dns_server;
    tribool udp, tfo, scv, udp_over_tcp;
    tribool v2ray_http_upgrade, v2ray_http_upgrade_fast_open, vless_udp;
    std::vector<std::string> alpnList;
    Node singleproxy;
    uint32_t index = nodes.size();
    const std::string section = yamlnode["proxies"].IsDefined() ? "proxies" : "Proxy";
    
    // Macro to reset all string variables (prevents cross-node contamination)
    #define RESET_VARS() proxytype.clear(); ps.clear(); server.clear(); port.clear(); cipher.clear(); group.clear(); password.clear(); underlying_proxy.clear(); type.clear(); id.clear(); aid.clear(); net.clear(); path.clear(); host.clear(); edge.clear(); tls.clear(); sni.clear(); plugin.clear(); pluginopts.clear(); pluginopts_mode.clear(); pluginopts_host.clear(); pluginopts_mux.clear(); pluginopts_version.clear(); pluginopts_password.clear(); protocol.clear(); protoparam.clear(); obfs.clear(); obfsparam.clear(); fp.clear(); flow.clear(); mode.clear(); clientFingerprint.clear(); user.clear(); ip_version.clear(); ip.clear(); ipv6.clear(); private_key.clear(); public_key.clear(); mtu.clear(); ports.clear(); obfs_protocol.clear(); up.clear(); up_speed.clear(); down.clear(); down_speed.clear(); auth.clear(); auth_str.clear(); fingerprint.clear(); ca.clear(); ca_str.clear(); recv_window_conn.clear(); recv_window.clear(); disable_mtu_discovery.clear(); hop_interval.clear(); alpn.clear(); obfs_password.clear(); cwnd.clear(); ech_enable.clear(); ech_config.clear(); initial_stream_receive_window.clear(); max_stream_receive_window.clear(); initial_connection_receive_window.clear(); max_connection_receive_window.clear(); uuid.clear(); heartbeat_interval.clear(); disable_sni.clear(); reduce_rtt.clear(); request_timeout.clear(); udp_relay_mode.clear(); congestion_controller.clear(); max_udp_relay_packet_size.clear(); max_open_streams.clear(); fast_open.clear(); version.clear(); idle_session_check_interval.clear(); idle_session_timeout.clear(); min_idle_session.clear(); multiplexing.clear(); transfer_protocol.clear(); sid.clear(); packet_encoding.clear(); dns_server.clear(); udp = tribool(); tfo = tribool(); scv = tribool(); udp_over_tcp = tribool(); v2ray_http_upgrade = tribool(); v2ray_http_upgrade_fast_open = tribool(); vless_udp = tribool(); encryption.clear(); alpnList.clear();

    for(uint32_t i = 0; i < yamlnode[section].size(); i++)
    {
        Proxy node;
        RESET_VARS(); // Reset all variables to prevent cross-node contamination
        
        singleproxy = yamlnode[section][i];
        singleproxy["type"] >>= proxytype;
        singleproxy["name"] >>= ps;
        singleproxy["server"] >>= server;
        singleproxy["port"] >>= port;
        // Use 'dialer-proxy' or 'underlying-proxy' to set underlying proxy
        if(singleproxy["dialer-proxy"].IsDefined())
            singleproxy["dialer-proxy"] >>= underlying_proxy;
        else if(singleproxy["underlying-proxy"].IsDefined())
            singleproxy["underlying-proxy"] >>= underlying_proxy;
        singleproxy["port-range"] >>= ports;
        if(port.empty() || port == "0")
            if(ports.empty())
                continue;
        udp = safe_as<std::string>(singleproxy["udp"]);
        tfo = safe_as<std::string>(singleproxy["fast-open"]);
        if(singleproxy["skip-cert-verify"].IsDefined())
            scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
        switch(hash_(proxytype))
        {
        case "vmess"_hash:
            group = V2RAY_DEFAULT_GROUP;

            singleproxy["uuid"] >>= id;
            if(id.length() < 36)
                break;
            singleproxy["alterId"] >>= aid;
            singleproxy["cipher"] >>= cipher;
            net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
            singleproxy["servername"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            singleproxy["client-fingerprint"] >>= fp;
            switch(hash_(net))
            {
            case "http"_hash:
                singleproxy["http-opts"]["path"][0] >>= path;
                singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                edge.clear();
                break;
            case "ws"_hash:
                if(singleproxy["ws-opts"].IsDefined())
                {
                    path = singleproxy["ws-opts"]["path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-opts"]["path"]) : "/";
                    // 提取 headers
                    if(singleproxy["ws-opts"]["headers"].IsDefined())
                    {
                        auto headers = singleproxy["ws-opts"]["headers"];
                        headers["Host"] >>= host;
                        headers["Edge"] >>= edge;
                        // 提取 v2ray-http-upgrade
                        if(headers["v2ray-http-upgrade"].IsDefined())
                        {
                            v2ray_http_upgrade = safe_as<bool>(headers["v2ray-http-upgrade"]);
                            singleproxy["ws-opts"]["headers"].remove("v2ray-http-upgrade");
                        }
                        if(headers["v2ray-http-upgrade-fast-open"].IsDefined())
                        {
                            v2ray_http_upgrade_fast_open = safe_as<bool>(headers["v2ray-http-upgrade-fast-open"]);
                            singleproxy["ws-opts"]["headers"].remove("v2ray-http-upgrade-fast-open");
                        }
                    }
                    if(singleproxy["ws-opts"]["early-data-header-name"].IsDefined())
                        node.WsEarlyDataHeaderName = safe_as<std::string>(singleproxy["ws-opts"]["early-data-header-name"]);
                    if(singleproxy["ws-opts"]["max-early-data"].IsDefined())
                        node.WsMaxEarlyData = to_int(safe_as<std::string>(singleproxy["ws-opts"]["max-early-data"]), 0);
                    // 兼容 ws-opts 顶层
                    if(singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined())
                        v2ray_http_upgrade = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                    if(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"].IsDefined())
                        v2ray_http_upgrade_fast_open = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"]);
                }
                else
                {
                    path = singleproxy["ws-path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-path"]) : "/";
                    singleproxy["ws-headers"]["Host"] >>= host;
                    singleproxy["ws-headers"]["Edge"] >>= edge;
                }
                break;
            case "h2"_hash:
                singleproxy["h2-opts"]["path"] >>= path;
                if(singleproxy["h2-opts"]["host"].IsDefined() && singleproxy["h2-opts"]["host"].size() > 0)
                    singleproxy["h2-opts"]["host"][0] >>= host;
                edge.clear();
                if(singleproxy["ech-opts"].IsDefined())
                {
                    if(singleproxy["ech-opts"]["enable"].IsDefined())
                        node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                    if(singleproxy["ech-opts"]["config"].IsDefined())
                        node.EchConfig = safe_as<std::string>(singleproxy["ech-opts"]["config"]);
                }
                break;
            case "grpc"_hash:
                singleproxy["servername"] >>= host;
                singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                edge.clear();
                if(singleproxy["ech-opts"].IsDefined())
                {
                    if(singleproxy["ech-opts"]["enable"].IsDefined())
                        node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                    if(singleproxy["ech-opts"]["config"].IsDefined())
                        node.EchConfig = safe_as<std::string>(singleproxy["ech-opts"]["config"]);
                }
                break;
            }
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    node.EchConfig = safe_as<std::string>(singleproxy["ech-opts"]["config"]);
            }
            tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
            singleproxy["alpn"] >>= alpnList;

            vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, alpnList, udp, tfo, scv, tribool(), underlying_proxy, "", "", v2ray_http_upgrade, v2ray_http_upgrade_fast_open);
            break;
        case "ss"_hash:
            group = SS_DEFAULT_GROUP;

            singleproxy["cipher"] >>= cipher;
            singleproxy["password"] >>= password;
            if(singleproxy["plugin"].IsDefined())
            {
                switch(hash_(safe_as<std::string>(singleproxy["plugin"])))
                {
                case "obfs"_hash:
                    plugin = "obfs-local";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                        singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                    }
                    break;
                case "v2ray-plugin"_hash:
                    plugin = "v2ray-plugin";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                        singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                        tls = safe_as<bool>(singleproxy["plugin-opts"]["tls"]) ? "tls;" : "";
                        singleproxy["plugin-opts"]["path"] >>= path;
                        pluginopts_mux = safe_as<bool>(singleproxy["plugin-opts"]["mux"]) ? "mux=4;" : "";
                        // Extended v2ray-plugin options (Meta only)
                        std::string fingerprint, server_name;
                        tribool v2ray_http_upgrade, v2ray_http_upgrade_fast_open, skip_cert_verify;
                        if(singleproxy["plugin-opts"]["fingerprint"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["fingerprint"] >>= fingerprint;
                            if(!fingerprint.empty())
                                pluginopts += "fingerprint=" + fingerprint + ";";
                        }
                        if(singleproxy["plugin-opts"]["server_name"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["server_name"] >>= server_name;
                            if(!server_name.empty())
                                pluginopts += "server_name=" + server_name + ";";
                        }
                        if(singleproxy["plugin-opts"]["v2ray-http-upgrade"].IsDefined())
                        {
                            v2ray_http_upgrade = safe_as<bool>(singleproxy["plugin-opts"]["v2ray-http-upgrade"]);
                            node.V2rayHttpUpgrade = v2ray_http_upgrade;
                            pluginopts += "v2ray-http-upgrade=" + std::string(v2ray_http_upgrade ? "true" : "false") + ";";
                        }
                        if(singleproxy["plugin-opts"]["v2ray-http-upgrade-fast-open"].IsDefined())
                        {
                            v2ray_http_upgrade_fast_open = safe_as<bool>(singleproxy["plugin-opts"]["v2ray-http-upgrade-fast-open"]);
                            node.V2rayHttpUpgradeFastOpen = v2ray_http_upgrade_fast_open;
                            pluginopts += "v2ray-http-upgrade-fast-open=" + std::string(v2ray_http_upgrade_fast_open ? "true" : "false") + ";";
                        }
                        if(singleproxy["plugin-opts"]["skip-cert-verify"].IsDefined())
                        {
                            skip_cert_verify = safe_as<bool>(singleproxy["plugin-opts"]["skip-cert-verify"]);
                            pluginopts += "skip-cert-verify=" + std::string(skip_cert_verify ? "true" : "false") + ";";
                        }
                        if(singleproxy["plugin-opts"]["headers"].IsDefined() && singleproxy["plugin-opts"]["headers"].IsMap())
                        {
                            std::string headers_str;
                            for(const auto& header : singleproxy["plugin-opts"]["headers"])
                            {
                                if(!headers_str.empty()) headers_str += ";";
                                headers_str += safe_as<std::string>(header.first) + "=" + safe_as<std::string>(header.second);
                            }
                            if(!headers_str.empty())
                                pluginopts += "headers=" + headers_str + ";";
                        }
                        if(singleproxy["plugin-opts"]["ech-opts"].IsDefined())
                        {
                            if(singleproxy["plugin-opts"]["ech-opts"]["enable"].IsDefined())
                            {
                                bool enable = safe_as<bool>(singleproxy["plugin-opts"]["ech-opts"]["enable"]);
                                node.EchEnable = enable;
                                pluginopts += "ech=" + std::string(enable ? "true" : "false") + ";";
                            }
                            if(singleproxy["plugin-opts"]["ech-opts"]["config"].IsDefined())
                            {
                                std::string config = safe_as<std::string>(singleproxy["plugin-opts"]["ech-opts"]["config"]);
                                node.EchConfig = config;
                                pluginopts += "ech-config=" + config + ";";
                            }
                        }
                    }
                    break;
                case "shadow-tls"_hash:
                    plugin = "shadow-tls";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                        singleproxy["plugin-opts"]["password"] >>= pluginopts_password;
                        singleproxy["plugin-opts"]["version"] >>= pluginopts_version;
                        if(singleproxy["plugin-opts"]["alpn"].IsDefined() && singleproxy["plugin-opts"]["alpn"].IsSequence())
                        {
                            std::string alpn_str;
                            for(std::size_t i = 0; i < singleproxy["plugin-opts"]["alpn"].size(); ++i)
                            {
                                if(i > 0) alpn_str += ",";
                                alpn_str += safe_as<std::string>(singleproxy["plugin-opts"]["alpn"][i]);
                            }
                            if(!alpn_str.empty())
                                pluginopts += "alpn=" + alpn_str + ";";
                        }
                        else if(singleproxy["plugin-opts"]["alpn"].IsDefined())
                        {
                            std::string alpn = safe_as<std::string>(singleproxy["plugin-opts"]["alpn"]);
                            pluginopts += "alpn=" + alpn + ";";
                        }
                    }
                    break;
                case "gost-plugin"_hash:
                    plugin = "gost-plugin";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                        singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                        tls = safe_as<bool>(singleproxy["plugin-opts"]["tls"]) ? "tls;" : "";
                        singleproxy["plugin-opts"]["path"] >>= path;
                        pluginopts_mux = safe_as<bool>(singleproxy["plugin-opts"]["mux"]) ? "mux=4;" : "";
                        std::string fingerprint, server_name;
                        tribool skip_cert_verify;
                        if(singleproxy["plugin-opts"]["fingerprint"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["fingerprint"] >>= fingerprint;
                            if(!fingerprint.empty())
                                pluginopts += "fingerprint=" + fingerprint + ";";
                        }
                        if(singleproxy["plugin-opts"]["server_name"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["server_name"] >>= server_name;
                            if(!server_name.empty())
                                pluginopts += "server_name=" + server_name + ";";
                        }
                        if(singleproxy["plugin-opts"]["skip-cert-verify"].IsDefined())
                        {
                            skip_cert_verify = safe_as<bool>(singleproxy["plugin-opts"]["skip-cert-verify"]);
                            pluginopts += "skip-cert-verify=" + std::string(skip_cert_verify ? "true" : "false") + ";";
                        }
                        if(singleproxy["plugin-opts"]["headers"].IsDefined() && singleproxy["plugin-opts"]["headers"].IsMap())
                        {
                            std::string headers_str;
                            for(const auto& header : singleproxy["plugin-opts"]["headers"])
                            {
                                if(!headers_str.empty()) headers_str += ";";
                                headers_str += safe_as<std::string>(header.first) + "=" + safe_as<std::string>(header.second);
                            }
                            if(!headers_str.empty())
                                pluginopts += "headers=" + headers_str + ";";
                        }
                    }
                    break;
                case "restls"_hash:
                    plugin = "restls";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        if(singleproxy["plugin-opts"]["host"].IsDefined() && !singleproxy["plugin-opts"]["host"].IsMap())
                            singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                        singleproxy["plugin-opts"]["password"] >>= pluginopts_password;
                        std::string version_hint, restls_script;
                        if(singleproxy["plugin-opts"]["version-hint"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["version-hint"] >>= version_hint;
                            pluginopts += "version-hint=" + version_hint + ";";
                        }
                        if(singleproxy["plugin-opts"]["restls-script"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["restls-script"] >>= restls_script;
                            pluginopts += "restls-script=" + restls_script + ";";
                        }
                    }
                    break;
                default:
                    break;
                }
            }
            else if(singleproxy["obfs"].IsDefined())
            {
                plugin = "obfs-local";
                singleproxy["obfs"] >>= pluginopts_mode;
                singleproxy["obfs-host"] >>= pluginopts_host;
            }
            else
                plugin.clear();

            switch(hash_(plugin))
            {
            case "simple-obfs"_hash:
            case "obfs-local"_hash:
                pluginopts = "obfs=" + pluginopts_mode;
                pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                break;
            case "v2ray-plugin"_hash:
                pluginopts = "mode=" + pluginopts_mode + ";" + tls + pluginopts_mux;
                if(!pluginopts_host.empty())
                    pluginopts += "host=" + pluginopts_host + ";";
                if(!path.empty())
                    pluginopts += "path=" + path + ";";
                break;
            case "shadow-tls"_hash:
                if(!pluginopts_host.empty())
                    pluginopts += "host=" + pluginopts_host + ";";
                if(!pluginopts_password.empty())
                    pluginopts += "password=" + pluginopts_password + ";";
                if(!pluginopts_version.empty())
                    pluginopts += "version=" + pluginopts_version + ";";
                break;
            case "gost-plugin"_hash:
                pluginopts = "mode=" + pluginopts_mode + ";" + tls + pluginopts_mux;
                if(!pluginopts_host.empty())
                    pluginopts += "host=" + pluginopts_host + ";";
                if(!path.empty())
                    pluginopts += "path=" + path + ";";
                break;
            case "restls"_hash:
                if(!pluginopts_host.empty())
                    pluginopts += "host=" + pluginopts_host + ";";
                if(!pluginopts_password.empty())
                    pluginopts += "password=" + pluginopts_password + ";";
                break;
            }

            //support for go-shadowsocks2
            if(cipher == "AEAD_CHACHA20_POLY1305")
                cipher = "chacha20-ietf-poly1305";
            else if(strFind(cipher, "AEAD"))
            {
                cipher = replaceAllDistinct(replaceAllDistinct(cipher, "AEAD_", ""), "_", "-");
                std::transform(cipher.begin(), cipher.end(), cipher.begin(), ::tolower);
            }

            if(singleproxy["udp-over-tcp"].IsDefined())
                udp_over_tcp = safe_as<bool>(singleproxy["udp-over-tcp"]);
            if(singleproxy["smux"].IsDefined())
            {
                if(singleproxy["smux"]["enabled"].IsDefined())
                    node.SmuxEnabled = safe_as<bool>(singleproxy["smux"]["enabled"]);
                if(singleproxy["smux"]["max-connections"].IsDefined())
                    node.SmuxMaxConnections = safe_as<int>(singleproxy["smux"]["max-connections"]);
                if(singleproxy["smux"]["min-streams"].IsDefined())
                    node.SmuxMinStreams = safe_as<int>(singleproxy["smux"]["min-streams"]);
                if(singleproxy["smux"]["max-streams"].IsDefined())
                    node.SmuxMaxStreams = safe_as<int>(singleproxy["smux"]["max-streams"]);
                if(singleproxy["smux"]["padding"].IsDefined())
                    node.SmuxPadding = safe_as<bool>(singleproxy["smux"]["padding"]);
                if(singleproxy["smux"]["statistic"].IsDefined())
                    node.SmuxStatistic = safe_as<bool>(singleproxy["smux"]["statistic"]);
                if(singleproxy["smux"]["only-tcp"].IsDefined())
                    node.SmuxOnlyTcp = safe_as<bool>(singleproxy["smux"]["only-tcp"]);
            }
            if(singleproxy["ip-version"].IsDefined())
                singleproxy["ip-version"] >>= ip_version;

            ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv, udp_over_tcp, underlying_proxy);
            node.IPVersion = ip_version;
            break;
        case "socks5"_hash:
            group = SOCKS_DEFAULT_GROUP;

            singleproxy["username"] >>= user;
            singleproxy["password"] >>= password;
            if(singleproxy["tls"].IsDefined())
                singleproxy["tls"] >>= tls;
            if(singleproxy["udp"].IsDefined())
                udp = safe_as<bool>(singleproxy["udp"]);
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
            if(singleproxy["fingerprint"].IsDefined())
                singleproxy["fingerprint"] >>= fingerprint;
            if(singleproxy["ip-version"].IsDefined())
                singleproxy["ip-version"] >>= ip_version;

            socksConstruct(node, group, ps, server, port, user, password, udp, tfo, scv, underlying_proxy);
            node.TLSSecure = tls == "true";
            node.Fingerprint = fingerprint;
            node.IPVersion = ip_version;
            break;
        case "ssr"_hash:
            group = SSR_DEFAULT_GROUP;

            singleproxy["cipher"] >>= cipher;
            if(cipher == "dummy") cipher = "none";
            singleproxy["password"] >>= password;
            singleproxy["protocol"] >>= protocol;
            singleproxy["obfs"] >>= obfs;
            if(singleproxy["protocol-param"].IsDefined())
                singleproxy["protocol-param"] >>= protoparam;
            else
                singleproxy["protocolparam"] >>= protoparam;
            if(singleproxy["obfs-param"].IsDefined())
                singleproxy["obfs-param"] >>= obfsparam;
            else
                singleproxy["obfsparam"] >>= obfsparam;

            ssrConstruct(node, group, ps, server, port, protocol, cipher, obfs, password, obfsparam, protoparam, udp, tfo, scv, underlying_proxy);
            break;
        case "http"_hash:
            group = HTTP_DEFAULT_GROUP;

            singleproxy["username"] >>= user;
            singleproxy["password"] >>= password;
            singleproxy["tls"] >>= tls;
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
            if(singleproxy["sni"].IsDefined())
                singleproxy["sni"] >>= sni;
            if(singleproxy["fingerprint"].IsDefined())
                singleproxy["fingerprint"] >>= fingerprint;
            if(singleproxy["ip-version"].IsDefined())
                singleproxy["ip-version"] >>= ip_version;

            httpConstruct(node, group, ps, server, port, user, password, tls == "true", tfo, scv, tribool(), underlying_proxy);
            node.ServerName = sni;
            node.Fingerprint = fingerprint;
            node.IPVersion = ip_version;
            break;
        case "trojan"_hash:
            group = TROJAN_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= sni;
            singleproxy["network"] >>= net;
            switch(hash_(net))
            {
            case "grpc"_hash:
                singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                break;
            case "ws"_hash:
                if(singleproxy["ws-opts"].IsDefined())
                {
                    path = singleproxy["ws-opts"]["path"].IsDefined() ? safe_as<std::string>( singleproxy["ws-opts"]["path"]) : "/";
                    if(singleproxy["ws-opts"]["headers"].IsDefined())
                    {
                        auto headers = singleproxy["ws-opts"]["headers"];
                        if(headers["Host"].IsDefined())
                            headers["Host"] >>= host;
                        if(headers["Edge"].IsDefined())
                            headers["Edge"] >>= edge;
                        // 提取 v2ray-http-upgrade
                        if(headers["v2ray-http-upgrade"].IsDefined())
                        {
                            v2ray_http_upgrade = safe_as<bool>(headers["v2ray-http-upgrade"]);
                            singleproxy["ws-opts"]["headers"].remove("v2ray-http-upgrade");
                        }
                        if(headers["v2ray-http-upgrade-fast-open"].IsDefined())
                        {
                            v2ray_http_upgrade_fast_open = safe_as<bool>(headers["v2ray-http-upgrade-fast-open"]);
                            singleproxy["ws-opts"]["headers"].remove("v2ray-http-upgrade-fast-open");
                        }
                    }
                    // capture v2ray upgrade flags if present (兼容 ws-opts 顶层)
                    if(singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined())
                        v2ray_http_upgrade = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                    if(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"].IsDefined())
                        v2ray_http_upgrade_fast_open = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"]);
                    // 解析 early-data 字段
                    if(singleproxy["ws-opts"]["early-data-header-name"].IsDefined())
                        node.WsEarlyDataHeaderName = safe_as<std::string>(singleproxy["ws-opts"]["early-data-header-name"]);
                    if(singleproxy["ws-opts"]["max-early-data"].IsDefined())
                        node.WsMaxEarlyData = to_int(safe_as<std::string>(singleproxy["ws-opts"]["max-early-data"]), 0);
                }
                break;
            default:
                net = "tcp";
                path.clear();
                host.clear();
                break;
            }
            singleproxy["alpn"] >>= alpnList;
            if(singleproxy["client-fingerprint"].IsDefined())
                singleproxy["client-fingerprint"] >>= fp;
            
            trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList, true, udp, tfo, scv, tribool(), underlying_proxy, v2ray_http_upgrade, v2ray_http_upgrade_fast_open);
            break;
        case "snell"_hash:
            group = SNELL_DEFAULT_GROUP;
            singleproxy["psk"] >>= password;
            singleproxy["obfs"] >>= obfs;
            singleproxy["host"] >>= host;
            singleproxy["version"] >>= aid;

            snellConstruct(node, group, ps, server, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv, underlying_proxy);
            break;
        case "wireguard"_hash:
            group = WG_DEFAULT_GROUP;

            singleproxy["public-key"] >>= public_key;
            singleproxy["private-key"] >>= private_key;
            singleproxy["dns"] >>= dns_server;
            singleproxy["mtu"] >>= mtu;
            singleproxy["preshared-key"] >>= password;
            singleproxy["ip"] >>= ip;
            singleproxy["ipv6"] >>= ipv6;

            wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password, dns_server, mtu, "0", "", "", udp, underlying_proxy);
            break;
        case "hysteria"_hash:
            group = HYSTERIA_DEFAULT_GROUP;

            singleproxy["ports"] >>= ports;
            singleproxy["protocol"] >>= protocol;
            singleproxy["obfs-protocol"] >>= obfs_protocol;
            singleproxy["up"] >>= up;
            singleproxy["up-speed"] >>= up_speed;
            singleproxy["down"] >>= down;
            singleproxy["down-speed"] >>= down_speed;
            singleproxy["auth"] >>= auth;
            singleproxy["auth-str"] >>= auth_str;
            singleproxy["obfs"] >>= obfs;
            singleproxy["sni"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            singleproxy["alpn"] >>= alpnList;
            singleproxy["ca"] >>= ca;
            singleproxy["ca-str"] >>= ca_str;
            singleproxy["recv-window-conn"] >>= recv_window_conn;
            singleproxy["recv-window"] >>= recv_window;
            singleproxy["disable-mtu-discovery"] >>= disable_mtu_discovery;
            singleproxy["hop-interval"] >>= hop_interval;

            hysteriaConstruct(node, group, ps, server, port, ports, protocol, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, obfs, sni, fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpnList, "", tfo, scv, underlying_proxy);
            break;
        case "hysteria2"_hash:
            group = HYSTERIA2_DEFAULT_GROUP;
            singleproxy["ports"] >>= ports;
            singleproxy["up"] >>= up;
            singleproxy["down"] >>= down;
            singleproxy["password"] >>= password;
            if (password.empty())
                singleproxy["auth"] >>= password;
            singleproxy["auth"] >>= auth;
            singleproxy["obfs"] >>= obfs;
            singleproxy["obfs-password"] >>= obfs_password;
            singleproxy["sni"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            singleproxy["ca"] >>= ca;
            singleproxy["ca-str"] >>= ca_str;
            singleproxy["cwnd"] >>= cwnd;
            singleproxy["hop-interval"] >>= hop_interval;
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    ech_enable = safe_as<std::string>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= ech_config;
            }
            singleproxy["initial-stream-receive-window"] >>= initial_stream_receive_window;
            singleproxy["max-stream-receive-window"] >>= max_stream_receive_window;
            singleproxy["initial-connection-receive-window"] >>= initial_connection_receive_window;
            singleproxy["max-connection-receive-window"] >>= max_connection_receive_window;
            if(singleproxy["udp"].IsDefined())
                udp = safe_as<bool>(singleproxy["udp"]);
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);

            hysteria2Construct(node, group, ps, server, port, ports, up, down, password, auth, obfs, obfs_password, sni, fingerprint, alpn, ca, ca_str, cwnd, hop_interval, ech_enable, ech_config, initial_stream_receive_window, max_stream_receive_window, initial_connection_receive_window, max_connection_receive_window, udp, tfo, scv, underlying_proxy);
            break;
        case "vless"_hash:
            vless_udp = tribool();
            group = VLESS_DEFAULT_GROUP;
            singleproxy["uuid"] >>= id;
            singleproxy["alterId"] >>= aid;
            sni = singleproxy["sni"].IsDefined() ? safe_as<std::string>(singleproxy["sni"]) : safe_as<std::string>(singleproxy["servername"]);
            net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
            singleproxy["alpn"] >>= alpnList;
            singleproxy["client-fingerprint"] >>= fp;
            singleproxy["flow"] >>= flow;
            switch(hash_(net))
            {
                case "tcp"_hash:
                case "http"_hash:
                    if(singleproxy["http-opts"].IsDefined())
                    {
                        if(singleproxy["http-opts"]["path"].IsSequence() && singleproxy["http-opts"]["path"].size() > 0)
                            singleproxy["http-opts"]["path"][0] >>= path;
                        if(singleproxy["http-opts"]["headers"].IsDefined() && singleproxy["http-opts"]["headers"]["Host"].IsSequence() && singleproxy["http-opts"]["headers"]["Host"].size() > 0)
                            singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                    }
                    edge.clear();
                    break;
                case "ws"_hash:
                    if(singleproxy["ws-opts"].IsDefined())
                    {
                        path = singleproxy["ws-opts"]["path"].IsDefined() ? safe_as<std::string>( singleproxy["ws-opts"]["path"]) : "/";
                        if(singleproxy["ws-opts"]["headers"].IsDefined())
                        {
                            auto headers = singleproxy["ws-opts"]["headers"];
                            if(headers["Host"].IsDefined())
                                headers["Host"] >>= host;
                            if(headers["Edge"].IsDefined())
                                headers["Edge"] >>= edge;
                            // 提取 v2ray-http-upgrade
                            if(headers["v2ray-http-upgrade"].IsDefined())
                            {
                                v2ray_http_upgrade = safe_as<bool>(headers["v2ray-http-upgrade"]);
                                singleproxy["ws-opts"]["headers"].remove("v2ray-http-upgrade");
                            }
                            if(headers["v2ray-http-upgrade-fast-open"].IsDefined())
                            {
                                v2ray_http_upgrade_fast_open = safe_as<bool>(headers["v2ray-http-upgrade-fast-open"]);
                                singleproxy["ws-opts"]["headers"].remove("v2ray-http-upgrade-fast-open");
                            }
                        }
                        if(singleproxy["ws-opts"]["early-data-header-name"].IsDefined())
                            node.WsEarlyDataHeaderName = safe_as<std::string>(singleproxy["ws-opts"]["early-data-header-name"]);
                        if(singleproxy["ws-opts"]["max-early-data"].IsDefined())
                            node.WsMaxEarlyData = to_int(safe_as<std::string>(singleproxy["ws-opts"]["max-early-data"]), 0);
                        // 兼容 ws-opts 顶层
                        if(singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined())
                            v2ray_http_upgrade = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                        if(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"].IsDefined())
                            v2ray_http_upgrade_fast_open = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"]);
                    }
                    else{
                        path = singleproxy["ws-path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-path"]) : "/";
                        if(singleproxy["ws-headers"].IsDefined() && singleproxy["ws-headers"]["Host"].IsDefined())
                            singleproxy["ws-headers"]["Host"] >>= host;
                        if(singleproxy["ws-headers"].IsDefined() && singleproxy["ws-headers"]["Edge"].IsDefined())
                            singleproxy["ws-headers"]["Edge"] >>= edge;
                    }
                    break;
                case "h2"_hash:
                    singleproxy["h2-opts"]["path"] >>= path;
                    if(singleproxy["h2-opts"]["host"].IsSequence() && singleproxy["h2-opts"]["host"].size() > 0)
                        singleproxy["h2-opts"]["host"][0] >>= host;
                    edge.clear();
                    break;
                case "grpc"_hash:
                    singleproxy["servername"] >>= host;
                    if(singleproxy["grpc-opts"].IsDefined())
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                    else if(singleproxy["grpc-service-name"].IsDefined())
                        singleproxy["grpc-service-name"] >>= path;
                    if(!path.empty())
                        node.GrpcServiceName = path;
                    singleproxy["grpc-opts"]["grpc-mode"] >>= mode;
                    edge.clear();
                    break;
                case "quic"_hash:
                    singleproxy["quic-opts"]["security"] >>= host;
                    singleproxy["quic-opts"]["key"] >>= path;
                    break;
                default:
                    continue;
            }
            tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
            if(singleproxy["reality-opts"].IsDefined())
            {
                if(singleproxy["reality-opts"]["servername"].IsDefined())
                {
                    singleproxy["reality-opts"]["servername"] >>= host;
                    sni = host;
                }
                else
                {
                    host = singleproxy["sni"].IsDefined() ? safe_as<std::string>(singleproxy["sni"]) : safe_as<std::string>(singleproxy["servername"]);
                }
                singleproxy["reality-opts"]["public-key"] >>= public_key;
                singleproxy["reality-opts"]["short-id"] >>= sid;
            }
            singleproxy["packet-encoding"] >>= packet_encoding;
            if(singleproxy["udp"].IsDefined())
                vless_udp = safe_as<bool>(singleproxy["udp"]);
            if(singleproxy["tfo"].IsDefined())
                tfo = safe_as<std::string>(singleproxy["tfo"]);
            // v2ray_http_upgrade and v2ray_http_upgrade_fast_open are already tribool values when parsed above
            // Read actual encryption value from config (default to "none" for VLESS)
            encryption = "none";
            singleproxy["encryption"] >>= encryption;
            vlessConstruct(node, VLESS_DEFAULT_GROUP, ps, server, port, type, id, aid, net, encryption, flow, mode, path, host, "", tls, public_key, sid, fp, sni, alpnList, packet_encoding, vless_udp, tfo, scv, tribool(), "", v2ray_http_upgrade, v2ray_http_upgrade_fast_open);
            break;
        case "tuic"_hash:
            group = TUIC_DEFAULT_GROUP;
            singleproxy["uuid"] >>= uuid;
            singleproxy["ip"] >>= ip;
            singleproxy["password"] >>= password;
            singleproxy["heartbeat_interval"] >>= heartbeat_interval;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            // capture SNI (prefer explicit sni, fallback to servername if providers use that key)
            if(singleproxy["sni"].IsDefined())
                singleproxy["sni"] >>= sni;
            else if(singleproxy["servername"].IsDefined())
                singleproxy["servername"] >>= sni;
            singleproxy["disable-sni"] >>= disable_sni;
            singleproxy["reduce-rtt"] >>= reduce_rtt;
            singleproxy["request-timeout"] >>= request_timeout;
            singleproxy["udp-relay-mode"] >>= udp_relay_mode;
            singleproxy["congestion-controller"] >>= congestion_controller;
            singleproxy["max-udp-relay-packet-size"] >>= max_udp_relay_packet_size;
            singleproxy["max-open-streams"] >>= max_open_streams;
            singleproxy["fast-open"] >>= fast_open;
            singleproxy["version"] >>= version;
            TUICConstruct(node, group, ps, server, port, uuid, password, ip, heartbeat_interval, alpn, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, sni, fast_open, version, tfo, scv, underlying_proxy);
            break;
        case "anytls"_hash:
            group = ANYTLS_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= sni;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            singleproxy["fingerprint"] >>= fingerprint;
            anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, server, port, password, sni, alpn, fingerprint, idle_session_check_interval, idle_session_timeout, min_idle_session, tfo, scv, underlying_proxy);
            break;
        case "mieru"_hash:
            group = MIERU_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["username"] >>= user;
            singleproxy["port-range"] >>= ports;
            if(!singleproxy["multiplexing"].IsNull())
                singleproxy["multiplexing"] >>= multiplexing;
            transfer_protocol = "TCP";
            if(!singleproxy["transport"].IsNull())
                singleproxy["transport"] >>= transfer_protocol;
            mieruConstruct(node, MIERU_DEFAULT_GROUP, ps, port, password, server, ports, user, multiplexing, transfer_protocol, udp, tribool(), scv, tribool(), "");
            break;
        default:
            continue;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
    #undef RESET_VARS
}

void explodeStdVMess(std::string vmess, Proxy &node)
{
    std::string add, port, type, id, aid, net, path, host, tls, remarks;
    std::string addition;
    vmess = vmess.substr(8);
    string_size pos;

    pos = vmess.rfind('#');
    if(pos != std::string::npos)
    {
        remarks = urlDecode(vmess.substr(pos + 1));
        vmess.erase(pos);
    }
    const std::string stdvmess_matcher = R"(^([a-z]+)(?:\+([a-z]+))?:([\da-f]{4}(?:[\da-f]{4}-){4}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?\?(.*))?$)";
    if(regGetMatch(vmess, stdvmess_matcher, 8, 0, &net, &tls, &id, &aid, &add, &port, &addition))
        return;

    switch(hash_(net))
    {
    case "tcp"_hash:
    case "kcp"_hash:
        type = getUrlArg(addition, "type");
        break;
    case "http"_hash:
    case "ws"_hash:
        host = getUrlArg(addition, "host");
        path = getUrlArg(addition, "path");
        break;
    case "quic"_hash:
        type = getUrlArg(addition, "security");
        host = getUrlArg(addition, "type");
        path = getUrlArg(addition, "key");
        break;
    default:
        return;
    }

    if(remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
    {
        alpnList.push_back(alpn);
    }

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", path, host, "", tls, "", alpnList);
}

void explodeShadowrocket(std::string rocket, Proxy &node)
{
    std::string add, port, type, id, aid, net = "tcp", path, host, tls, cipher, remarks;
    std::string obfs; //for other style of link
    std::string addition;
    rocket = rocket.substr(8);

    string_size pos = rocket.find('?');
    addition = rocket.substr(pos + 1);
    rocket.erase(pos);

    if(regGetMatch(urlSafeBase64Decode(rocket), "(.*?):(.*)@(.*):(.*)", 5, 0, &cipher, &id, &add, &port))
        return;
    if(port == "0")
        return;
    remarks = urlDecode(getUrlArg(addition, "remarks"));
    obfs = getUrlArg(addition, "obfs");
    if(!obfs.empty())
    {
        if(obfs == "websocket")
        {
            net = "ws";
            host = getUrlArg(addition, "obfsParam");
            path = getUrlArg(addition, "path");
        }
    }
    else
    {
        net = getUrlArg(addition, "network");
        host = getUrlArg(addition, "wsHost");
        path = getUrlArg(addition, "wspath");
    }
    tls = getUrlArg(addition, "tls") == "1" ? "tls" : "";
    aid = getUrlArg(addition, "aid");

    if(aid.empty())
        aid = "0";

    if(remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
    {
        alpnList.push_back(alpn);
    }

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "", alpnList);
}

void explodeKitsunebi(std::string kit, Proxy &node)
{
    std::string add, port, type, id, aid = "0", net = "tcp", path, host, tls, cipher = "auto", remarks;
    std::string addition;
    string_size pos;
    kit = kit.substr(9);

    pos = kit.find('#');
    if(pos != std::string::npos)
    {
        remarks = kit.substr(pos + 1);
        kit = kit.substr(0, pos);
    }

    pos = kit.find('?');
    addition = kit.substr(pos + 1);
    kit = kit.substr(0, pos);

    if(regGetMatch(kit, "(.*?)@(.*):(.*)", 4, 0, &id, &add, &port))
        return;
    pos = port.find('/');
    if(pos != std::string::npos)
    {
        path = port.substr(pos);
        port.erase(pos);
    }
    if(port == "0")
        return;
    net = getUrlArg(addition, "network");
    tls = getUrlArg(addition, "tls") == "true" ? "tls" : "";
    host = getUrlArg(addition, "ws.host");

    if(remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
    {
        alpnList.push_back(alpn);
    }

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "", alpnList);
}

void explodeStdHysteria2(std::string hysteria2, Proxy &node) {
    std::string add, port, ports, password, host, insecure, up, down, alpn, obfs, obfs_password, remarks, sni, fingerprint;
    std::string ca, ca_str, cwnd, hop_interval;
    std::string ech_enable, ech_config, initial_stream_receive_window, max_stream_receive_window;
    std::string initial_connection_receive_window, max_connection_receive_window;
    std::string addition;
    tribool scv, udp;
    hysteria2 = hysteria2.substr(12);
    string_size pos;

    pos = hysteria2.rfind("#");
    if (pos != hysteria2.npos) {
        remarks = urlDecode(hysteria2.substr(pos + 1));
        hysteria2.erase(pos);
    }

    pos = hysteria2.rfind("?");
    if (pos != hysteria2.npos) {
        addition = hysteria2.substr(pos + 1);
        hysteria2.erase(pos);
    }

    if (strFind(hysteria2, "@")) {
        if (regGetMatch(hysteria2, R"(^(.*?)@(.*)[:](\d+)$)", 4, 0, &password, &add, &port))
            return;
    } else {
        password = getUrlArg(addition, "password");
        if (password.empty())
            return;

        if (!strFind(hysteria2, ":"))
            return;

        if (regGetMatch(hysteria2, R"(^(.*)[:](\d+)$)", 3, 0, &add, &port))
            return;
    }

    scv = getUrlArg(addition, "insecure");
    up = getUrlArg(addition, "up");
    down = getUrlArg(addition, "down");
    alpn = getUrlArg(addition, "alpn");
    obfs = getUrlArg(addition, "obfs");
    obfs_password = getUrlArg(addition, "obfs-password");
    sni = getUrlArg(addition, "sni");
    if(sni.empty())
    {
        sni = getUrlArg(addition, "peer");
    }
    fingerprint = getUrlArg(addition, "pinSHA256");
    if(fingerprint.empty())
    {
        fingerprint = getUrlArg(addition, "fingerprint");
    }
    ports = getUrlArg(addition, "ports");
    if(ports.empty())
    {
        ports = getUrlArg(addition, "mport");
    }
    ca = getUrlArg(addition, "ca");
    ca_str = getUrlArg(addition, "ca-str");
    cwnd = getUrlArg(addition, "cwnd");
    hop_interval = getUrlArg(addition, "hop-interval");
    ech_enable = getUrlArg(addition, "ech-enable");
    if(ech_enable.empty())
    {
        ech_enable = getUrlArg(addition, "ech");
    }
    ech_config = getUrlArg(addition, "ech-config");
    initial_stream_receive_window = getUrlArg(addition, "initial-stream-receive-window");
    max_stream_receive_window = getUrlArg(addition, "max-stream-receive-window");
    initial_connection_receive_window = getUrlArg(addition, "initial-connection-receive-window");
    max_connection_receive_window = getUrlArg(addition, "max-connection-receive-window");
    udp = getUrlArg(addition, "udp");
    if (remarks.empty())
        remarks = add + ":" + port;
    hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remarks, add, port, ports, up, down, password, "", obfs, obfs_password, sni, fingerprint, alpn, ca, ca_str, cwnd, hop_interval, ech_enable, ech_config, initial_stream_receive_window, max_stream_receive_window, initial_connection_receive_window, max_connection_receive_window, udp, scv, "");
    return;
}

void explodeHysteria2(std::string hysteria2, Proxy &node) {
    hysteria2 = regReplace(hysteria2, "(hysteria2|hy2)://", "hysteria2://");

    // replace /? with ?
    hysteria2 = regReplace(hysteria2, "/\\?", "?", true, false);
    if (regMatch(hysteria2, "hysteria2://(.*?)[:](.*)")) {
        explodeStdHysteria2(hysteria2, node);
        return;
    }
}

void explodeStdHysteria(std::string hysteria, Proxy &node)
{
    std::string add, port, remarks;
    std::string ports, protocol, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, obfs, sni, fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpn;
    std::vector<std::string> alpnList;
    std::string addition;
    hysteria = hysteria.substr(11);
    string_size pos;

    pos = hysteria.rfind("#");
    if(pos != hysteria.npos)
    {
        remarks = urlDecode(hysteria.substr(pos + 1));
        hysteria.erase(pos);
    }
    const std::string stdhysteria_matcher = R"(^(.*)[:](\d+)[?](.*)$)";
    if(regGetMatch(hysteria, stdhysteria_matcher, 4, 0, &add, &port, &addition))
        return;
    protocol = getUrlArg(addition, "protocol");
    obfs_protocol = getUrlArg(addition, "obfs-protocol");
    up = getUrlArg(addition, "upmbps");
    up_speed = getUrlArg(addition, "up-speed");
    down = getUrlArg(addition, "downmbps");
    down_speed = getUrlArg(addition, "down-speed");
    auth = getUrlArg(addition, "auth");
    auth_str = getUrlArg(addition, "auth_str");
    obfs = getUrlArg(addition, "obfs");
    sni = getUrlArg(addition, "peer");
    fingerprint = getUrlArg(addition, "fingerprint");
    // the alpn is not supported officially yet
    alpn = getUrlArg(addition, "alpn");
    ca = getUrlArg(addition, "ca");
    ca_str = getUrlArg(addition, "ca-str");
    recv_window_conn = getUrlArg(addition, "recv-window-conn");
    recv_window = getUrlArg(addition, "recv-window");
    disable_mtu_discovery = getUrlArg(addition, "disable-mtu-discovery");
    hop_interval = getUrlArg(addition, "hop-interval");

    tribool scv = getUrlArg(addition, "insecure");
    if(remarks.empty())
        remarks = add + ":" + port;

    hysteriaConstruct(node, HYSTERIA_DEFAULT_GROUP, remarks, add, port, ports, protocol, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, obfs, sni, fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpnList, alpn, tribool(), scv, "");
    return;
}

void explodeStdTUIC(std::string TUIC, Proxy &node)
{
    std::string add, port,uuid, ip, password, token, heartbeat_interval, disable_sni, reduce_rtt, request_timeout;
    std::string udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams;
    std::string alpn, sni, fast_open, remarks, addition;
    tribool tfo, scv;
    std::string tuic = TUIC;

    tuic = tuic.substr(7);
    string_size pos;

    pos = TUIC.rfind("#");
    if(pos != TUIC.npos)
    {
        remarks = urlDecode(TUIC.substr(pos + 1));
        TUIC.erase(pos);
    }
    pos = TUIC.rfind("?");
    if(pos != TUIC.npos)
    {
        addition = TUIC.substr(pos + 1);
        TUIC.erase(pos);
    }
    if(strFind(TUIC, "@"))
    {
        if(regGetMatch(TUIC, R"(^(.*?):(.*?)@(.*?):(\d+)$)", 5, 0, &uuid, &password, &add, &port))
            return;
    }
    else
    {
        uuid = getUrlArg(addition, "uuid");
        password = getUrlArg(addition, "password");
        if(uuid.empty() || password.empty())
            return;
        if(!strFind(TUIC, ":"))
            return;
        if(regGetMatch(TUIC, R"(^(.*?):(\d+)$)", 3, 0, &add, &port))
            return;
    }
    token = getUrlArg(addition, "token");
    heartbeat_interval = getUrlArg(addition, "heartbeat_interval");
    disable_sni = getUrlArg(addition, "disable_sni");
    reduce_rtt = getUrlArg(addition, "reduce_rtt");
    request_timeout = getUrlArg(addition, "request_timeout");
    udp_relay_mode = getUrlArg(addition, "udp_relay_mode");
    congestion_controller = getUrlArg(addition, "congestion_control");
    max_udp_relay_packet_size = getUrlArg(addition, "max_udp_relay_packet_size");
    max_open_streams = getUrlArg(addition, "max_open_streams");
    alpn = getUrlArg(addition, "alpn");
    sni = getUrlArg(addition, "sni");
    fast_open = getUrlArg(addition, "fast_open");
    scv = getUrlArg(addition, "insecure");
    std::string tuic_version = getUrlArg(addition, "version");
    if (remarks.empty())
        remarks = add + ":" + port;
    TUICConstruct(node, TUIC_DEFAULT_GROUP, remarks, add, port, uuid, password, ip, heartbeat_interval, alpn, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, sni, fast_open, tuic_version, tfo, scv, "");
}


void explodeStdMieru(std::string mieru, Proxy &node)
{
    std::string username, password, host, port, ports, profile, protocol, multiplexing, mtu, remarks;
    std::string addition;
    tribool udp, tfo, scv, tls13;
    string_size pos;
    pos = mieru.rfind("#");
    if(pos != mieru.npos)
    {
        remarks = urlDecode(mieru.substr(pos + 1));
        mieru.erase(pos);
    }
    pos = mieru.rfind("?");
    if(pos != mieru.npos)
    {
        addition = mieru.substr(pos + 1);
        mieru.erase(pos);
    }
    if(regGetMatch(mieru, R"(^(.*?):(.*?)@(.*)$)", 4, 0, &username, &password, &host))
        return;
    port = getUrlArg(addition, "port");
    if(port.find('-') != std::string::npos)
    {
        ports = port;
    }
    protocol = getUrlArg(addition, "protocol");
    multiplexing = getUrlArg(addition, "multiplexing");
    mtu = getUrlArg(addition, "mtu");
    if(remarks.empty())
        remarks = host;

    mieruConstruct(node, "MieruGroup", remarks, port, password, host, ports, username, multiplexing, protocol, udp, tfo, scv, tls13, "");
}

void explodeStdAnyTLS(std::string anytls, Proxy &node)
{
    std::string add, port, password, sni, alpn, fingerprint, remarks, addition,idle_session_check_interval,idle_session_timeout,min_idle_session;
    std::string client_fingerprint;
    tribool tfo, scv;
    anytls = anytls.substr(9);  // 去除 anytls://
    string_size pos;
    pos = anytls.rfind("#");
    if (pos != anytls.npos) {
        remarks = urlDecode(anytls.substr(pos + 1));
        anytls.erase(pos);
    }
    pos = anytls.rfind("?");
    if (pos != anytls.npos) {
        addition = anytls.substr(pos + 1);
        anytls.erase(pos);
    }
    // 支持 user:pass@host:port
    if (strFind(anytls, "@")) {
        if (regGetMatch(anytls, R"(^(.*?)@(.*?):(\d+)$)", 4, 0, &password, &add, &port))
            return;
    } else {
        password = getUrlArg(addition, "password");
        if (password.empty()) return;
        if (!strFind(anytls, ":")) return;
        if (regGetMatch(anytls, R"(^(.*?):(\d+)$)", 3, 0, &add, &port)) return;
    }
    // 其他参数
    sni = getUrlArg(addition, "peer");
    alpn = getUrlArg(addition, "alpn");
    fingerprint = urlDecode(getUrlArg(addition, "hpkp"));
    // client fingerprint (TLS ClientHello), support both fp and client-fingerprint
    client_fingerprint = getUrlArg(addition, "fp");
    if(client_fingerprint.empty())
        client_fingerprint = getUrlArg(addition, "client-fingerprint");
    tfo = tribool(getUrlArg(addition, "tfo"));
    scv = tribool(getUrlArg(addition, "insecure"));
    if (remarks.empty())
        remarks = add + ":" + port;
    anyTLSConstruct(node, "AnyTLS", remarks, add, port, password, sni, alpn, fingerprint, idle_session_check_interval, idle_session_timeout, min_idle_session,tfo, scv, "");
    if(!client_fingerprint.empty())
        node.ClientFingerprint = client_fingerprint;
}

void explodeAnyTLS(std::string anytls, Proxy &node)
{
    anytls = regReplace(anytls, "(anytls)://", "anytls://");

    // replace /? with ?
    anytls = regReplace(anytls, "/\\?", "?", true, false);
    if(regMatch(anytls, "anytls://(.*?)[:](.*)"))
    {
        explodeStdAnyTLS(anytls, node);
        return;
    }
}

void explodeStdVLESS(std::string vless, Proxy &node)
{
    std::string add, port, type, uuid, aid, net, flow, public_key, sid, fingerprint, mode, path, host, tls, remarks, sni, addition, alpn;
    std::string decoded, userinfo, hostinfo;
    string_array user_parts;
    std::vector<std::string> alpnList;
    tribool tfo, scv, vless_udp, v2ray_http_upgrade, v2ray_http_upgrade_fast_open;
    std::string packet_encoding;
    vless = vless.substr(8);
    string_size pos;
    pos = vless.rfind("#");
    if(pos != vless.npos)
    {
        remarks = urlDecode(vless.substr(pos + 1));
        vless.erase(pos);
    }
    pos = vless.rfind("?");
    if(pos != vless.npos)
    {
        addition = vless.substr(pos + 1);
        vless.erase(pos);
    }
    // 支持 uuid@host:port 格式
    if(strFind(vless, "@"))
    {
        if(regGetMatch(vless, R"(^(.*?)@(.*?):(\d+)$)", 4, 0, &uuid, &add, &port))
            return;
    }
    else
    {
        decoded = urlSafeBase64Decode(vless);
        uuid = getUrlArg(addition, "uuid");
        if(uuid.empty() && strFind(decoded, "@") && strFind(decoded, ":"))
        {
            userinfo = decoded.substr(0, decoded.find('@'));
            hostinfo = decoded.substr(decoded.find('@') + 1);
            if(strFind(userinfo, ":"))
            {
                user_parts = split(userinfo, ":");
                if(user_parts.size() >= 2)
                {
                    uuid = user_parts[1];
                }
            }
            else
            {
                uuid = userinfo;
            }
            if(regGetMatch(hostinfo, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
                return;
        }
        else if(regGetMatch(vless, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
        {
            return;
        }
    }
    if(uuid.empty())
        return;

    if (!addition.empty())
    {
        sni = getUrlArg(addition, "sni");
        if(sni.empty())
        {
            sni = getUrlArg(addition, "peer");
        }
        net = getUrlArg(addition, "type");
        alpn = getUrlArg(addition, "alpn");
        if(!alpn.empty())
            alpnList.push_back(alpn);
        fingerprint = getUrlArg(addition, "hpkp");
        flow = getUrlArg(addition, "flow");
        public_key = getUrlArg(addition, "pbk");
        sid = getUrlArg(addition, "sid");
        tfo = tribool(getUrlArg(addition, "tfo"));
        std::string insecure_val = getUrlArg(addition, "insecure");
        if (insecure_val.empty())
            insecure_val = getUrlArg(addition, "allowInsecure");
        scv = tribool(insecure_val);
        tls = getUrlArg(addition, "security");

        // Parse optional parameters with conditional assignment
        std::string temp_val;
        if(!(temp_val = getUrlArg(addition, "udp")).empty())
            vless_udp = tribool(temp_val);
        if(!(temp_val = getUrlArg(addition, "xudp")).empty())
            node.XUDP = tribool(temp_val);

        // client-fingerprint: try "fp" first, fallback to "client-fingerprint"
        if(!(temp_val = getUrlArg(addition, "fp")).empty() || !(temp_val = getUrlArg(addition, "client-fingerprint")).empty())
            node.ClientFingerprint = temp_val;

        // packet-encoding: try "packetEncoding" first, fallback to "packet-encoding"
        if(!(temp_val = getUrlArg(addition, "packetEncoding")).empty() || !(temp_val = getUrlArg(addition, "packet-encoding")).empty())
        {
            packet_encoding = temp_val;
            node.PacketEncoding = temp_val;
        }

        // ech-config: try "ech" first, fallback to "ech-config"
        if(!(temp_val = getUrlArg(addition, "ech")).empty() || !(temp_val = getUrlArg(addition, "ech-config")).empty())
            node.EchConfig = temp_val;

        if(!(temp_val = getUrlArg(addition, "max-early-data")).empty())
            node.WsMaxEarlyData = to_int(temp_val);
        if(!(temp_val = getUrlArg(addition, "early-data-header-name")).empty())
            node.WsEarlyDataHeaderName = temp_val;
        if(!(temp_val = getUrlArg(addition, "support-x25519mlkem768")).empty())
            node.SupportX25519Mlkem768 = tribool(temp_val);
        if(remarks.empty())
        {
            remarks = urlDecode(getUrlArg(addition, "remark"));
            if(remarks.empty())
                remarks = urlDecode(getUrlArg(addition, "remarks"));
        }
        switch(hash_(net))
        {
            case "tcp"_hash:
            case "ws"_hash:
                type = getUrlArg(addition, "headerType");
                path = getUrlArg(addition, "path");
                host = getUrlArg(addition, "host");
                if(!(temp_val = getUrlArg(addition, "v2ray-http-upgrade")).empty())
                {
                    node.V2rayHttpUpgrade = tribool(temp_val);
                    v2ray_http_upgrade = node.V2rayHttpUpgrade;
                }
                if(!(temp_val = getUrlArg(addition, "v2ray-http-upgrade-fast-open")).empty())
                {
                    node.V2rayHttpUpgradeFastOpen = tribool(temp_val);
                    v2ray_http_upgrade_fast_open = node.V2rayHttpUpgradeFastOpen;
                }
                break;
            case "h2"_hash:
                type = getUrlArg(addition, "headerType");
                host = getUrlArg(addition, strFind(addition,"sni") ? "sni" : "host");
                path = getUrlArg(addition, "path");
                break;
            case "xhttp"_hash:
                if(net == "xhttp") net = "h2";
                type = getUrlArg(addition, "headerType");
                host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "host");
                path = getUrlArg(addition, "path");
                break;
            case "grpc"_hash:
                host = getUrlArg(addition, "sni");
                path = getUrlArg(addition, "serviceName");
                mode = getUrlArg(addition, "mode");
                break;
            case "quic"_hash:
                type = getUrlArg(addition, "headerType");
                host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "quicSecurity");
                path = getUrlArg(addition, "key");
                break;
            default:
                return;
        }
        if(remarks.empty())
        {
            remarks = urlDecode(getUrlArg(addition, "remark"));
            if(remarks.empty())
                remarks = urlDecode(getUrlArg(addition, "remarks"));
        }
    }
    if(remarks.empty())
        remarks = add + ":" + port;

    // VLESS protocol encryption must always be "none" per specification
    vlessConstruct(node, VLESS_DEFAULT_GROUP, remarks, add, port, type, uuid, aid, net, "none", flow, mode, path, host, "", tls, public_key, sid, fingerprint, sni, alpnList, packet_encoding, vless_udp, tfo, scv, tribool(), "", v2ray_http_upgrade, v2ray_http_upgrade_fast_open);
    return;
}

void explodeVLESS(std::string vless, Proxy &node)
{
    vless = regReplace(vless, "(vless)://", "vless://");
    // replace /? with ?
    vless = regReplace(vless, "/\\?", "?", true, false);
    explodeStdVLESS(vless, node);
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
void parsePeers(Proxy &node, const std::string &data)
{
    auto peers = regGetAllMatch(data, R"(\((.*?)\))", true);
    if(peers.empty())
        return;
    auto peer = peers[0];
    auto peerdata = regGetAllMatch(peer, R"(([a-z-]+) ?= ?([^" ),]+|".*?"),? ?)", true);
    if(peerdata.size() % 2 != 0)
        return;
    for(size_t i = 0; i < peerdata.size(); i += 2)
    {
        auto key = peerdata[i];
        auto val = peerdata[i + 1];
        switch(hash_(key))
        {
        case "public-key"_hash:
            node.PublicKey = val;
            break;
        case "endpoint"_hash:
            node.Hostname = val.substr(0, val.rfind(':'));
            node.Port = to_int(val.substr(val.rfind(':') + 1));
            break;
        case "client-id"_hash:
            node.ClientId = val;
            break;
        case "allowed-ips"_hash:
            node.AllowedIPs = trimOf(val, '"');
            break;
        default:
            break;
        }
    }
}

bool explodeSurge(std::string surge, std::vector<Proxy> &nodes)
{
    std::multimap<std::string, std::string> proxies;
    uint32_t i, index = nodes.size();
    INIReader ini;

    /*
    if(!strFind(surge, "[Proxy]"))
        return false;
    */

    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.set_isolated_items_section("Proxy");
    ini.add_direct_save_section("Proxy");
    if(surge.find("[Proxy]") != surge.npos)
        surge = regReplace(surge, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(surge);

    if(!ini.section_exist("Proxy"))
        return false;
    ini.enter_section("Proxy");
    ini.get_items(proxies);

    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";

    for(auto &x : proxies)
    {
        std::string remarks, server, port, method, username, password, sni; //common
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, mod_url, mod_md5; //ss
        std::string id, net, tls, host, edge, path, fp; //v2
        std::string protocol, protoparam; //ssr
        std::string section, ip, ipv6, private_key, public_key, mtu, test_url, client_id, peer, keepalive; //wireguard
        std::string type, fingerprint; //vless
        string_array dns_servers;
        string_multimap wireguard_config;
        std::string version, aead = "1";
        std::string itemName, itemVal, config;
        std::vector<std::string> configs, vArray, headers, header;
        tribool udp, tfo, scv, tls13;
        std::string underlying_proxy, clientFingerprint;
        Proxy node;

        /*
        remarks = regReplace(x.second, proxystr, "$1");
        configs = split(regReplace(x.second, proxystr, "$2"), ",");
        */
        regGetMatch(x.second, proxystr, 3, 0, &remarks, &config);
        configs = split(config, ",");
        if(configs.size() < 3)
            continue;
        switch(hash_(configs[0]))
        {
        case "direct"_hash:
        case "reject"_hash:
        case "reject-tinygif"_hash:
            continue;
        case "custom"_hash: //surge 2 style custom proxy
            //remove module detection to speed up parsing and compatible with broken module
            /*
            mod_url = trim(configs[5]);
            if(parsedMD5.count(mod_url) > 0)
            {
                mod_md5 = parsedMD5[mod_url]; //read calculated MD5 from map
            }
            else
            {
                mod_md5 = getMD5(webGet(mod_url)); //retrieve module and calculate MD5
                parsedMD5.insert(std::pair<std::string, std::string>(mod_url, mod_md5)); //save unrecognized module MD5 to map
            }
            */

            //if(mod_md5 == modSSMD5) //is SSEncrypt module
        {
            if(configs.size() < 5)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            method = trim(configs[3]);
            password = trim(configs[4]);

            for(i = 6; i < configs.size(); i++)
            {
                vArray = split(configs[i], "=");
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "obfs"_hash:
                    plugin = "simple-obfs";
                    pluginopts_mode = itemVal;
                    break;
                case "obfs-host"_hash:
                    pluginopts_host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            if(!plugin.empty())
            {
                pluginopts = "obfs=" + pluginopts_mode;
                pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
            }

            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv, tribool(), underlying_proxy);
        }
            //else
            //    continue;
        break;
        case "ss"_hash: //surge 3 style ss proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "encrypt-method"_hash:
                    method = itemVal;
                    break;
                case "password"_hash:
                    password = itemVal;
                    break;
                case "obfs"_hash:
                    plugin = "simple-obfs";
                    pluginopts_mode = itemVal;
                    break;
                case "obfs-host"_hash:
                    pluginopts_host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            if(!plugin.empty())
            {
                pluginopts = "obfs=" + pluginopts_mode;
                pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
            }

            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv, tribool(), underlying_proxy);
            break;
        case "socks5"_hash: //surge 3 style socks5 proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            if(configs.size() >= 5)
            {
                username = trim(configs[3]);
                password = trim(configs[4]);
            }
            for(i = 5; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv, underlying_proxy);
            break;
        case "vmess"_hash: //surge 4 style vmess proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            net = "tcp";
            method = "auto";

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "username"_hash:
                    id = itemVal;
                    break;
                case "ws"_hash:
                    net = itemVal == "true" ? "ws" : "tcp";
                    break;
                case "tls"_hash:
                    tls = itemVal == "true" ? "tls" : "";
                    break;
                case "ws-path"_hash:
                    path = itemVal;
                    break;
                case "obfs-host"_hash:
                    host = itemVal;
                    break;
                case "ws-headers"_hash:
                    headers = split(itemVal, "|");
                    for(auto &y : headers)
                    {
                        header = split(trim(y), ":");
                        if(header.size() != 2)
                            continue;
                        else if(regMatch(header[0], "(?i)host"))
                            host = trimQuote(header[1]);
                        else if(regMatch(header[0], "(?i)edge"))
                            edge = trimQuote(header[1]);
                    }
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "tls13"_hash:
                    tls13 = itemVal;
                    break;
                case "vmess-aead"_hash:
                    aead = itemVal == "true" ? "0" : "1";
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }

            vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, edge, tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13, underlying_proxy);
            break;
        case "http"_hash: //http proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "username"_hash:
                    username = itemVal;
                    break;
                case "password"_hash:
                    password = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, false, tfo, scv, tribool(), underlying_proxy);
            break;
        case "trojan"_hash: // surge 4 style trojan proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "password"_hash:
                    password = itemVal;
                    break;
                case "sni"_hash:
                    host = itemVal;
                    sni = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "fingerprint"_hash:
                    fp = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }

            trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp, sni, std::vector<std::string>{}, true, udp, tfo, scv, tribool(), underlying_proxy);
            break;
        case "snell"_hash:
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "psk"_hash:
                    password = itemVal;
                    break;
                case "obfs"_hash:
                    plugin = itemVal;
                    break;
                case "obfs-host"_hash:
                    host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "version"_hash:
                    version = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }

            snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server, port, password, plugin, host, to_int(version, 0), udp, tfo, scv, underlying_proxy);
            break;
        case "wireguard"_hash:
            for (i = 1; i < configs.size(); i++)
            {
                vArray = splitKeyValue(trim(configs[i]), "=");
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "section-name"_hash:
                    section = itemVal;
                    break;
                case "test-url"_hash:
                    test_url = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                }
            }
            if(section.empty())
                continue;
            ini.get_items("WireGuard " + section, wireguard_config);
            if(wireguard_config.empty())
                continue;

            for (auto &c : wireguard_config)
            {
                itemName = trim(c.first);
                itemVal = trim(c.second);
                switch(hash_(itemName))
                {
                case "self-ip"_hash:
                    ip = itemVal;
                    break;
                case "self-ip-v6"_hash:
                    ipv6 = itemVal;
                    break;
                case "private-key"_hash:
                    private_key = itemVal;
                    break;
                case "dns-server"_hash:
                    vArray = split(itemVal, ",");
                    for (auto &y : vArray)
                        dns_servers.emplace_back(trim(y));
                    break;
                case "mtu"_hash:
                    mtu = itemVal;
                    break;
                case "peer"_hash:
                    peer = itemVal;
                    break;
                case "keepalive"_hash:
                    keepalive = itemVal;
                    break;
                }
            }

            wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers, mtu, keepalive, test_url, "", udp, underlying_proxy);
            parsePeers(node, peer);
            break;
        default:
            switch(hash_(remarks))
            {
            case "shadowsocks"_hash: //quantumult x style ss/ssr link
                server = trim(configs[0].substr(0, configs[0].rfind(":")));
                port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                if(port == "0")
                    continue;

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitKeyValue(trim(configs[i]), "=");
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "method"_hash:
                        method = itemVal;
                        break;
                    case "password"_hash:
                        password = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "ssr-protocol"_hash:
                        protocol = itemVal;
                        break;
                    case "ssr-protocol-param"_hash:
                        protoparam = itemVal;
                        break;
                    case "obfs"_hash:
                    {
                        switch(hash_(itemVal))
                        {
                        case "http"_hash:
                        case "tls"_hash:
                            plugin = "simple-obfs";
                            pluginopts_mode = itemVal;
                            break;
                        case "wss"_hash:
                            tls = "tls";
                            [[fallthrough]];
                        case "ws"_hash:
                            pluginopts_mode = "websocket";
                            plugin = "v2ray-plugin";
                            break;
                        default:
                            pluginopts_mode = itemVal;
                        }
                        break;
                    }
                    case "obfs-host"_hash:
                        pluginopts_host = itemVal;
                        break;
                    case "obfs-uri"_hash:
                        path = itemVal;
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "underlying-proxy"_hash:
                        underlying_proxy = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;
                switch(hash_(plugin))
                {
                case "simple-obfs"_hash:
                    pluginopts = "obfs=" + pluginopts_mode;
                    if(!pluginopts_host.empty())
                        pluginopts += ";obfs-host=" + pluginopts_host;
                    break;
                case "v2ray-plugin"_hash:
                    if(pluginopts_host.empty() && !isIPv4(server) && !isIPv6(server))
                        pluginopts_host = server;
                    pluginopts = "mode=" + pluginopts_mode;
                    if(!pluginopts_host.empty())
                        pluginopts += ";host=" + pluginopts_host;
                    if(!path.empty())
                        pluginopts += ";path=" + path;
                    pluginopts += ";" + tls;
                    break;
                }

                if(!protocol.empty())
                {
                    ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, pluginopts_mode, password, pluginopts_host, protoparam, udp, tfo, scv, underlying_proxy);
                }
                else
                {
                    ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv, tls13, underlying_proxy);
                }
                break;
            case "vmess"_hash: //quantumult x style vmess link
                server = trim(configs[0].substr(0, configs[0].rfind(":")));
                port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                if(port == "0")
                    continue;
                net = "tcp";

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitKeyValue(trim(configs[i]), "=");
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "method"_hash:
                        method = itemVal;
                        break;
                    case "password"_hash:
                        id = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "obfs"_hash:
                        switch(hash_(itemVal))
                        {
                        case "ws"_hash:
                            net = "ws";
                            break;
                        case "over-tls"_hash:
                            tls = "tls";
                            break;
                        case "wss"_hash:
                            net = "ws";
                            tls = "tls";
                            break;
                        }
                        break;
                    case "obfs-host"_hash:
                        host = itemVal;
                        break;
                    case "obfs-uri"_hash:
                        path = itemVal;
                        break;
                    case "over-tls"_hash:
                        tls = itemVal == "true" ? "tls" : "";
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "aead"_hash:
                        aead = itemVal == "true" ? "0" : "1";
                        break;
                    case "underlying-proxy"_hash:
                        underlying_proxy = itemVal;
                        break;
                    case "early-data-header-name"_hash:
                        node.WsEarlyDataHeaderName = itemVal;
                        break;
                    case "max-early-data"_hash:
                        node.WsMaxEarlyData = to_int(itemVal, 0);
                        break;
                    case "fingerprint"_hash:
                        fingerprint = itemVal;
                        break;
                    case "client-fingerprint"_hash:
                        fp = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, "", tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13, underlying_proxy, fp, fingerprint);
                break;
            case "trojan"_hash: //quantumult x style trojan link
                server = trim(configs[0].substr(0, configs[0].rfind(':')));
                port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                if(port == "0")
                    continue;

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitKeyValue(trim(configs[i]), "=");
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "password"_hash:
                        password = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "over-tls"_hash:
                        tls = itemVal;
                        break;
                    case "tls-host"_hash:
                        host = itemVal;
                        sni = itemVal;
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "tls-verification"_hash:
                        scv = itemVal == "false";
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "fp"_hash:
                        fp = itemVal;
                        break;
                    case "underlying-proxy"_hash:
                        underlying_proxy = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp, sni, std::vector<std::string>{}, tls == "true", udp, tfo, scv, tls13, underlying_proxy);
                break;
            case "http"_hash: //quantumult x style http links
                server = trim(configs[0].substr(0, configs[0].rfind(':')));
                port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                if(port == "0")
                    continue;

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitKeyValue(trim(configs[i]), "=");
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "username"_hash:
                        username = itemVal;
                        break;
                    case "password"_hash:
                        password = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "over-tls"_hash:
                        tls = itemVal;
                        break;
                    case "tls-verification"_hash:
                        scv = itemVal == "false";
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "underlying-proxy"_hash:
                        underlying_proxy = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                if(username == "none")
                    username.clear();
                if(password == "none")
                    password.clear();

                httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, tls == "true", tfo, scv, tls13, underlying_proxy);
                break;
            case "vless"_hash: // quantumult x style vless link
                server = trim(configs[0].substr(0, configs[0].rfind(":")));
                port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                if(port == "0")
                    continue;
                net = "tcp";
                for(i = 1; i < configs.size(); i++)
                {
                    vArray = split(trim(configs[i]), "=");
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                        case "method"_hash:
                            method = itemVal;
                            break;
                        case "password"_hash:
                            id = itemVal;
                            break;
                        case "tag"_hash:
                            remarks = itemVal;
                            break;
                        case "obfs"_hash:
                            switch(hash_(itemVal))
                            {
                                case "ws"_hash:
                                    net = "ws";
                                    break;
                                case "over-tls"_hash:
                                    tls = "tls";
                                    break;
                                case "wss"_hash:
                                    net = "ws";
                                    tls = "tls";
                                    break;
                            }
                            break;
                        case "obfs-host"_hash:
                            host = itemVal;
                            break;
                        case "obfs-uri"_hash:
                            path = itemVal;
                            break;
                        case "over-tls"_hash:
                            tls = itemVal == "true" ? "tls" : "";
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "fast-open"_hash:
                            tfo = itemVal;
                            break;
                        case "tls13"_hash:
                            tls13 = itemVal;
                            break;
                        case "aead"_hash:
                            aead = itemVal == "true" ? "0" : "1";
                        default:
                            continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;
                // VLESS protocol encryption must always be "none" per specification
                vlessConstruct(node, VLESS_DEFAULT_GROUP, remarks, server, port, type, id, aead, net, "none", "", "", path, host, "", tls, "", "", fingerprint, sni, std::vector<std::string>{}, "", udp, tfo, scv, tls13);
                break;
            default:
                continue;
            }
            break;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
    return index;
}

void explodeSSTap(std::string sstap, std::vector<Proxy> &nodes)
{
    std::string configType, group, remarks, server, port;
    std::string cipher;
    std::string user, pass;
    std::string protocol, protoparam, obfs, obfsparam;
    Document json;
    uint32_t index = nodes.size();
    json.Parse(sstap.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    for(uint32_t i = 0; i < json["configs"].Size(); i++)
    {
        Proxy node;
        json["configs"][i]["group"] >> group;
        json["configs"][i]["remarks"] >> remarks;
        json["configs"][i]["server"] >> server;
        port = GetMember(json["configs"][i], "server_port");
        if(port == "0")
            continue;

        if(remarks.empty())
            remarks = server + ":" + port;

        json["configs"][i]["password"] >> pass;
        json["configs"][i]["type"] >> configType;
        switch(to_int(configType, 0))
        {
        case 5: //socks 5
            json["configs"][i]["username"] >> user;
            socksConstruct(node, group, remarks, server, port, user, pass);
            break;
        case 6: //ss/ssr
            json["configs"][i]["protocol"] >> protocol;
            json["configs"][i]["obfs"] >> obfs;
            json["configs"][i]["method"] >> cipher;
            if(find(ss_ciphers.begin(), ss_ciphers.end(), cipher) != ss_ciphers.end() && protocol == "origin" && obfs == "plain") //is ss
            {
                ssConstruct(node, group, remarks, server, port, pass, cipher, "", "");
            }
            else //is ssr cipher
            {
                json["configs"][i]["obfsparam"] >> obfsparam;
                json["configs"][i]["protocolparam"] >> protoparam;
                ssrConstruct(node, group, remarks, server, port, protocol, cipher, obfs, pass, obfsparam, protoparam);
            }
            break;
        default:
            continue;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeNetchConf(std::string netch, std::vector<Proxy> &nodes)
{
    Document json;
    uint32_t index = nodes.size();

    json.Parse(netch.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    if(!json.HasMember("Server"))
        return;

    for(uint32_t i = 0; i < json["Server"].Size(); i++)
    {
        Proxy node;
        explodeNetch("Netch://" + base64Encode(json["Server"][i] | SerializeObject()), node);

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes)
{
    ConfType filetype = ConfType::Unknow;

    if(strFind(content, "\"version\""))
        filetype = ConfType::SS;
    else if(strFind(content, "\"serverSubscribes\""))
        filetype = ConfType::SSR;
    else if(strFind(content, "\"uiItem\"") || strFind(content, "vnext"))
        filetype = ConfType::V2Ray;
    else if(strFind(content, "\"proxy_apps\""))
        filetype = ConfType::SSConf;
    else if(strFind(content, "\"idInUse\""))
        filetype = ConfType::SSTap;
    else if(strFind(content, "\"local_address\"") && strFind(content, "\"local_port\""))
        filetype = ConfType::SSR; //use ssr config parser
    else if(strFind(content, "\"ModeFileNameType\""))
        filetype = ConfType::Netch;

    switch(filetype)
    {
    case ConfType::SS:
        explodeSSConf(content, nodes);
        break;
    case ConfType::SSR:
        explodeSSRConf(content, nodes);
        break;
    case ConfType::V2Ray:
        explodeVmessConf(content, nodes);
        break;
    case ConfType::SSConf:
        explodeSSAndroid(content, nodes);
        break;
    case ConfType::SSTap:
        explodeSSTap(content, nodes);
        break;
    case ConfType::Netch:
        explodeNetchConf(content, nodes);
        break;
    default:
        //try to parse as a local subscription
        explodeSub(content, nodes);
    }

    return !nodes.empty();
}

void explodeSingboxTransport(rapidjson::Value &singboxNode, std::string &net, std::string &host, std::string &path, std::string edge)
{
    if(singboxNode.HasMember("transport") && singboxNode["transport"].IsObject())
    {
        rapidjson::Value transport = singboxNode["transport"].GetObject();
        net = GetMember(transport, "type");
        switch(hash_(net))
        {
            case "http"_hash:
            {
                host = GetMember(transport, "host");
                break;
            }
            case "ws"_hash:
            {
                path = GetMember(transport, "path");
                if(transport.HasMember("headers") && transport["headers"].IsObject())
                {
                    rapidjson::Value headers = transport["headers"].GetObject();
                    host = GetMember(headers, "Host");
                    edge = GetMember(headers, "Edge");
                }
                break;
            }
            case "grpc"_hash:
            {
                path = GetMember(transport, "service_name");
                break;
            }
            default:
                net = "tcp";
                path.clear();
                break;
        }
    }
    else
    {
        net = "tcp";
        host.clear();
        edge.clear();
        path.clear();
    }
}

void explodeSingbox(rapidjson::Value &outbounds, std::vector<Proxy> &nodes)
{
    uint32_t index = nodes.size();
    for(rapidjson::SizeType i = 0; i < outbounds.Size(); ++i)
    {
        if(outbounds[i].IsObject())
        {
            std::string proxytype, ps, server, port, cipher, group, password, underlying_proxy; //common
            std::string type = "none", id, aid = "0", net = "tcp", path, host, edge, tls, sni; //vmess
            std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux, pluginopts_version, pluginopts_password; //ss
            std::string protocol, protoparam, obfs, obfsparam; //ssr
            std::string flow, mode; //trojan
            std::string user; //socks
            std::string ip, ipv6, private_key, public_key, mtu; //wireguard
            std::string ports, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str,/* obfs, sni,*/ fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpn; //hysteria
            std::vector<std::string> hysteria_alpnList;
            std::string obfs_password, cwnd; //hysteria2
            std::string uuid,/*ip , password*/ heartbeat_interval, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, fast_open, tuic_version;   //tuic
            std::string sid, packet_encoding; // vless
            std::string idle_session_check_interval, idle_session_timeout, min_idle_session; // anyTLS
            string_array dns_server;
            tribool udp, tfo, scv, disablesni, reducertt;
            rapidjson::Value singboxNode = outbounds[i].GetObject();
            if(singboxNode.HasMember("type") && singboxNode["type"].IsString())
            {
                Proxy node;
                proxytype = singboxNode["type"].GetString();
                ps = GetMember(singboxNode, "tag");
                server = GetMember(singboxNode, "server");
                port = GetMember(singboxNode, "server_port");
                tfo = GetMember(singboxNode, "tcp_fast_open");
                std::vector<std::string> alpnList;
                if(singboxNode.HasMember("tls") && singboxNode["tls"].IsObject())
                {
                    rapidjson::Value tlsObj = singboxNode["tls"].GetObject();
                    if(tlsObj.HasMember("enabled") && tlsObj["enabled"].IsBool() && tlsObj["enabled"].GetBool())
                    {
                        tls = "tls";
                    }
                    sni = GetMember(tlsObj, "server_name");
                    if(tlsObj.HasMember("alpn") && tlsObj["alpn"].IsArray() && !tlsObj["alpn"].Empty())
                    {
                        rapidjson::Value alpns = tlsObj["alpn"].GetArray();
                        if(alpns.Size() > 0)
                        {
                            alpn = alpns[0].GetString();
                            for(auto &item: tlsObj["alpn"].GetArray())
                            {
                                if(item.IsString())
                                    alpnList.emplace_back(item.GetString());
                            }
                        }
                    }
                    if(tlsObj.HasMember("insecure") && tlsObj["insecure"].IsBool())
                    {
                        scv = tlsObj["insecure"].GetBool();
                    }
                    if(tlsObj.HasMember("disable_sni") && tlsObj["disable_sni"].IsBool())
                    {
                        disablesni = tlsObj["disable_sni"].GetBool();
                    }
                    if(tlsObj.HasMember("certificate") && tlsObj["certificate"].IsString())
                    {
                        ca_str = tlsObj["certificate"].GetString();
                    }
                    if(tlsObj.HasMember("reality") && tlsObj["reality"].IsObject())
                    {
                        tls = "reality";
                        rapidjson::Value reality = tlsObj["reality"].GetObject();
                        if(reality.HasMember("server_name") && reality["server_name"].IsString())
                        {
                            host = reality["server_name"].GetString();
                        }
                        if(reality.HasMember("public_key") && reality["public_key"].IsString())
                        {
                            public_key = reality["public_key"].GetString();
                        }
                        if(reality.HasMember("short_id") && reality["short_id"].IsString())
                        {
                            sid = reality["short_id"].GetString();
                        }
                    }
                }
                else
                {
                    tls = "false";
                }
                switch(hash_(proxytype))
                {
                    case "vmess"_hash:
                        group = V2RAY_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        if(id.length() < 36)
                        {
                            break;
                        }
                        aid = GetMember(singboxNode, "alter_id");
                        cipher = GetMember(singboxNode, "security");
                        explodeSingboxTransport(singboxNode, net, host, path, edge);
                        vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, alpnList, udp, tfo, scv, tribool(), underlying_proxy, "", "", tribool(), tribool());
                        break;
                    case "shadowsocks"_hash:
                        group = SS_DEFAULT_GROUP;
                        cipher = GetMember(singboxNode, "method");
                        password = GetMember(singboxNode, "password");
                        plugin = GetMember(singboxNode, "plugin");
                        pluginopts = GetMember(singboxNode, "plugin_opts");
                        ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv,  tribool(), underlying_proxy);
                        break;
                    case "http"_hash:
                        group = HTTP_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        user = GetMember(singboxNode, "username");
                        httpConstruct(node, group, ps, server, port, user, password, tls == "tls", tfo, scv);
                        break;
                    case "socks"_hash:
                        group = SOCKS_DEFAULT_GROUP;
                        user = GetMember(singboxNode, "username");
                        password = GetMember(singboxNode, "password");
                        socksConstruct(node, group, ps, server, port, user, password);
                        break;
                    case "trojan"_hash:
                        group = TROJAN_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        explodeSingboxTransport(singboxNode, net, host, path, edge);
                        trojanConstruct(node, group, ps, server, port, password, net, host, path, "", sni, alpnList, true, udp, tfo, scv, tribool(), underlying_proxy);
                        break;
                    case "wireguard"_hash:
                        group = WG_DEFAULT_GROUP;
                        ip = GetMember(singboxNode, "inet4_bind_address");
                        ipv6 = GetMember(singboxNode, "inet6_bind_address");
                        public_key = GetMember(singboxNode, "public_key");
                        private_key = GetMember(singboxNode, "private_key");
                        mtu = GetMember(singboxNode, "mtu");
                        password = GetMember(singboxNode, "pre_shared_key");
                        dns_server = {"dns"};
                        wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password, dns_server, mtu, "0", "", "", udp, underlying_proxy);
                        break;
                    case "hysteria"_hash:
                        group = HYSTERIA_DEFAULT_GROUP;
                        protocol = GetMember(singboxNode, "protocol");
                        up_speed = GetMember(singboxNode, "up_mbps");
                        if(up_speed.empty()) up = GetMember(singboxNode, "up");
                        down_speed = GetMember(singboxNode, "down_mbps");
                        if(down_speed.empty()) down = GetMember(singboxNode, "down");
                        auth = GetMember(singboxNode, "auth");
                        if(singboxNode.HasMember("auth_str") && singboxNode["auth_str"].IsString())
                        {
                        auth_str = GetMember(singboxNode, "auth_str");
                        }
                        obfs = GetMember(singboxNode, "obfs");
                        sni = GetMember(singboxNode, "sni");
                        fingerprint = GetMember(singboxNode, "fingerprint");
                        alpn = GetMember(singboxNode, "alpn");
                        ca = GetMember(singboxNode, "ca");
                        ca_str = GetMember(singboxNode, "ca_str");
                        recv_window_conn = GetMember(singboxNode, "recv_window_conn");
                        recv_window = GetMember(singboxNode, "recv_window");
                        disable_mtu_discovery = GetMember(singboxNode, "disable_mtu_discovery");
                        hysteriaConstruct(node, group, ps, server, port, "", protocol, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, obfs, sni, fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, "", hysteria_alpnList, alpn, tfo, scv, underlying_proxy);
                        break;
                    case "hysteria2"_hash:
                        group = HYSTERIA2_DEFAULT_GROUP;
                        ports = GetMember(singboxNode, "ports");
                        up_speed = GetMember(singboxNode, "up_mbps");
                        down_speed = GetMember(singboxNode, "down_mbps");
                        password = GetMember(singboxNode, "password");
                        if(singboxNode.HasMember("obfs") && singboxNode["obfs"].IsObject())
                        {
                            rapidjson::Value obfsOpt = singboxNode["obfs"].GetObject();
                            obfs = GetMember(obfsOpt, "obfs");
                            obfs_password = GetMember(obfsOpt, "password");
                        }
                        sni = GetMember(singboxNode, "sni");
                        fingerprint = GetMember(singboxNode, "fingerprint");
                        alpn =GetMember(singboxNode, "alpn");
                        ca = GetMember(singboxNode, "ca");
                        ca_str = GetMember(singboxNode, "ca_str");
                        cwnd = GetMember(singboxNode, "cwnd");
                        hop_interval = GetMember(singboxNode, "hop_interval");

                        hysteria2Construct(node, group, ps, server, port, ports, up_speed, down_speed, password, "", obfs, obfs_password, sni, fingerprint, alpn, ca, ca_str, cwnd, hop_interval, "", "", "", "", "", "", tfo, scv, underlying_proxy);
                        break;
                    case "vless"_hash:
                        group = VLESS_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        flow = GetMember(singboxNode, "flow");
                        packet_encoding = GetMember(singboxNode, "packet_encoding");
                        if(singboxNode.HasMember("transport") && singboxNode["transport"].IsObject())
                        {
                            rapidjson::Value transport = singboxNode["transport"].GetObject();
                            net = GetMember(transport, "type");
                            switch(hash_(net))
                            {
                                case "tcp"_hash:
                                {
                                    break;
                                }
                                case "ws"_hash:
                                {
                                    path = GetMember(transport, "path");
                                    if(transport.HasMember("headers") && transport["headers"].IsObject())
                                    {
                                        rapidjson::Value headers = transport["headers"].GetObject();
                                        host = GetMember(headers, "Host");
                                        edge = GetMember(headers, "Edge");
                                    }
                                    break;
                                }
                                case "http"_hash:
                                {
                                    host = GetMember(transport, "host");
                                    path = GetMember(transport, "path");
                                    edge.clear();
                                    break;
                                }
                                case "httpupgrade"_hash:
                                {
                                    net = "h2";
                                    host = GetMember(transport, "host");
                                    path = GetMember(transport, "path");
                                    edge.clear();
                                    break;
                                }
                                case "grpc"_hash:
                                {
                                    host = server;
                                    path = GetMember(transport, "service_name");
                                    break;
                                }
                            }
                        }

                        // VLESS protocol encryption must always be "none" per specification
                        vlessConstruct(node, group, ps, server, port, type, id, aid, net, "none", flow, mode, path, host, "", tls, public_key, sid, fingerprint, sni, alpnList, packet_encoding, udp);
                        break;
                    case "tuic"_hash:
                        group = TUIC_DEFAULT_GROUP;
                        uuid = GetMember(singboxNode, "uuid");
                        password = GetMember(singboxNode, "password");
                        congestion_controller = GetMember(singboxNode, "congestion_control");
                        udp_relay_mode = GetMember(singboxNode, "udp_relay_mode");
                        if(singboxNode.HasMember("zero_rtt_handshake") && singboxNode["zero_rtt_handshake"].IsBool())
                            reduce_rtt = singboxNode["zero_rtt_handshake"].GetBool();
                        heartbeat_interval = GetMember(singboxNode, "heartbeat");
                        fast_open = GetMember(singboxNode, "fast_open");
                        sni = GetMember(singboxNode, "sni");
                        alpn = GetMember(singboxNode, "alpn");
                        TUICConstruct(node, group, ps, server, port, uuid, password, ip, heartbeat_interval, alpn, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, sni, fast_open, tuic_version, tfo, scv, underlying_proxy);
                        break;
                    case "anytls"_hash:
                        group = ANYTLS_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, server, port, password, sni, alpn, fingerprint, idle_session_check_interval, idle_session_timeout, min_idle_session, tfo, scv, underlying_proxy);
                        break;
                    default:
                        continue;
                }
                node.Id = index;
                nodes.emplace_back(std::move(node));
                index++;
            }
        }
    }
}

void explode(const std::string &link, Proxy &node)
{
    if(startsWith(link, "ssr://"))
        explodeSSR(link, node);
    else if(startsWith(link, "vmess://") || startsWith(link, "vmess1://"))
        explodeVmess(link, node);
    else if(startsWith(link, "ss://"))
        explodeSS(link, node);
    else if(startsWith(link, "socks://") || startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks"))
        explodeSocks(link, node);
    else if(startsWith(link, "https://t.me/http") || startsWith(link, "tg://http")) //telegram style http link
        explodeHTTP(link, node);
    else if(startsWith(link, "Netch://"))
        explodeNetch(link, node);
    else if(startsWith(link, "trojan://") || startsWith(link, "trojan-go://"))
        explodeTrojan(link, node);
    else if(startsWith(link, "hysteria://"))
        explodeHysteria(link, node);
    else if(startsWith(link, "hysteria2://") || startsWith(link, "hy2://"))
        explodeHysteria2(link, node);
    else if(startsWith(link, "tuic://"))
        explodeTUIC(link, node);
    else if(startsWith(link, "anytls://"))
        explodeAnyTLS(link, node);
    else if(startsWith(link, "vless://") || startsWith(link, "vless1://"))
        explodeVLESS(link, node);
    else if(startsWith(link, "mierus://") || startsWith(link, "mieru://"))
        explodeMierus(link, node);
    else if(isLink(link))
        explodeHTTPSub(link, node);
}

void explodeSub(std::string sub, std::vector<Proxy> &nodes)
{
    std::stringstream strstream;
    std::string strLink;
    bool processed = false;

    //try to parse as SSD configuration
    if(startsWith(sub, "ssd://"))
    {
        explodeSSD(sub, nodes);
        processed = true;
    }

    //try to parse as clash configuration
    try
    {
        if(!processed && regFind(sub, "\"?(Proxy|proxies)\"?:"))
        {
            std::string cleaned_yaml;
            std::istringstream iss(sub);
            std::string line;
            bool in_proxies_array = false;
            while(std::getline(iss, line))
            {
                if(regFind(line, "^(?:Proxy|proxies):"))
                {
                    in_proxies_array = true;
                    cleaned_yaml += line + "\n";
                    continue;
                }
                if(in_proxies_array && !line.empty() && line[0] != ' ' && line[0] != '#' && line[0] != '\t')
                {
                    in_proxies_array = false;
                    cleaned_yaml += line + "\n";
                    continue;
                }
                if(in_proxies_array)
                {
                    std::string trimmed = trim(line);
                    if(trimmed.empty())
                    {
                        continue;
                    }
                    if(trimmed[0] == '#')
                    {
                        if(global.printDbgInfo)
                        {
                            writeLog(LOG_TYPE_RENDER, "Skipping comment line in proxies array: " + (trimmed.length() > 60 ? trimmed.substr(0, 60) + "..." : trimmed), LOG_LEVEL_DEBUG);
                        }
                        continue;
                    }
                    cleaned_yaml += line + "\n";
                    continue;
                }
                cleaned_yaml += line + "\n";
            }
            regGetMatch(cleaned_yaml, R"(^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)", 1, &sub);
            Node yamlnode = Load(sub);
            if(yamlnode.size() && (yamlnode["Proxy"].IsDefined() || yamlnode["proxies"].IsDefined()))
            {
                explodeClash(yamlnode, nodes);
                processed = true;
            }
        }
    }
    catch (std::exception &e)
    {
        //writeLog(0, e.what(), LOG_LEVEL_DEBUG);
        //ignore
        throw;
    }

    try
    {
        std::string pattern = "\"?(inbounds)\"?:";
        if(!processed &&
            regFind(sub, pattern)) {
            pattern = "\"?(outbounds)\"?:";
            if(regFind(sub, pattern))
            {
                pattern = "\"?(route)\"?:";
                if(regFind(sub, pattern))
                {
                    rapidjson::Document document;
                    document.Parse(sub.c_str());
                    if(!document.HasParseError() || document.IsObject())
                    {
                        rapidjson::Value &value = document["outbounds"];
                        if(value.IsArray() && !value.Empty())
                        {
                            explodeSingbox(value, nodes);
                            processed = true;
                        }
                    }
                }
            }
        }
    }
    catch(std::exception &e)
    {
        //writeLog(0, e.what(), LOG_LEVEL_DEBUG);
        //ignore
        throw;
    }
    //try to parse as surge configuration
    if(!processed && explodeSurge(sub, nodes))
        processed = true;

    //try to parse as normal subscription
    if(!processed)
    {
        sub = urlSafeBase64Decode(sub);
        if(regFind(sub, "(vmess|shadowsocks|http|trojan)\\s*?="))
        {
            if(explodeSurge(sub, nodes))
                return;
        }
        strstream << sub;
        char delimiter = count(sub.begin(), sub.end(), '\n') < 1 ? count(sub.begin(), sub.end(), '\r') < 1 ? ' ' : '\r' : '\n';
        while(getline(strstream, strLink, delimiter))
        {
            Proxy node;
            if(strLink.rfind('\r') != std::string::npos)
                strLink.erase(strLink.size() - 1);
            explode(strLink, node);
            if(strLink.empty() || node.Type == ProxyType::Unknown)
            {
                continue;
            }
            nodes.emplace_back(std::move(node));
        }
    }
}
