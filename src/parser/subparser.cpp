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

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &sni, const std::vector<std::string> &alpnList, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, const std::string &fingerprint, const std::string &clientFingerprint, tribool v2ray_http_upgrade, tribool v2ray_http_upgrade_fast_open, const std::string &certificate, const std::string &certificate_key)
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
    if(!certificate.empty()) node.Certificate = certificate;
    if(!certificate_key.empty()) node.CertificateKey = certificate_key;
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

void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &method, const std::string &plugin, const std::string &pluginopts, tribool udp, tribool tfo, tribool scv, tribool udp_over_tcp, const std::string& underlying_proxy, const std::string &client_fingerprint, int udp_over_tcp_version)
{
    commonConstruct(node, ProxyType::Shadowsocks, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Plugin = plugin;
    node.PluginOption = pluginopts;
    node.UDPoverTCP = udp_over_tcp;
    node.ClientFingerprint = client_fingerprint;
    node.UDPOverTCPVersion = udp_over_tcp_version;
    std::string fingerprint = getUrlArg(pluginopts, "fingerprint");
    if(!fingerprint.empty())
        node.Fingerprint = fingerprint;
    if(plugin == "kcptun")
    {
        std::string key = getUrlArg(pluginopts, "key");
        if(!key.empty())
            node.KCPKey = key;
        std::string crypt = getUrlArg(pluginopts, "crypt");
        if(!crypt.empty())
            node.KCPCrypt = crypt;
        std::string mode = getUrlArg(pluginopts, "mode");
        if(!mode.empty())
            node.KCPMode = mode;
        std::string conn = getUrlArg(pluginopts, "conn");
        if(!conn.empty())
            node.KCPConn = to_int(conn);
        std::string autoexpire = getUrlArg(pluginopts, "autoexpire");
        if(!autoexpire.empty())
            node.KCPAutoExpire = to_int(autoexpire);
        std::string scavengettl = getUrlArg(pluginopts, "scavengettl");
        if(!scavengettl.empty())
            node.KCPScavengeTTL = to_int(scavengettl);
        std::string mtu = getUrlArg(pluginopts, "mtu");
        if(!mtu.empty())
            node.KCPMtu = to_int(mtu);
        std::string ratelimit = getUrlArg(pluginopts, "ratelimit");
        if(!ratelimit.empty())
            node.KCPRateLimit = to_int(ratelimit);
        std::string sndwnd = getUrlArg(pluginopts, "sndwnd");
        if(!sndwnd.empty())
            node.KCPSndWnd = to_int(sndwnd);
        std::string rcvwnd = getUrlArg(pluginopts, "rcvwnd");
        if(!rcvwnd.empty())
            node.KCPRcvWnd = to_int(rcvwnd);
        std::string datashard = getUrlArg(pluginopts, "datashard");
        if(!datashard.empty())
            node.KCPDataShard = to_int(datashard);
        std::string parityshard = getUrlArg(pluginopts, "parityshard");
        if(!parityshard.empty())
            node.KCPParityShard = to_int(parityshard);
        std::string dscp = getUrlArg(pluginopts, "dscp");
        if(!dscp.empty())
            node.KCPDSCP = to_int(dscp);
        std::string nocomp = getUrlArg(pluginopts, "nocomp");
        if(!nocomp.empty())
            node.KCPNoComp = to_int(nocomp);
        std::string acknodelay = getUrlArg(pluginopts, "acknodelay");
        if(!acknodelay.empty())
            node.KCPAckNoDelay = to_int(acknodelay);
        std::string nodelay = getUrlArg(pluginopts, "nodelay");
        if(!nodelay.empty())
            node.KCPNodelay = to_int(nodelay);
        std::string interval = getUrlArg(pluginopts, "interval");
        if(!interval.empty())
            node.KCPInterval = to_int(interval);
        std::string resend = getUrlArg(pluginopts, "resend");
        if(!resend.empty())
            node.KCPResend = to_int(resend);
        std::string sockbuf = getUrlArg(pluginopts, "sockbuf");
        if(!sockbuf.empty())
            node.KCPSockbuf = to_int(sockbuf);
        std::string smuxver = getUrlArg(pluginopts, "smuxver");
        if(!smuxver.empty())
            node.KCPSmuxver = to_int(smuxver);
        std::string smuxbuf = getUrlArg(pluginopts, "smuxbuf");
        if(!smuxbuf.empty())
            node.KCPSmuxbuf = to_int(smuxbuf);
        std::string framesize = getUrlArg(pluginopts, "framesize");
        if(!framesize.empty())
            node.KCPFramesize = to_int(framesize);
        std::string streambuf = getUrlArg(pluginopts, "streambuf");
        if(!streambuf.empty())
            node.KCPStreambuf = to_int(streambuf);
        std::string keepalive = getUrlArg(pluginopts, "keepalive");
        if(!keepalive.empty())
            node.KCPKeepalive = to_int(keepalive);
    }
}

void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy, const std::string& ip_version, bool tls, const std::string& fingerprint, const std::string& certificate, const std::string& certificate_key, const std::string& sni)
{
    commonConstruct(node, ProxyType::SOCKS5, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Username = username;
    node.Password = password;
    if(!ip_version.empty())
        node.IPVersion = ip_version;
    node.TLSSecure = tls;
    if(!fingerprint.empty())
        node.Fingerprint = fingerprint;
    if(!certificate.empty())
        node.Certificate = certificate;
    if(!certificate_key.empty())
        node.CertificateKey = certificate_key;
    if(!sni.empty())
        node.ServerName = sni;
}

void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, bool tls, tribool tfo, tribool scv, tribool tls13, const std::string& underlying_proxy, const std::string& ip_version, const std::string& fingerprint, const std::string& certificate, const std::string& certificate_key, const std::string& sni, tribool udp)
{
    commonConstruct(node, tls ? ProxyType::HTTPS : ProxyType::HTTP, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Username = username;
    node.Password = password;
    node.TLSSecure = tls;
    if(!ip_version.empty())
        node.IPVersion = ip_version;
    if(!fingerprint.empty())
        node.Fingerprint = fingerprint;
    if(!certificate.empty())
        node.Certificate = certificate;
    if(!certificate_key.empty())
        node.CertificateKey = certificate_key;
    if(!sni.empty())
        node.ServerName = sni;
}

void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &network, const std::string &host, const std::string &path, const std::string &fp, const std::string &sni, const std::vector<std::string> &alpnList, bool tlssecure, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, tribool v2ray_http_upgrade, tribool v2ray_http_upgrade_fast_open, const std::string &flow, tribool flow_show, const std::string &certificate, const std::string &certificate_key)
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
    if(!flow.empty())
        node.Flow = flow;
    if(!flow_show.is_undef())
        node.FlowShow = flow_show;
    if(!certificate.empty())
        node.Certificate = certificate;
    if(!certificate_key.empty())
        node.CertificateKey = certificate_key;
    if(network == "grpc")
        node.GrpcServiceName = path;
    else if(network == "ws")
        node.WsPath = path;
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

void wireguardConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &selfIp, const std::string &selfIpv6, const std::string &privKey, const std::string &pubKey, const std::string &psk, const string_array &dns, const std::string &mtu, const std::string &keepalive, const std::string &testUrl, const std::string &clientId, const tribool &udp, const std::string& underlying_proxy, const string_array &reserved, const string_array &peers, const std::string &dialer_proxy, tribool remote_dns_resolve)
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
    if(!reserved.empty())
        node.Reserved = reserved;
    if(!peers.empty())
        node.Peers = peers;
    if(!dialer_proxy.empty())
        node.DialerProxy = dialer_proxy;
    if(!remote_dns_resolve.is_undef())
        node.RemoteDnsResolve = remote_dns_resolve;
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
        node.AlpnList = alpnList;
    else if (!alpn.empty())
        node.Alpn = alpn;
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
            node.UpSpeed = to_int(up);
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
            node.DownSpeed = to_int(down);
    }
    node.Ports = ports;
    node.Password = password;
    node.Auth = auth;
    if(node.Password.empty() && !node.Auth.empty())
        node.Password = node.Auth;
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
        node.EchEnable = tribool(ech_enable);
    if(!ech_config.empty())
        node.EchConfig = ech_config;
    if(!initial_stream_receive_window.empty())
        node.InitialStreamReceiveWindow = to_int(initial_stream_receive_window);
    if(!max_stream_receive_window.empty())
        node.MaxStreamReceiveWindow = to_int(max_stream_receive_window);
    if(!initial_connection_receive_window.empty())
        node.InitialConnectionReceiveWindow = to_int(initial_connection_receive_window);
    if(!max_connection_receive_window.empty())
        node.MaxConnectionReceiveWindow = to_int(max_connection_receive_window);
}

void masqueConstruct(Proxy &node, const std::string &group, const std::string &remarks,  const std::string &server, const std::string &port,  const std::string &private_key, const std::string &public_key,  const std::string &ip, const std::string &ipv6,  const std::string &mtu, const std::string &network, tribool udp,  const std::string &underlying_proxy,  const tribool &remote_dns_resolve,  const StringArray &dnsservers,  const std::string &congestion_controller)
{
    commonConstruct(node, ProxyType::Masque, group, remarks, server, port, udp, tribool(), tribool(), tribool(), underlying_proxy);
    node.TransferProtocol = network;
    node.PrivateKey = private_key;
    node.PublicKey = public_key;
    node.IP = ip;
    node.MasqueIPv6 = ipv6;
    if(!mtu.empty())
        node.Mtu = (uint16_t)std::stoi(mtu);
    node.RemoteDnsResolve = remote_dns_resolve;
    node.DnsServers = dnsservers;
    node.CongestionController = congestion_controller;
}

void TUICConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &uuid, const std::string &password, const std::string &ip, const std::string &heartbeat_interval, const std::string &alpn, const std::string &disable_sni, const std::string &reduce_rtt, const std::string &request_timeout, const std::string &udp_relay_mode, const std::string &congestion_controller, const std::string &max_udp_relay_packet_size, const std::string &max_open_streams, const std::string &sni, const std::string &fast_open, const std::string &token, const std::string &version, tribool tfo, tribool scv, const std::string &underlying_proxy, tribool udp_over_stream, int udp_over_stream_version)
{
    commonConstruct(node, ProxyType::TUIC, group, remarks, server, port, tribool(), tfo, scv, tribool(), underlying_proxy);
        node.Password = password;
        node.UUID = uuid;
        node.IP = ip;
        node.HeartbeatInterval = heartbeat_interval;
        if(!alpn.empty())
            node.Alpn = alpn;
        node.DisableSNI= disable_sni;
        node.ReduceRTT = reduce_rtt;
        node.RequestTimeout = to_int(request_timeout);
        node.UdpRelayMode = udp_relay_mode;
        node.CongestionController = congestion_controller;
        node.MaxUdpRelayPacketSize = to_int(max_udp_relay_packet_size);
        node.MaxOpenStreams =  to_int(max_open_streams);
        node.SNI = sni;
        node.FastOpen = tribool(fast_open);
        node.Token = token;
        node.TuicVersion = to_int(version, 0);
        node.UDPOverStream = udp_over_stream;
        node.UDPOverStreamVersion = udp_over_stream_version;
}

void anyTLSConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &sni, const std::vector<std::string> &alpnList, const std::string &fingerprint, const std::string &idle_session_check_interval, const std::string &idle_session_timeout, const std::string &min_idle_session, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, const std::string &padding_scheme, const std::string &ip_version)
{
    commonConstruct(node, ProxyType::AnyTLS, group, remarks, server, port, tribool(), tfo, scv, tls13, underlying_proxy);
        node.Password = password;
        node.SNI = sni;
        if(!alpnList.empty())
            node.AlpnList = alpnList;
        node.Fingerprint = fingerprint;
        node.IdleSessionCheckInterval = to_int(idle_session_check_interval);
        node.IdleSessionTimeout = to_int(idle_session_timeout);
        node.MinIdleSession = to_int(min_idle_session);
        if(!padding_scheme.empty())
            node.PaddingScheme = padding_scheme;
        if(!ip_version.empty())
            node.IPVersion = ip_version;
}

void sudokuConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &key, const std::string &aead, const std::string &padding_min, const std::string &padding_max, const std::string &ascii, const std::string &http_mask, const std::string &http_mask_mode, const std::string &http_mask_tls, const std::string &http_mask_host, const std::string &http_mask_multiplex, const std::string &enable_pure_downlink, const std::string &disable_http_mask, const std::string &path_root, const std::string &handshake_timeout, const std::string &custom_table, const std::vector<std::string> &custom_tables, const std::string &underlying_proxy)
{
    commonConstruct(node, ProxyType::Sudoku, group, remarks, server, port, tribool(), tribool(), tribool(), tribool(), underlying_proxy);
    node.Key = key;
    node.AEAD = aead;
    node.PaddingMin = to_int(padding_min);
    node.PaddingMax = to_int(padding_max);
    node.TableType = ascii;
    if(!http_mask.empty())
        node.HTTPMask = tribool(http_mask);
    if(!http_mask_mode.empty())
        node.HTTPMaskMode = http_mask_mode;
    if(!http_mask_tls.empty())
        node.HTTPMaskTLS = tribool(http_mask_tls);
    if(!http_mask_host.empty())
        node.HTTPMaskHost = http_mask_host;
    if(!http_mask_multiplex.empty())
        node.HTTPMaskMultiplex = http_mask_multiplex;
    if(!enable_pure_downlink.empty())
        node.EnablePureDownlink = tribool(enable_pure_downlink);
    if(!disable_http_mask.empty())
        node.DisableHTTPMask = tribool(disable_http_mask);
    if(!path_root.empty())
        node.PathRoot = path_root;
    if(!handshake_timeout.empty())
        node.HandshakeTimeout = to_int(handshake_timeout);
    if(!custom_table.empty())
        node.CustomTable = custom_table;
    if(!custom_tables.empty())
        node.CustomTables = custom_tables;
}

static std::string encodeHTTPHeaderMap(const YAML::Node &headers)
{
    if(!headers.IsDefined() || !headers.IsMap())
        return "";
    std::string encoded;
    for(const auto &header : headers)
    {
        const auto key = safe_as<std::string>(header.first);
        if(key.empty())
            continue;
        const auto &valueNode = header.second;
        if(valueNode.IsSequence())
        {
            for(const auto &item : valueNode)
            {
                const auto value = safe_as<std::string>(item);
                if(!encoded.empty())
                    encoded += ";";
                encoded += urlEncode(key) + "=" + urlEncode(value);
            }
            continue;
        }
        const auto value = safe_as<std::string>(valueNode);
        if(!encoded.empty())
            encoded += ";";
        encoded += urlEncode(key) + "=" + urlEncode(value);
    }
    return encoded;
}

void trusttunnelConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, const std::string &sni, const std::vector<std::string> &alpnList, const std::string &client_fingerprint, tribool health_check, tribool udp, tribool scv, tribool quic, const std::string &congestion_controller, const std::string &underlying_proxy)
{
    commonConstruct(node, ProxyType::TrustTunnel, group, remarks, server, port, udp, tribool(), scv, tribool(), underlying_proxy);
    node.Username = username;
    node.Password = password;
    if(!sni.empty())
        node.ServerName = sni;
    if(!alpnList.empty())
        node.AlpnList = alpnList;
    if(!client_fingerprint.empty())
        node.ClientFingerprint = client_fingerprint;
    node.HealthCheck = health_check;
    node.QUIC = quic;
    if(!congestion_controller.empty())
        node.CongestionController = congestion_controller;
}

void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &uuid, const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &public_key, const std::string &short_id, const std::string &fingerprint, const std::string &sni, const std::vector<std::string> &alpnList, const std::string &packet_encoding, const std::string &encryption, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, tribool v2ray_http_upgrade, tribool v2ray_http_upgrade_fast_open, tribool packet_addr, tribool xudp, const std::string &certificate, const std::string &certificate_key, const std::string &spider_x)
{
    commonConstruct(node, ProxyType::VLESS, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UUID = uuid;
    node.SNI = sni;
    node.TransferProtocol = net.empty() ? "tcp" : type == "http" ? "http" : net;
    node.EncryptMethod = cipher;
    node.Edge = edge;
    node.Flow = flow;
    node.Encryption = encryption;
    node.FakeType = type;
    node.TLSSecure = tls == "tls" || tls == "xtls" || tls == "reality";
    if(flow == "xtls-rprx-vision" || flow.find("vision") != std::string::npos)
        node.XTLS = 2;
    node.PublicKey = public_key;
    node.ShortID = short_id;
    node.SpiderX = spider_x;
    node.Fingerprint = fingerprint;
    if(node.ClientFingerprint.empty())
        node.ClientFingerprint = fingerprint;
    node.AlpnList = alpnList;
    node.PacketEncoding = packet_encoding;
    node.PacketAddr = packet_addr;
    node.XUDP = xudp;
    node.TLSStr = tls;
    node.V2rayHttpUpgrade = v2ray_http_upgrade;
    node.V2rayHttpUpgradeFastOpen = v2ray_http_upgrade_fast_open;
    if(!certificate.empty()) node.Certificate = certificate;
    if(!certificate_key.empty()) node.CertificateKey = certificate_key;
    node.Host = host;
    switch (hash_(net))
    {
        case "grpc"_hash:
            node.Host = host;
            node.GRPCMode = mode.empty() ? "gun" : mode;
            node.GrpcServiceName = path.empty() ? "/" : urlEncode(urlDecode(trim(path)));
            break;
        case "xhttp"_hash:
            node.Host = trim(host);
            node.Path = path.empty() ? "/" : trim(path);
            node.GRPCMode = trim(mode);
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

void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &port, const std::string &password, const std::string &host, const std::string &ports, const std::string &username, const std::string &multiplexing, const std::string &transfer_protocol, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy, const std::string &port_range, const std::string &handshake_mode, const std::string &traffic_pattern)
{
    commonConstruct(node, ProxyType::Mieru, group, remarks, host, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Host = trim(host);
    node.Password = password;
    node.Ports = ports;
    node.PortRange = port_range;
    node.HandshakeMode = handshake_mode;
    node.TransferProtocol = transfer_protocol.empty()? "TCP" : trim(transfer_protocol);
    node.Username = username;
    node.Multiplexing = multiplexing.empty() ? "MULTIPLEXING_LOW" : trim(multiplexing);
    node.TrafficPattern = traffic_pattern;
}

void explodeVmess(std::string vmess, Proxy &node)
{
    std::string version, ps, add, port, type, id, aid, net, path, host, tls, sni;
    std::string fingerprint, client_fingerprint, alpn, ip_version, packet_encoding;
    std::string ech_config, skip_cert_verify_str, udp_str, tfo_str, authenticated_length_str, global_padding_str, ech_enable_str;
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
    // Extended parameters
    GetMember(jsondata, "fp", fingerprint);
    if(fingerprint.empty())
        GetMember(jsondata, "fingerprint", fingerprint);
    GetMember(jsondata, "client-fingerprint", client_fingerprint);
    if(client_fingerprint.empty())
        GetMember(jsondata, "clientFingerprint", client_fingerprint);
    // skip-cert-verify / allowInsecure
    GetMember(jsondata, "skip-cert-verify", skip_cert_verify_str);
    if(skip_cert_verify_str.empty())
        GetMember(jsondata, "allowInsecure", skip_cert_verify_str);
    GetMember(jsondata, "alpn", alpn);
    GetMember(jsondata, "ip-version", ip_version);
    if(ip_version.empty())
        GetMember(jsondata, "ipVersion", ip_version);
    GetMember(jsondata, "packet-encoding", packet_encoding);
    if(packet_encoding.empty())
        GetMember(jsondata, "packetEncoding", packet_encoding);
    // Boolean flags
    GetMember(jsondata, "udp", udp_str);
    GetMember(jsondata, "tfo", tfo_str);
    GetMember(jsondata, "authenticated-length", authenticated_length_str);
    if(authenticated_length_str.empty())
        GetMember(jsondata, "authenticatedLength", authenticated_length_str);
    GetMember(jsondata, "global-padding", global_padding_str);
    if(global_padding_str.empty())
        GetMember(jsondata, "globalPadding", global_padding_str);
    // ECH
    GetMember(jsondata, "ech-enable", ech_enable_str);
    if(ech_enable_str.empty())
        GetMember(jsondata, "echEnable", ech_enable_str);
    GetMember(jsondata, "ech-config", ech_config);
    if(ech_config.empty())
        GetMember(jsondata, "echConfig", ech_config);
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
    // Parse alpn list
    std::vector<std::string> alpnList;
    if(!alpn.empty())
        alpnList.push_back(alpn);
    // Convert string booleans to tribool
    tribool udp = udp_str == "true" || udp_str == "1" ? tribool(true) : (udp_str == "false" || udp_str == "0" ? tribool(false) : tribool());
    tribool tfo = tfo_str == "true" || tfo_str == "1" ? tribool(true) : (tfo_str == "false" || tfo_str == "0" ? tribool(false) : tribool());
    tribool scv = skip_cert_verify_str == "true" || skip_cert_verify_str == "1" ? tribool(true) : (skip_cert_verify_str == "false" || skip_cert_verify_str == "0" ? tribool(false) : tribool());
    tribool auth_len = authenticated_length_str == "true" || authenticated_length_str == "1" ? tribool(true) : (authenticated_length_str == "false" || authenticated_length_str == "0" ? tribool(false) : tribool());
    tribool glob_pad = global_padding_str == "true" || global_padding_str == "1" ? tribool(true) : (global_padding_str == "false" || global_padding_str == "0" ? tribool(false) : tribool());
    tribool ech_enable = ech_enable_str == "true" || ech_enable_str == "1" ? tribool(true) : (ech_enable_str == "false" || ech_enable_str == "0" ? tribool(false) : tribool());

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, "auto", path, host, "", tls, sni, alpnList, udp, tfo, scv, tribool(), "", fingerprint, client_fingerprint);
    // Set additional fields directly on node
    if(!ip_version.empty())
        node.IPVersion = ip_version;
    if(!packet_encoding.empty())
        node.PacketEncoding = packet_encoding;
    if(!auth_len.is_undef())
        node.AuthenticatedLength = auth_len;
    if(!glob_pad.is_undef())
        node.GlobalPadding = glob_pad;
    if(!ech_enable.is_undef())
        node.EchEnable = ech_enable;
    if(!ech_config.empty())
        node.EchConfig = ech_config;
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
    regGetMatch(content, "((?i)wssettings)", 2, 0, &wsset);

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
    std::string ip_version, client_fingerprint;
    tribool udp, tfo, scv, udp_over_tcp;
    int udp_over_tcp_version = 0;
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
        if(!plugins.empty())
        {
            auto pluginpos = plugins.find(';');
            if(pluginpos == std::string::npos)
            {
                plugin = plugins;
                pluginopts.clear();
            }
            else
            {
                plugin = plugins.substr(0, pluginpos);
                pluginopts = plugins.substr(pluginpos + 1);
            }
        }
        group = getUrlArg(addition, "group");
        if(!group.empty())
            group = urlSafeBase64Decode(group);
        udp = tribool(getUrlArg(addition, "udp"));
        tfo = tribool(getUrlArg(addition, "tfo"));
        scv = tribool(getUrlArg(addition, "insecure"));
        if(scv.is_undef())
            scv = tribool(getUrlArg(addition, "allowInsecure"));
        udp_over_tcp = tribool(getUrlArg(addition, "udp-over-tcp"));
        if(udp_over_tcp.is_undef())
            udp_over_tcp = tribool(getUrlArg(addition, "uot"));
        udp_over_tcp_version = to_int(getUrlArg(addition, "udp-over-tcp-version"), 0);
        ip_version = getUrlArg(addition, "ip-version");
        client_fingerprint = getUrlArg(addition, "client-fingerprint");
        ss.erase(ss.find('?'));
    }
    if(strFind(ss, "@"))
    {
        if(regGetMatch(ss, "(\\S+?)@(\\S+):(\\d+)", 4, 0, &secret, &server, &port))
            return;
        std::string decoded_secret = urlSafeBase64Decode(secret);
        if(regGetMatch(decoded_secret, "(\\S+?):(\\S+)", 3, 0, &method, &password) != 0)
        {
            if(regGetMatch(secret, "(\\S+?):(\\S+)", 3, 0, &method, &password) != 0)
                return;
            method = urlDecode(method);
            password = urlDecode(password);
        }
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

    ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts, udp, tfo, scv, udp_over_tcp, "", client_fingerprint, udp_over_tcp_version);
    if(!ip_version.empty())
        node.IPVersion = ip_version;
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
    tribool udp, tfo, scv;
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

    host = urlDecode(getUrlArg(addition, "sni"));
    sni = urlDecode(getUrlArg(addition, "sni"));
    std::string tempHost = urlDecode(getUrlArg(addition, "host"));
    if(!tempHost.empty())
        host = tempHost;
    if(host.empty())
        host = sni;
    if(host.empty())
        host = urlDecode(getUrlArg(addition, "peer"));
    udp = getUrlArg(addition, "udp");
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

    trojanConstruct(node, group, remark, server, port, psk, network, host, path, fp, sni, alpnList, true, udp, tfo, scv);
}

void explodeWireguard(std::string wg, Proxy &node)
{
    if(startsWith(wg, "wg://"))
        wg = regReplace(wg, "wg://", "wireguard://");
    if(startsWith(wg, "wireguard://"))
        explodeStdWireguard(wg, node);
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

void explodeMasque(std::string masque, Proxy &node)
{
    masque = regReplace(masque, "(masque)://", "masque://");
    masque = regReplace(masque, "/\\?", "?", true, false);
    if(regMatch(masque, "masque://(.*?)[:](.*)"))
    {
        explodeStdMasque(masque, node);
        return;
    }
}

void explodeMierus(std::string mierus, Proxy &node)
{
    // Accept both official mierus:// simple links and legacy/standard mieru:// inputs.
    mierus = regReplace(mierus, "/\\?", "?", true, false);
    if(strFind(mierus, "mierus://"))
    {
        if(regMatch(mierus, "mierus://(.*?)@(.*)"))
        {
            explodeStdMieru(mierus.substr(9), node);
        }
        else
        {
            mierus = urlSafeBase64Decode(mierus.substr(9));
            explodeStdMieru(mierus, node);
        }
    }
    else if(strFind(mierus, "mieru://"))
    {
        if(regMatch(mierus, "mieru://(.*?)@(.*)"))
        {
            explodeStdMieru(mierus.substr(8), node);
        }
        else
        {
            mierus = urlSafeBase64Decode(mierus.substr(8));
            explodeStdMieru(mierus, node);
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
    std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux, pluginopts_version, pluginopts_password, client_fingerprint; //ss
    std::string protocol, protoparam, obfs, obfsparam; //ssr
    std::string key, aead, padding_min, padding_max, ascii, http_mask, http_mask_mode, http_mask_tls, http_mask_host, http_mask_multiplex, enable_pure_downlink, disable_http_mask, path_root, handshake_timeout, custom_table; // sudoku
    std::vector<std::string> custom_tables; // sudoku
    std::string fp, flow, mode, clientFingerprint; //trojan
    std::string user, ip_version; //socks
    std::string ip, ipv6, private_key, public_key, mtu, keepalive, wg_allowed_ips; //wireguard
    std::vector<std::string> wg_reserved, wg_peers; // wireguard
    std::string ports, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, /* obfs, sni,*/ fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpn; //hysteria
    std::string obfs_password, cwnd, ech_enable, ech_config, initial_stream_receive_window, max_stream_receive_window, initial_connection_receive_window, max_connection_receive_window; //hysteria2
    std::string token, uuid, heartbeat_interval, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, fast_open, version;   //tuic
    std::string idle_session_check_interval, idle_session_timeout, min_idle_session; // anytls
    std::string multiplexing, transfer_protocol, port_range, handshake_mode, traffic_pattern; // mieru
    std::string short_id, packet_encoding, encryption, spider_x; // vless
    int udp_over_tcp_version = 0, udp_over_stream_version = 0; // version variables
    string_array dns_server;
    tribool udp, tfo, scv, udp_over_tcp;
    tribool v2ray_http_upgrade, v2ray_http_upgrade_fast_open, vless_udp, packet_addr_enabled, xudp_enabled, udp_over_stream, flow_show, remote_dns_resolve;
    tribool health_check, quic; // trusttunnel
    std::vector<std::string> alpnList;
    Node singleproxy;
    uint32_t index = nodes.size();
    const std::string section = yamlnode["proxies"].IsDefined() ? "proxies" : "Proxy";

    #define RESET_VARS() proxytype.clear(); ps.clear(); server.clear(); port.clear(); cipher.clear(); group.clear(); password.clear(); underlying_proxy.clear(); type.clear(); id.clear(); aid.clear(); net.clear(); path.clear(); host.clear(); edge.clear(); tls.clear(); sni.clear(); plugin.clear(); pluginopts.clear(); pluginopts_mode.clear(); pluginopts_host.clear(); pluginopts_mux.clear(); pluginopts_version.clear(); pluginopts_password.clear(); protocol.clear(); protoparam.clear(); obfs.clear(); obfsparam.clear(); fp.clear(); flow.clear(); mode.clear(); clientFingerprint.clear(); user.clear(); ip_version.clear(); ip.clear(); ipv6.clear(); private_key.clear(); public_key.clear(); mtu.clear(); keepalive.clear(); wg_allowed_ips.clear(); ports.clear(); obfs_protocol.clear(); up.clear(); up_speed.clear(); down.clear(); down_speed.clear(); auth.clear(); auth_str.clear(); fingerprint.clear(); ca.clear(); ca_str.clear(); recv_window_conn.clear(); recv_window.clear(); disable_mtu_discovery.clear(); hop_interval.clear(); alpn.clear(); obfs_password.clear(); cwnd.clear(); ech_enable.clear(); ech_config.clear(); initial_stream_receive_window.clear(); max_stream_receive_window.clear(); initial_connection_receive_window.clear(); max_connection_receive_window.clear(); token.clear(); uuid.clear(); heartbeat_interval.clear(); disable_sni.clear(); reduce_rtt.clear(); request_timeout.clear(); udp_relay_mode.clear(); congestion_controller.clear(); max_udp_relay_packet_size.clear(); max_open_streams.clear(); fast_open.clear(); version.clear(); idle_session_check_interval.clear(); idle_session_timeout.clear(); min_idle_session.clear(); multiplexing.clear(); transfer_protocol.clear(); short_id.clear(); packet_encoding.clear(); spider_x.clear(); dns_server.clear(); wg_reserved.clear(); wg_peers.clear(); udp = tribool(); tfo = tribool(); scv = tribool(); udp_over_tcp = tribool(); v2ray_http_upgrade = tribool(); v2ray_http_upgrade_fast_open = tribool(); vless_udp = tribool(); flow_show = tribool(); remote_dns_resolve = tribool(); health_check = tribool(); quic = tribool(); encryption.clear(); alpnList.clear(); enable_pure_downlink.clear(); disable_http_mask.clear(); path_root.clear(); handshake_timeout.clear(); http_mask_mode.clear(); http_mask_tls.clear(); http_mask_host.clear(); http_mask_multiplex.clear(); custom_table.clear(); custom_tables.clear();

    for(uint32_t i = 0; i < yamlnode[section].size(); i++)
    {
        Proxy node;
        RESET_VARS();

        singleproxy = yamlnode[section][i];
        singleproxy["type"] >>= proxytype;
        singleproxy["name"] >>= ps;
        singleproxy["server"] >>= server;
        singleproxy["port"] >>= port;
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
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= ca;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= private_key;
            switch(hash_(net))
            {
            case "http"_hash:
                if(singleproxy["http-opts"]["method"].IsDefined())
                    singleproxy["http-opts"]["method"] >>= node.HTTPOptsMethod;
                if(singleproxy["http-opts"]["path"].IsDefined() && singleproxy["http-opts"]["path"].IsSequence())
                {
                    for(const auto &item : singleproxy["http-opts"]["path"])
                        node.HTTPOptsPaths.push_back(safe_as<std::string>(item));
                    if(!node.HTTPOptsPaths.empty())
                        path = node.HTTPOptsPaths[0];
                }
                else
                {
                    singleproxy["http-opts"]["path"][0] >>= path;
                    if(!path.empty())
                        node.HTTPOptsPaths.push_back(path);
                }
                if(singleproxy["http-opts"]["headers"].IsDefined() && singleproxy["http-opts"]["headers"].IsMap())
                {
                    node.HTTPOptsHeaders = encodeHTTPHeaderMap(singleproxy["http-opts"]["headers"]);
                }
                singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                edge.clear();
                break;
            case "ws"_hash:
                if(singleproxy["ws-opts"].IsDefined())
                {
                    path = singleproxy["ws-opts"]["path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-opts"]["path"]) : "/";
                    if(singleproxy["ws-opts"]["headers"].IsDefined())
                    {
                        auto headers = singleproxy["ws-opts"]["headers"];
                        headers["Host"] >>= host;
                        headers["Edge"] >>= edge;
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
                    if(singleproxy["ws-opts"]["headers"].IsDefined() && singleproxy["ws-opts"]["headers"].IsMap())
                        node.WsHeadersMap = encodeHTTPHeaderMap(singleproxy["ws-opts"]["headers"]);
                    if(singleproxy["ws-opts"]["early-data-header-name"].IsDefined())
                        node.WsEarlyDataHeaderName = safe_as<std::string>(singleproxy["ws-opts"]["early-data-header-name"]);
                    if(singleproxy["ws-opts"]["max-early-data"].IsDefined())
                        node.WsMaxEarlyData = to_int(safe_as<std::string>(singleproxy["ws-opts"]["max-early-data"]), 0);
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
                if(singleproxy["h2-opts"]["host"].IsDefined() && singleproxy["h2-opts"]["host"].IsSequence())
                {
                    for(const auto &item : singleproxy["h2-opts"]["host"])
                        node.H2Hosts.push_back(safe_as<std::string>(item));
                    if(!node.H2Hosts.empty())
                        host = node.H2Hosts[0];
                }
                edge.clear();
                if(singleproxy["ech-opts"].IsDefined())
                {
                    if(singleproxy["ech-opts"]["enable"].IsDefined())
                        node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                    if(singleproxy["ech-opts"]["config"].IsDefined())
                        node.EchConfig = safe_as<std::string>(singleproxy["ech-opts"]["config"]);
                    if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                        singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
                }
                break;
            case "grpc"_hash:
                singleproxy["servername"] >>= host;
                if(singleproxy["grpc-opts"].IsDefined())
                    singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                else if(singleproxy["grpc-service-name"].IsDefined())
                    singleproxy["grpc-service-name"] >>= path;
                if(!path.empty())
                    node.GrpcServiceName = path;
                if(singleproxy["grpc-opts"]["grpc-user-agent"].IsDefined())
                    singleproxy["grpc-opts"]["grpc-user-agent"] >>= node.GrpcUserAgent;
                if(singleproxy["grpc-opts"]["ping-interval"].IsDefined())
                    node.GrpcPingInterval = safe_as<uint32_t>(singleproxy["grpc-opts"]["ping-interval"]);
                if(singleproxy["grpc-opts"]["max-connections"].IsDefined())
                    node.GrpcMaxConnections = safe_as<uint32_t>(singleproxy["grpc-opts"]["max-connections"]);
                if(singleproxy["grpc-opts"]["min-streams"].IsDefined())
                    node.GrpcMinStreams = safe_as<uint32_t>(singleproxy["grpc-opts"]["min-streams"]);
                if(singleproxy["grpc-opts"]["max-streams"].IsDefined())
                    node.GrpcMaxStreams = safe_as<uint32_t>(singleproxy["grpc-opts"]["max-streams"]);
                edge.clear();
                if(singleproxy["ech-opts"].IsDefined())
                {
                    if(singleproxy["ech-opts"]["enable"].IsDefined())
                        node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                    if(singleproxy["ech-opts"]["config"].IsDefined())
                        node.EchConfig = safe_as<std::string>(singleproxy["ech-opts"]["config"]);
                    if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                        singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
                }
                break;
            case "quic"_hash:
                singleproxy["quic-opts"]["security"] >>= host;
                singleproxy["quic-opts"]["key"] >>= path;
                break;
            }
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    node.EchConfig = safe_as<std::string>(singleproxy["ech-opts"]["config"]);
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
            }
            tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
            singleproxy["alpn"] >>= alpnList;
            if(singleproxy["authenticated-length"].IsDefined())
                node.AuthenticatedLength = safe_as<bool>(singleproxy["authenticated-length"]);
            if(singleproxy["global-padding"].IsDefined())
                node.GlobalPadding = safe_as<bool>(singleproxy["global-padding"]);
            if(singleproxy["packet-encoding"].IsDefined())
                singleproxy["packet-encoding"] >>= node.PacketEncoding;
            if(singleproxy["packet-addr"].IsDefined())
                packet_addr_enabled = safe_as<bool>(singleproxy["packet-addr"]);
            if(singleproxy["xudp"].IsDefined())
                xudp_enabled = safe_as<bool>(singleproxy["xudp"]);
            if(singleproxy["reality-opts"].IsDefined())
            {
                if(singleproxy["reality-opts"]["public-key"].IsDefined())
                    singleproxy["reality-opts"]["public-key"] >>= node.PublicKey;
                if(singleproxy["reality-opts"]["short-id"].IsDefined())
                    singleproxy["reality-opts"]["short-id"] >>= node.ShortID;
                if(singleproxy["reality-opts"]["support-x25519mlkem768"].IsDefined())
                    node.SupportX25519Mlkem768 = safe_as<bool>(singleproxy["reality-opts"]["support-x25519mlkem768"]);
                if(singleproxy["reality-opts"]["servername"].IsDefined())
                    singleproxy["reality-opts"]["servername"] >>= node.ServerName;
                if(singleproxy["reality-opts"]["spiderX"].IsDefined())
                    singleproxy["reality-opts"]["spiderX"] >>= node.SpiderX;
                else if(singleproxy["reality-opts"]["spider-x"].IsDefined())
                    singleproxy["reality-opts"]["spider-x"] >>= node.SpiderX;
                else if(singleproxy["reality-opts"]["spx"].IsDefined())
                    singleproxy["reality-opts"]["spx"] >>= node.SpiderX;
            }

            vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, alpnList, udp, tfo, scv, tribool(), underlying_proxy, fingerprint, fp, v2ray_http_upgrade, v2ray_http_upgrade_fast_open, ca, private_key);
            node.PacketAddr = packet_addr_enabled;
            node.XUDP = xudp_enabled;
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
                        pluginopts_mux = safe_as<bool>(singleproxy["plugin-opts"]["mux"]) ? "4" : "";
                        std::string fingerprint, server_name, certificate, private_key;
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
                        if(singleproxy["plugin-opts"]["certificate"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["certificate"] >>= certificate;
                            if(!certificate.empty())
                            {
                                node.Certificate = certificate;
                                pluginopts += "certificate=" + certificate + ";";
                            }
                        }
                        if(singleproxy["plugin-opts"]["private-key"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["private-key"] >>= private_key;
                            if(!private_key.empty())
                            {
                                node.CertificateKey = private_key;
                                pluginopts += "private-key=" + private_key + ";";
                            }
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
                            if(singleproxy["plugin-opts"]["ech-opts"]["query-server-name"].IsDefined())
                            {
                                std::string query_server_name = safe_as<std::string>(singleproxy["plugin-opts"]["ech-opts"]["query-server-name"]);
                                node.EchQueryServerName = query_server_name;
                                pluginopts += "ech-query-server-name=" + query_server_name + ";";
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
                        std::string fingerprint, server_name, certificate, private_key;
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
                        if(singleproxy["plugin-opts"]["certificate"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["certificate"] >>= certificate;
                            if(!certificate.empty())
                            {
                                node.Certificate = certificate;
                                pluginopts += "certificate=" + certificate + ";";
                            }
                        }
                        if(singleproxy["plugin-opts"]["private-key"].IsDefined())
                        {
                            singleproxy["plugin-opts"]["private-key"] >>= private_key;
                            if(!private_key.empty())
                            {
                                node.CertificateKey = private_key;
                                pluginopts += "private-key=" + private_key + ";";
                            }
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
                case "kcptun"_hash:
                    plugin = "kcptun";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        if(singleproxy["plugin-opts"]["key"].IsDefined()) singleproxy["plugin-opts"]["key"] >>= node.KCPKey;
                        if(singleproxy["plugin-opts"]["crypt"].IsDefined()) singleproxy["plugin-opts"]["crypt"] >>= node.KCPCrypt;
                        if(singleproxy["plugin-opts"]["mode"].IsDefined()) singleproxy["plugin-opts"]["mode"] >>= node.KCPMode;
                        if(singleproxy["plugin-opts"]["conn"].IsDefined()) node.KCPConn = safe_as<int>(singleproxy["plugin-opts"]["conn"]);
                        if(singleproxy["plugin-opts"]["autoexpire"].IsDefined()) node.KCPAutoExpire = safe_as<int>(singleproxy["plugin-opts"]["autoexpire"]);
                        if(singleproxy["plugin-opts"]["scavengettl"].IsDefined()) node.KCPScavengeTTL = safe_as<int>(singleproxy["plugin-opts"]["scavengettl"]);
                        if(singleproxy["plugin-opts"]["mtu"].IsDefined()) node.KCPMtu = safe_as<int>(singleproxy["plugin-opts"]["mtu"]);
                        if(singleproxy["plugin-opts"]["ratelimit"].IsDefined()) node.KCPRateLimit = safe_as<int>(singleproxy["plugin-opts"]["ratelimit"]);
                        if(singleproxy["plugin-opts"]["sndwnd"].IsDefined()) node.KCPSndWnd = safe_as<int>(singleproxy["plugin-opts"]["sndwnd"]);
                        if(singleproxy["plugin-opts"]["rcvwnd"].IsDefined()) node.KCPRcvWnd = safe_as<int>(singleproxy["plugin-opts"]["rcvwnd"]);
                        if(singleproxy["plugin-opts"]["datashard"].IsDefined()) node.KCPDataShard = safe_as<int>(singleproxy["plugin-opts"]["datashard"]);
                        if(singleproxy["plugin-opts"]["parityshard"].IsDefined()) node.KCPParityShard = safe_as<int>(singleproxy["plugin-opts"]["parityshard"]);
                        if(singleproxy["plugin-opts"]["dscp"].IsDefined()) node.KCPDSCP = safe_as<int>(singleproxy["plugin-opts"]["dscp"]);
                        if(singleproxy["plugin-opts"]["nocomp"].IsDefined()) node.KCPNoComp = safe_as<bool>(singleproxy["plugin-opts"]["nocomp"]);
                        if(singleproxy["plugin-opts"]["acknodelay"].IsDefined()) node.KCPAckNoDelay = safe_as<bool>(singleproxy["plugin-opts"]["acknodelay"]);
                        if(singleproxy["plugin-opts"]["nodelay"].IsDefined()) node.KCPNodelay = safe_as<int>(singleproxy["plugin-opts"]["nodelay"]);
                        if(singleproxy["plugin-opts"]["interval"].IsDefined()) node.KCPInterval = safe_as<int>(singleproxy["plugin-opts"]["interval"]);
                        if(singleproxy["plugin-opts"]["resend"].IsDefined()) node.KCPResend = safe_as<int>(singleproxy["plugin-opts"]["resend"]);
                        if(singleproxy["plugin-opts"]["sockbuf"].IsDefined()) node.KCPSockbuf = safe_as<int>(singleproxy["plugin-opts"]["sockbuf"]);
                        if(singleproxy["plugin-opts"]["smuxver"].IsDefined()) node.KCPSmuxver = safe_as<int>(singleproxy["plugin-opts"]["smuxver"]);
                        if(singleproxy["plugin-opts"]["smuxbuf"].IsDefined()) node.KCPSmuxbuf = safe_as<int>(singleproxy["plugin-opts"]["smuxbuf"]);
                        if(singleproxy["plugin-opts"]["framesize"].IsDefined()) node.KCPFramesize = safe_as<int>(singleproxy["plugin-opts"]["framesize"]);
                        if(singleproxy["plugin-opts"]["streambuf"].IsDefined()) node.KCPStreambuf = safe_as<int>(singleproxy["plugin-opts"]["streambuf"]);
                        if(singleproxy["plugin-opts"]["keepalive"].IsDefined()) node.KCPKeepalive = safe_as<int>(singleproxy["plugin-opts"]["keepalive"]);
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
                pluginopts = "mode=" + pluginopts_mode + ";" + tls;
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

            if(singleproxy["udp"].IsDefined())
                udp = safe_as<bool>(singleproxy["udp"]);
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
            if(singleproxy["udp-over-tcp"].IsDefined())
                udp_over_tcp = safe_as<bool>(singleproxy["udp-over-tcp"]);
            if(singleproxy["client-fingerprint"].IsDefined())
                singleproxy["client-fingerprint"] >>= client_fingerprint;
            if(singleproxy["udp-over-tcp-version"].IsDefined())
                udp_over_tcp_version = safe_as<int>(singleproxy["udp-over-tcp-version"]);
            if(singleproxy["smux"].IsDefined())
            {
                if(singleproxy["smux"]["enabled"].IsDefined())
                    node.SmuxEnabled = safe_as<bool>(singleproxy["smux"]["enabled"]);
                if(singleproxy["smux"]["protocol"].IsDefined())
                    singleproxy["smux"]["protocol"] >>= node.SmuxProtocol;
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

            ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv, udp_over_tcp, underlying_proxy, client_fingerprint, udp_over_tcp_version);
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
            if(singleproxy["client-fingerprint"].IsDefined())
                singleproxy["client-fingerprint"] >>= client_fingerprint;
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= ca;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= private_key;
            if(singleproxy["ip-version"].IsDefined())
                singleproxy["ip-version"] >>= ip_version;

            socksConstruct(node, group, ps, server, port, user, password, udp, tfo, scv, underlying_proxy);
            node.TLSSecure = tls == "true";
            node.Fingerprint = fingerprint;
            node.ClientFingerprint = client_fingerprint;
            node.Certificate = ca;
            node.CertificateKey = private_key;
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
            if(singleproxy["client-fingerprint"].IsDefined())
                singleproxy["client-fingerprint"] >>= client_fingerprint;
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= ca;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= private_key;
            if(singleproxy["ip-version"].IsDefined())
                singleproxy["ip-version"] >>= ip_version;

            httpConstruct(node, group, ps, server, port, user, password, tls == "true", tfo, scv, tribool(), underlying_proxy);
            node.ServerName = sni;
            node.Fingerprint = fingerprint;
            node.ClientFingerprint = client_fingerprint;
            node.Certificate = ca;
            node.CertificateKey = private_key;
            node.IPVersion = ip_version;
            break;
        case "trojan"_hash:
            group = TROJAN_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= sni;
            singleproxy["network"] >>= net;
            if(singleproxy["fingerprint"].IsDefined())
                singleproxy["fingerprint"] >>= fingerprint;
            switch(hash_(net))
            {
            case "grpc"_hash:
                if(singleproxy["grpc-opts"].IsDefined())
                    singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                else if(singleproxy["grpc-service-name"].IsDefined())
                    singleproxy["grpc-service-name"] >>= path;
                if(singleproxy["grpc-opts"]["grpc-user-agent"].IsDefined())
                    singleproxy["grpc-opts"]["grpc-user-agent"] >>= node.GrpcUserAgent;
                if(singleproxy["grpc-opts"]["ping-interval"].IsDefined())
                    node.GrpcPingInterval = safe_as<uint32_t>(singleproxy["grpc-opts"]["ping-interval"]);
                if(singleproxy["grpc-opts"]["max-connections"].IsDefined())
                    node.GrpcMaxConnections = safe_as<uint32_t>(singleproxy["grpc-opts"]["max-connections"]);
                if(singleproxy["grpc-opts"]["min-streams"].IsDefined())
                    node.GrpcMinStreams = safe_as<uint32_t>(singleproxy["grpc-opts"]["min-streams"]);
                if(singleproxy["grpc-opts"]["max-streams"].IsDefined())
                    node.GrpcMaxStreams = safe_as<uint32_t>(singleproxy["grpc-opts"]["max-streams"]);
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
                    if(singleproxy["ws-opts"]["headers"].IsDefined() && singleproxy["ws-opts"]["headers"].IsMap())
                        node.WsHeadersMap = encodeHTTPHeaderMap(singleproxy["ws-opts"]["headers"]);
                    if(singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined())
                        v2ray_http_upgrade = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                    if(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"].IsDefined())
                        v2ray_http_upgrade_fast_open = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"]);
                    if(singleproxy["ws-opts"]["early-data-header-name"].IsDefined())
                        node.WsEarlyDataHeaderName = safe_as<std::string>(singleproxy["ws-opts"]["early-data-header-name"]);
                    if(singleproxy["ws-opts"]["max-early-data"].IsDefined())
                        node.WsMaxEarlyData = to_int(safe_as<std::string>(singleproxy["ws-opts"]["max-early-data"]), 0);
                }
                else
                {
                    path = singleproxy["ws-path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-path"]) : "/";
                    singleproxy["ws-headers"]["Host"] >>= host;
                    singleproxy["ws-headers"]["Edge"] >>= edge;
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
            if(singleproxy["ss-opts"].IsDefined())
            {
                if(singleproxy["ss-opts"]["enabled"].IsDefined())
                    node.TrojanSSOpts = safe_as<bool>(singleproxy["ss-opts"]["enabled"]);
                if(singleproxy["ss-opts"]["method"].IsDefined())
                    singleproxy["ss-opts"]["method"] >>= node.TrojanSSMethod;
                if(singleproxy["ss-opts"]["password"].IsDefined())
                    singleproxy["ss-opts"]["password"] >>= node.TrojanSSPassword;
            }
            if(singleproxy["flow"].IsDefined())
                singleproxy["flow"] >>= flow;
            if(singleproxy["flow-show"].IsDefined())
                flow_show = safe_as<bool>(singleproxy["flow-show"]);
             if(singleproxy["reality-opts"].IsDefined())
            {
                if(singleproxy["reality-opts"]["public-key"].IsDefined())
                    singleproxy["reality-opts"]["public-key"] >>= node.PublicKey;
                if(singleproxy["reality-opts"]["short-id"].IsDefined())
                    singleproxy["reality-opts"]["short-id"] >>= node.ShortID;
                if(singleproxy["reality-opts"]["support-x25519mlkem768"].IsDefined())
                    node.SupportX25519Mlkem768 = safe_as<bool>(singleproxy["reality-opts"]["support-x25519mlkem768"]);
                if(singleproxy["reality-opts"]["servername"].IsDefined())
                    singleproxy["reality-opts"]["servername"] >>= node.ServerName;
                if(singleproxy["reality-opts"]["spiderX"].IsDefined())
                    singleproxy["reality-opts"]["spiderX"] >>= node.SpiderX;
                else if(singleproxy["reality-opts"]["spider-x"].IsDefined())
                    singleproxy["reality-opts"]["spider-x"] >>= node.SpiderX;
                else if(singleproxy["reality-opts"]["spx"].IsDefined())
                    singleproxy["reality-opts"]["spx"] >>= node.SpiderX;
            }

            trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList, true, udp, tfo, scv, tribool(), underlying_proxy, v2ray_http_upgrade, v2ray_http_upgrade_fast_open, flow, flow_show, "", "");
            if(!fingerprint.empty())
                node.Fingerprint = fingerprint;
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= node.Certificate;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= node.CertificateKey;
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= node.EchConfig;
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
            }
            break;
        case "snell"_hash:
            group = SNELL_DEFAULT_GROUP;
            singleproxy["psk"] >>= password;
            if(password.empty() && singleproxy["password"].IsDefined())
                singleproxy["password"] >>= password;
            if(singleproxy["obfs-opts"].IsDefined())
            {
                singleproxy["obfs-opts"]["mode"] >>= obfs;
                singleproxy["obfs-opts"]["host"] >>= host;
            }
            if(obfs.empty() && singleproxy["obfs"].IsDefined())
                singleproxy["obfs"] >>= obfs;
            if(host.empty() && singleproxy["host"].IsDefined())
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
            if(singleproxy["pre-shared-key"].IsDefined())
                singleproxy["pre-shared-key"] >>= password;
            else
                singleproxy["preshared-key"] >>= password;
            singleproxy["ip"] >>= ip;
            singleproxy["ipv6"] >>= ipv6;
            singleproxy["allowed-ips"] >>= wg_allowed_ips;
            singleproxy["reserved"] >>= wg_reserved;
            singleproxy["peers"] >>= wg_peers;
            singleproxy["dialer-proxy"] >>= underlying_proxy;
            if(singleproxy["persistent-keepalive"].IsDefined())
                singleproxy["persistent-keepalive"] >>= keepalive;
            else
                singleproxy["keepalive"] >>= keepalive;
            if(singleproxy["remote-dns-resolve"].IsDefined())
                remote_dns_resolve = safe_as<bool>(singleproxy["remote-dns-resolve"]);
             if(singleproxy["amnezia-wg-option"].IsDefined())
            {
                auto amnezia = singleproxy["amnezia-wg-option"];
                if(amnezia["jc"].IsDefined()) amnezia["jc"] >>= node.AmneziaJC;
                if(amnezia["jmin"].IsDefined()) amnezia["jmin"] >>= node.AmneziaJMin;
                if(amnezia["jmax"].IsDefined()) amnezia["jmax"] >>= node.AmneziaJMax;
                if(amnezia["s1"].IsDefined()) amnezia["s1"] >>= node.AmneziaS1;
                if(amnezia["s2"].IsDefined()) amnezia["s2"] >>= node.AmneziaS2;
                if(amnezia["s3"].IsDefined()) amnezia["s3"] >>= node.AmneziaS3;
                if(amnezia["s4"].IsDefined()) amnezia["s4"] >>= node.AmneziaS4;
                if(amnezia["h1"].IsDefined()) amnezia["h1"] >>= node.AmneziaH1;
                if(amnezia["h2"].IsDefined()) amnezia["h2"] >>= node.AmneziaH2;
                if(amnezia["h3"].IsDefined()) amnezia["h3"] >>= node.AmneziaH3;
                if(amnezia["h4"].IsDefined()) amnezia["h4"] >>= node.AmneziaH4;
                if(amnezia["i1"].IsDefined()) amnezia["i1"] >>= node.AmneziaI1;
                if(amnezia["i2"].IsDefined()) amnezia["i2"] >>= node.AmneziaI2;
                if(amnezia["i3"].IsDefined()) amnezia["i3"] >>= node.AmneziaI3;
                if(amnezia["i4"].IsDefined()) amnezia["i4"] >>= node.AmneziaI4;
                if(amnezia["i5"].IsDefined()) amnezia["i5"] >>= node.AmneziaI5;
                if(amnezia["j1"].IsDefined()) amnezia["j1"] >>= node.AmneziaJ1;
                if(amnezia["j2"].IsDefined()) amnezia["j2"] >>= node.AmneziaJ2;
                if(amnezia["j3"].IsDefined()) amnezia["j3"] >>= node.AmneziaJ3;
                if(amnezia["itime"].IsDefined()) amnezia["itime"] >>= node.AmneziaItime;
            }

            wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password, dns_server, mtu, keepalive, "", "", udp, underlying_proxy, wg_reserved, wg_peers, "", remote_dns_resolve);
            if(!wg_allowed_ips.empty())
                node.AllowedIPs = wg_allowed_ips;
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
            if(auth_str.empty())
                singleproxy["auth_str"] >>= auth_str;
            singleproxy["obfs"] >>= obfs;
            singleproxy["sni"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            singleproxy["alpn"] >>= alpnList;
            singleproxy["ca"] >>= ca;
            singleproxy["ca-str"] >>= ca_str;
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= node.Certificate;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= node.CertificateKey;
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= node.EchConfig;
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
            }
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
            if(singleproxy["bbr-profile"].IsDefined())
                singleproxy["bbr-profile"] >>= node.BBRProfile;
            else if(singleproxy["bbrProfile"].IsDefined())
                singleproxy["bbrProfile"] >>= node.BBRProfile;
            singleproxy["sni"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            singleproxy["ca"] >>= ca;
            singleproxy["ca-str"] >>= ca_str;
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= node.Certificate;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= node.CertificateKey;
            singleproxy["cwnd"] >>= cwnd;
            singleproxy["hop-interval"] >>= hop_interval;
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    ech_enable = safe_as<std::string>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= ech_config;
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
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
            sni = singleproxy["sni"].IsDefined() ? safe_as<std::string>(singleproxy["sni"]) : safe_as<std::string>(singleproxy["servername"]);
            net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
            singleproxy["alpn"] >>= alpnList;
            singleproxy["client-fingerprint"] >>= fp;
            singleproxy["fingerprint"] >>= fingerprint;
            singleproxy["flow"] >>= flow;
            if(singleproxy["flow-show"].IsDefined())
                flow_show = safe_as<bool>(singleproxy["flow-show"]);
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= ca;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= private_key;
            switch(hash_(net))
            {
                case "tcp"_hash:
                case "http"_hash:
                    if(singleproxy["http-opts"].IsDefined())
                    {
                        if(singleproxy["http-opts"]["method"].IsDefined())
                            singleproxy["http-opts"]["method"] >>= node.HTTPOptsMethod;
                        if(singleproxy["http-opts"]["path"].IsSequence() && singleproxy["http-opts"]["path"].size() > 0)
                        {
                            for(const auto &item : singleproxy["http-opts"]["path"])
                                node.HTTPOptsPaths.push_back(safe_as<std::string>(item));
                            path = node.HTTPOptsPaths[0];
                        }
                        if(singleproxy["http-opts"]["headers"].IsDefined() && singleproxy["http-opts"]["headers"]["Host"].IsSequence() && singleproxy["http-opts"]["headers"]["Host"].size() > 0)
                            singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                        if(singleproxy["http-opts"]["headers"].IsDefined() && singleproxy["http-opts"]["headers"].IsMap())
                            node.HTTPOptsHeaders = encodeHTTPHeaderMap(singleproxy["http-opts"]["headers"]);
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
                        }
                        if(singleproxy["ws-opts"]["early-data-header-name"].IsDefined())
                            node.WsEarlyDataHeaderName = safe_as<std::string>(singleproxy["ws-opts"]["early-data-header-name"]);
                        if(singleproxy["ws-opts"]["max-early-data"].IsDefined())
                            node.WsMaxEarlyData = to_int(safe_as<std::string>(singleproxy["ws-opts"]["max-early-data"]), 0);
                        if(singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined())
                            v2ray_http_upgrade = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                        if(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"].IsDefined())
                            v2ray_http_upgrade_fast_open = safe_as<bool>(singleproxy["ws-opts"]["v2ray-http-upgrade-fast-open"]);
                        if(singleproxy["ws-opts"]["headers"].IsDefined() && singleproxy["ws-opts"]["headers"].IsMap())
                            node.WsHeadersMap = encodeHTTPHeaderMap(singleproxy["ws-opts"]["headers"]);
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
                    {
                        for(const auto &item : singleproxy["h2-opts"]["host"])
                            node.H2Hosts.push_back(safe_as<std::string>(item));
                        host = node.H2Hosts[0];
                    }
                    edge.clear();
                    break;
                case "xhttp"_hash:
                    if(singleproxy["xhttp-opts"].IsDefined())
                    {
                        if(singleproxy["xhttp-opts"]["path"].IsDefined())
                            singleproxy["xhttp-opts"]["path"] >>= path;
                        else
                            path = "/";

                        if(singleproxy["xhttp-opts"]["host"].IsDefined())
                            singleproxy["xhttp-opts"]["host"] >>= host;
                        else if(singleproxy["xhttp-opts"]["headers"].IsDefined() && singleproxy["xhttp-opts"]["headers"]["Host"].IsDefined())
                            singleproxy["xhttp-opts"]["headers"]["Host"] >>= host;

                        if(singleproxy["xhttp-opts"]["headers"].IsDefined() && singleproxy["xhttp-opts"]["headers"].IsMap())
                            node.XHTTPHeaders = encodeHTTPHeaderMap(singleproxy["xhttp-opts"]["headers"]);

                        if(singleproxy["xhttp-opts"]["mode"].IsDefined())
                            singleproxy["xhttp-opts"]["mode"] >>= mode;

                        if(singleproxy["xhttp-opts"]["no-grpc-header"].IsDefined())
                            node.XHTTPNoGRPCHeader = safe_as<bool>(singleproxy["xhttp-opts"]["no-grpc-header"]);

                        if(singleproxy["xhttp-opts"]["x-padding-bytes"].IsDefined())
                            singleproxy["xhttp-opts"]["x-padding-bytes"] >>= node.XHTTPXPaddingBytes;
                        if(singleproxy["xhttp-opts"]["sc-max-each-post-bytes"].IsDefined())
                            singleproxy["xhttp-opts"]["sc-max-each-post-bytes"] >>= node.XHTTPScMaxEachPostBytes;
                        else if(singleproxy["xhttp-opts"]["scMaxEachPostBytes"].IsDefined())
                            singleproxy["xhttp-opts"]["scMaxEachPostBytes"] >>= node.XHTTPScMaxEachPostBytes;
                        if(singleproxy["xhttp-opts"]["sc-max-buffered-posts"].IsDefined())
                            singleproxy["xhttp-opts"]["sc-max-buffered-posts"] >>= node.XHTTPScMaxBufferedPosts;
                        else if(singleproxy["xhttp-opts"]["scMaxBufferedPosts"].IsDefined())
                            singleproxy["xhttp-opts"]["scMaxBufferedPosts"] >>= node.XHTTPScMaxBufferedPosts;
                        if(singleproxy["xhttp-opts"]["sc-min-posts-interval-ms"].IsDefined())
                            singleproxy["xhttp-opts"]["sc-min-posts-interval-ms"] >>= node.XHTTPScMinPostsIntervalMs;
                        else if(singleproxy["xhttp-opts"]["scMinPostsIntervalMs"].IsDefined())
                            singleproxy["xhttp-opts"]["scMinPostsIntervalMs"] >>= node.XHTTPScMinPostsIntervalMs;
                        if(singleproxy["xhttp-opts"]["reuse-settings"].IsDefined())
                        {
                            auto reuse = singleproxy["xhttp-opts"]["reuse-settings"];
                            if(reuse["max-connections"].IsDefined())
                                reuse["max-connections"] >>= node.XHTTPReuseMaxConnections;
                            else if(reuse["maxConnections"].IsDefined())
                                reuse["maxConnections"] >>= node.XHTTPReuseMaxConnections;
                            if(reuse["max-concurrency"].IsDefined())
                                reuse["max-concurrency"] >>= node.XHTTPReuseMaxConcurrency;
                            else if(reuse["maxConcurrency"].IsDefined())
                                reuse["maxConcurrency"] >>= node.XHTTPReuseMaxConcurrency;
                            if(reuse["c-max-reuse-times"].IsDefined())
                                reuse["c-max-reuse-times"] >>= node.XHTTPReuseCMaxReuseTimes;
                            else if(reuse["cMaxReuseTimes"].IsDefined())
                                reuse["cMaxReuseTimes"] >>= node.XHTTPReuseCMaxReuseTimes;
                            if(reuse["h-max-request-times"].IsDefined())
                                reuse["h-max-request-times"] >>= node.XHTTPReuseHMaxRequestTimes;
                            else if(reuse["hMaxRequestTimes"].IsDefined())
                                reuse["hMaxRequestTimes"] >>= node.XHTTPReuseHMaxRequestTimes;
                            if(reuse["h-max-reusable-secs"].IsDefined())
                                reuse["h-max-reusable-secs"] >>= node.XHTTPReuseHMaxReusableSecs;
                            else if(reuse["hMaxReusableSecs"].IsDefined())
                                reuse["hMaxReusableSecs"] >>= node.XHTTPReuseHMaxReusableSecs;
                            if(reuse["h-keep-alive-period"].IsDefined())
                                node.XHTTPReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["h-keep-alive-period"]);
                            else if(reuse["hKeepAlivePeriod"].IsDefined())
                                node.XHTTPReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["hKeepAlivePeriod"]);
                        }
                        else if(singleproxy["xhttp-opts"]["xmux"].IsDefined())
                        {
                            auto reuse = singleproxy["xhttp-opts"]["xmux"];
                            if(reuse["max-connections"].IsDefined())
                                reuse["max-connections"] >>= node.XHTTPReuseMaxConnections;
                            else if(reuse["maxConnections"].IsDefined())
                                reuse["maxConnections"] >>= node.XHTTPReuseMaxConnections;
                            if(reuse["max-concurrency"].IsDefined())
                                reuse["max-concurrency"] >>= node.XHTTPReuseMaxConcurrency;
                            else if(reuse["maxConcurrency"].IsDefined())
                                reuse["maxConcurrency"] >>= node.XHTTPReuseMaxConcurrency;
                            if(reuse["c-max-reuse-times"].IsDefined())
                                reuse["c-max-reuse-times"] >>= node.XHTTPReuseCMaxReuseTimes;
                            else if(reuse["cMaxReuseTimes"].IsDefined())
                                reuse["cMaxReuseTimes"] >>= node.XHTTPReuseCMaxReuseTimes;
                            if(reuse["h-max-request-times"].IsDefined())
                                reuse["h-max-request-times"] >>= node.XHTTPReuseHMaxRequestTimes;
                            else if(reuse["hMaxRequestTimes"].IsDefined())
                                reuse["hMaxRequestTimes"] >>= node.XHTTPReuseHMaxRequestTimes;
                            if(reuse["h-max-reusable-secs"].IsDefined())
                                reuse["h-max-reusable-secs"] >>= node.XHTTPReuseHMaxReusableSecs;
                            else if(reuse["hMaxReusableSecs"].IsDefined())
                                reuse["hMaxReusableSecs"] >>= node.XHTTPReuseHMaxReusableSecs;
                            if(reuse["h-keep-alive-period"].IsDefined())
                                node.XHTTPReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["h-keep-alive-period"]);
                            else if(reuse["hKeepAlivePeriod"].IsDefined())
                                node.XHTTPReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["hKeepAlivePeriod"]);
                        }
                        else
                        {
                            // Compatibility: parse legacy flat reuse fields under xhttp-opts.
                            if(singleproxy["xhttp-opts"]["max-connections"].IsDefined())
                                singleproxy["xhttp-opts"]["max-connections"] >>= node.XHTTPReuseMaxConnections;
                            if(singleproxy["xhttp-opts"]["max-concurrency"].IsDefined())
                                singleproxy["xhttp-opts"]["max-concurrency"] >>= node.XHTTPReuseMaxConcurrency;
                            if(singleproxy["xhttp-opts"]["c-max-reuse-times"].IsDefined())
                                singleproxy["xhttp-opts"]["c-max-reuse-times"] >>= node.XHTTPReuseCMaxReuseTimes;
                            if(singleproxy["xhttp-opts"]["h-max-request-times"].IsDefined())
                                singleproxy["xhttp-opts"]["h-max-request-times"] >>= node.XHTTPReuseHMaxRequestTimes;
                            if(singleproxy["xhttp-opts"]["h-max-reusable-secs"].IsDefined())
                                singleproxy["xhttp-opts"]["h-max-reusable-secs"] >>= node.XHTTPReuseHMaxReusableSecs;
                            if(singleproxy["xhttp-opts"]["h-keep-alive-period"].IsDefined())
                                node.XHTTPReuseHKeepAlivePeriod = safe_as<uint32_t>(singleproxy["xhttp-opts"]["h-keep-alive-period"]);
                            else if(singleproxy["xhttp-opts"]["hKeepAlivePeriod"].IsDefined())
                                node.XHTTPReuseHKeepAlivePeriod = safe_as<uint32_t>(singleproxy["xhttp-opts"]["hKeepAlivePeriod"]);
                        }

                        if(singleproxy["xhttp-opts"]["download-settings"].IsDefined())
                        {
                            auto download = singleproxy["xhttp-opts"]["download-settings"];
                            if(download["path"].IsDefined())
                                download["path"] >>= node.XHTTPDownloadPath;
                            if(download["host"].IsDefined())
                                download["host"] >>= node.XHTTPDownloadHost;
                            else if(download["headers"].IsDefined() && download["headers"]["Host"].IsDefined())
                                download["headers"]["Host"] >>= node.XHTTPDownloadHost;
                            if(download["headers"].IsDefined() && download["headers"].IsMap())
                                node.XHTTPDownloadHeaders = encodeHTTPHeaderMap(download["headers"]);
                            if(download["no-grpc-header"].IsDefined())
                                node.XHTTPDownloadNoGRPCHeader = safe_as<bool>(download["no-grpc-header"]);
                            if(download["x-padding-bytes"].IsDefined())
                                download["x-padding-bytes"] >>= node.XHTTPDownloadXPaddingBytes;
                            if(download["sc-max-each-post-bytes"].IsDefined())
                                download["sc-max-each-post-bytes"] >>= node.XHTTPDownloadScMaxEachPostBytes;
                            else if(download["scMaxEachPostBytes"].IsDefined())
                                download["scMaxEachPostBytes"] >>= node.XHTTPDownloadScMaxEachPostBytes;
                            if(download["sc-max-buffered-posts"].IsDefined())
                                download["sc-max-buffered-posts"] >>= node.XHTTPDownloadScMaxBufferedPosts;
                            else if(download["scMaxBufferedPosts"].IsDefined())
                                download["scMaxBufferedPosts"] >>= node.XHTTPDownloadScMaxBufferedPosts;
                            if(download["sc-min-posts-interval-ms"].IsDefined())
                                download["sc-min-posts-interval-ms"] >>= node.XHTTPDownloadScMinPostsIntervalMs;
                            else if(download["scMinPostsIntervalMs"].IsDefined())
                                download["scMinPostsIntervalMs"] >>= node.XHTTPDownloadScMinPostsIntervalMs;
                            if(download["reuse-settings"].IsDefined())
                            {
                                auto reuse = download["reuse-settings"];
                                if(reuse["max-connections"].IsDefined())
                                    reuse["max-connections"] >>= node.XHTTPDownloadReuseMaxConnections;
                                else if(reuse["maxConnections"].IsDefined())
                                    reuse["maxConnections"] >>= node.XHTTPDownloadReuseMaxConnections;
                                if(reuse["max-concurrency"].IsDefined())
                                    reuse["max-concurrency"] >>= node.XHTTPDownloadReuseMaxConcurrency;
                                else if(reuse["maxConcurrency"].IsDefined())
                                    reuse["maxConcurrency"] >>= node.XHTTPDownloadReuseMaxConcurrency;
                                if(reuse["c-max-reuse-times"].IsDefined())
                                    reuse["c-max-reuse-times"] >>= node.XHTTPDownloadReuseCMaxReuseTimes;
                                else if(reuse["cMaxReuseTimes"].IsDefined())
                                    reuse["cMaxReuseTimes"] >>= node.XHTTPDownloadReuseCMaxReuseTimes;
                                if(reuse["h-max-request-times"].IsDefined())
                                    reuse["h-max-request-times"] >>= node.XHTTPDownloadReuseHMaxRequestTimes;
                                else if(reuse["hMaxRequestTimes"].IsDefined())
                                    reuse["hMaxRequestTimes"] >>= node.XHTTPDownloadReuseHMaxRequestTimes;
                                if(reuse["h-max-reusable-secs"].IsDefined())
                                    reuse["h-max-reusable-secs"] >>= node.XHTTPDownloadReuseHMaxReusableSecs;
                                else if(reuse["hMaxReusableSecs"].IsDefined())
                                    reuse["hMaxReusableSecs"] >>= node.XHTTPDownloadReuseHMaxReusableSecs;
                                if(reuse["h-keep-alive-period"].IsDefined())
                                    node.XHTTPDownloadReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["h-keep-alive-period"]);
                                else if(reuse["hKeepAlivePeriod"].IsDefined())
                                    node.XHTTPDownloadReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["hKeepAlivePeriod"]);
                            }
                            else if(download["xmux"].IsDefined())
                            {
                                // Compatibility: parse legacy xmux object under download-settings.
                                auto reuse = download["xmux"];
                                if(reuse["max-connections"].IsDefined())
                                    reuse["max-connections"] >>= node.XHTTPDownloadReuseMaxConnections;
                                else if(reuse["maxConnections"].IsDefined())
                                    reuse["maxConnections"] >>= node.XHTTPDownloadReuseMaxConnections;
                                if(reuse["max-concurrency"].IsDefined())
                                    reuse["max-concurrency"] >>= node.XHTTPDownloadReuseMaxConcurrency;
                                else if(reuse["maxConcurrency"].IsDefined())
                                    reuse["maxConcurrency"] >>= node.XHTTPDownloadReuseMaxConcurrency;
                                if(reuse["c-max-reuse-times"].IsDefined())
                                    reuse["c-max-reuse-times"] >>= node.XHTTPDownloadReuseCMaxReuseTimes;
                                else if(reuse["cMaxReuseTimes"].IsDefined())
                                    reuse["cMaxReuseTimes"] >>= node.XHTTPDownloadReuseCMaxReuseTimes;
                                if(reuse["h-max-request-times"].IsDefined())
                                    reuse["h-max-request-times"] >>= node.XHTTPDownloadReuseHMaxRequestTimes;
                                else if(reuse["hMaxRequestTimes"].IsDefined())
                                    reuse["hMaxRequestTimes"] >>= node.XHTTPDownloadReuseHMaxRequestTimes;
                                if(reuse["h-max-reusable-secs"].IsDefined())
                                    reuse["h-max-reusable-secs"] >>= node.XHTTPDownloadReuseHMaxReusableSecs;
                                else if(reuse["hMaxReusableSecs"].IsDefined())
                                    reuse["hMaxReusableSecs"] >>= node.XHTTPDownloadReuseHMaxReusableSecs;
                                if(reuse["h-keep-alive-period"].IsDefined())
                                    node.XHTTPDownloadReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["h-keep-alive-period"]);
                                else if(reuse["hKeepAlivePeriod"].IsDefined())
                                    node.XHTTPDownloadReuseHKeepAlivePeriod = safe_as<uint32_t>(reuse["hKeepAlivePeriod"]);
                            }
                            else
                            {
                                // Compatibility: parse legacy flat reuse fields under download-settings.
                                if(download["max-connections"].IsDefined())
                                    download["max-connections"] >>= node.XHTTPDownloadReuseMaxConnections;
                                if(download["max-concurrency"].IsDefined())
                                    download["max-concurrency"] >>= node.XHTTPDownloadReuseMaxConcurrency;
                                if(download["c-max-reuse-times"].IsDefined())
                                    download["c-max-reuse-times"] >>= node.XHTTPDownloadReuseCMaxReuseTimes;
                                if(download["h-max-request-times"].IsDefined())
                                    download["h-max-request-times"] >>= node.XHTTPDownloadReuseHMaxRequestTimes;
                                if(download["h-max-reusable-secs"].IsDefined())
                                    download["h-max-reusable-secs"] >>= node.XHTTPDownloadReuseHMaxReusableSecs;
                                if(download["h-keep-alive-period"].IsDefined())
                                    node.XHTTPDownloadReuseHKeepAlivePeriod = safe_as<uint32_t>(download["h-keep-alive-period"]);
                                else if(download["hKeepAlivePeriod"].IsDefined())
                                    node.XHTTPDownloadReuseHKeepAlivePeriod = safe_as<uint32_t>(download["hKeepAlivePeriod"]);
                            }

                            if(download["server"].IsDefined())
                                download["server"] >>= node.XHTTPDownloadServer;
                            if(download["port"].IsDefined())
                                node.XHTTPDownloadPort = static_cast<uint16_t>(safe_as<int>(download["port"]));
                            if(download["tls"].IsDefined())
                                node.XHTTPDownloadTLS = safe_as<bool>(download["tls"]);
                            if(download["alpn"].IsDefined() && download["alpn"].IsSequence())
                                download["alpn"] >>= node.XHTTPDownloadALPN;
                            if(download["ech-opts"].IsDefined())
                            {
                                if(download["ech-opts"]["enable"].IsDefined())
                                    node.XHTTPDownloadECHEnable = safe_as<bool>(download["ech-opts"]["enable"]);
                                if(download["ech-opts"]["config"].IsDefined())
                                    download["ech-opts"]["config"] >>= node.XHTTPDownloadECHConfig;
                                if(download["ech-opts"]["query-server-name"].IsDefined())
                                    download["ech-opts"]["query-server-name"] >>= node.XHTTPDownloadECHQueryServerName;
                            }
                            if(download["reality-opts"].IsDefined())
                            {
                                if(download["reality-opts"]["public-key"].IsDefined())
                                    download["reality-opts"]["public-key"] >>= node.XHTTPDownloadRealityPublicKey;
                                if(download["reality-opts"]["short-id"].IsDefined())
                                    download["reality-opts"]["short-id"] >>= node.XHTTPDownloadRealityShortID;
                                if(download["reality-opts"]["support-x25519mlkem768"].IsDefined())
                                    node.XHTTPDownloadRealitySupportX25519Mlkem768 = safe_as<bool>(download["reality-opts"]["support-x25519mlkem768"]);
                                if(download["reality-opts"]["spiderX"].IsDefined())
                                    download["reality-opts"]["spiderX"] >>= node.XHTTPDownloadRealitySpiderX;
                                else if(download["reality-opts"]["spider-x"].IsDefined())
                                    download["reality-opts"]["spider-x"] >>= node.XHTTPDownloadRealitySpiderX;
                                else if(download["reality-opts"]["spx"].IsDefined())
                                    download["reality-opts"]["spx"] >>= node.XHTTPDownloadRealitySpiderX;
                            }
                            if(download["skip-cert-verify"].IsDefined())
                                node.XHTTPDownloadSkipCertVerify = safe_as<bool>(download["skip-cert-verify"]);
                            if(download["fingerprint"].IsDefined())
                                download["fingerprint"] >>= node.XHTTPDownloadFingerprint;
                            if(download["certificate"].IsDefined())
                                download["certificate"] >>= node.XHTTPDownloadCertificate;
                            if(download["private-key"].IsDefined())
                                download["private-key"] >>= node.XHTTPDownloadPrivateKey;
                            if(download["servername"].IsDefined())
                                download["servername"] >>= node.XHTTPDownloadServerName;
                            if(download["client-fingerprint"].IsDefined())
                                download["client-fingerprint"] >>= node.XHTTPDownloadClientFingerprint;
                        }
                    }
                    else
                    {
                        path = "/";
                    }
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
                    if(singleproxy["grpc-opts"]["grpc-user-agent"].IsDefined())
                        singleproxy["grpc-opts"]["grpc-user-agent"] >>= node.GrpcUserAgent;
                    if(singleproxy["grpc-opts"]["ping-interval"].IsDefined())
                        node.GrpcPingInterval = safe_as<uint32_t>(singleproxy["grpc-opts"]["ping-interval"]);
                    if(singleproxy["grpc-opts"]["max-connections"].IsDefined())
                        node.GrpcMaxConnections = safe_as<uint32_t>(singleproxy["grpc-opts"]["max-connections"]);
                    if(singleproxy["grpc-opts"]["min-streams"].IsDefined())
                        node.GrpcMinStreams = safe_as<uint32_t>(singleproxy["grpc-opts"]["min-streams"]);
                    if(singleproxy["grpc-opts"]["max-streams"].IsDefined())
                        node.GrpcMaxStreams = safe_as<uint32_t>(singleproxy["grpc-opts"]["max-streams"]);
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
                singleproxy["reality-opts"]["short-id"] >>= short_id;
                if(singleproxy["reality-opts"]["support-x25519mlkem768"].IsDefined())
                    node.SupportX25519Mlkem768 = safe_as<bool>(singleproxy["reality-opts"]["support-x25519mlkem768"]);
                if(singleproxy["reality-opts"]["spiderX"].IsDefined())
                    singleproxy["reality-opts"]["spiderX"] >>= spider_x;
                else if(singleproxy["reality-opts"]["spider-x"].IsDefined())
                    singleproxy["reality-opts"]["spider-x"] >>= spider_x;
                else if(singleproxy["reality-opts"]["spx"].IsDefined())
                    singleproxy["reality-opts"]["spx"] >>= spider_x;
            }
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= node.EchConfig;
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
            }
            singleproxy["packet-encoding"] >>= packet_encoding;
            if(singleproxy["udp"].IsDefined())
                vless_udp = safe_as<bool>(singleproxy["udp"]);
            if(singleproxy["fast-open"].IsDefined())
                tfo = safe_as<std::string>(singleproxy["fast-open"]);
            else if(singleproxy["tfo"].IsDefined())
                tfo = safe_as<std::string>(singleproxy["tfo"]);
            if(!encryption.empty() && encryption != "none")
                singleproxy["encryption"] >>= encryption;
            else
                encryption = "none";
            if(singleproxy["packet-addr"].IsDefined())
                packet_addr_enabled = safe_as<bool>(singleproxy["packet-addr"]);
            if(singleproxy["xudp"].IsDefined())
                xudp_enabled = safe_as<bool>(singleproxy["xudp"]);

            vlessConstruct(node, VLESS_DEFAULT_GROUP, ps, server, port, type, id, net, "", flow, mode, path, host, "", tls, public_key, short_id, fingerprint, sni, alpnList, packet_encoding, encryption, vless_udp, tfo, scv, tribool(), "", v2ray_http_upgrade, v2ray_http_upgrade_fast_open, tribool(packet_addr_enabled), tribool(xudp_enabled), ca, private_key, spider_x);
            if(!fp.empty())
                node.ClientFingerprint = fp;
            break;
        case "masque"_hash:
            group = MASQUE_DEFAULT_GROUP;
            singleproxy["private-key"] >>= private_key;
            singleproxy["public-key"] >>= public_key;
            singleproxy["ip"] >>= ip;
            singleproxy["ipv6"] >>= ipv6;
            singleproxy["sni"] >>= sni;
            singleproxy["mtu"] >>= mtu;
            singleproxy["network"] >>= net;
            singleproxy["cwnd"] >>= cwnd;
            if(singleproxy["bbr-profile"].IsDefined())
                singleproxy["bbr-profile"] >>= node.BBRProfile;
            else if(singleproxy["bbrProfile"].IsDefined())
                singleproxy["bbrProfile"] >>= node.BBRProfile;
            if(singleproxy["udp"].IsDefined())
                udp = safe_as<bool>(singleproxy["udp"]);
            if(singleproxy["dialer-proxy"].IsDefined())
                singleproxy["dialer-proxy"] >>= underlying_proxy;
            if(singleproxy["remote-dns-resolve"].IsDefined())
                remote_dns_resolve = safe_as<bool>(singleproxy["remote-dns-resolve"]);
            if(singleproxy["dns"].IsDefined() && singleproxy["dns"].IsSequence())
            {
                dns_server.clear();
                for(auto v : singleproxy["dns"])
                    dns_server.push_back(safe_as<std::string>(v));
            }
            singleproxy["congestion-controller"] >>= congestion_controller;

            masqueConstruct(node, group, ps, server, port, private_key, public_key, ip, ipv6, mtu, net, udp, underlying_proxy, remote_dns_resolve, dns_server, congestion_controller);
            if(!sni.empty())
                node.SNI = sni;
            if(!cwnd.empty())
                node.CWND = to_int(cwnd);
            break;
        case "tuic"_hash:
            group = TUIC_DEFAULT_GROUP;
            singleproxy["token"] >>= token;
            singleproxy["uuid"] >>= uuid;
            singleproxy["password"] >>= password;
            singleproxy["ip"] >>= ip;
            singleproxy["heartbeat-interval"] >>= heartbeat_interval;
            if(heartbeat_interval.empty())
                singleproxy["heartbeat_interval"] >>= heartbeat_interval;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            if(singleproxy["sni"].IsDefined())
                singleproxy["sni"] >>= sni;
            else if(singleproxy["servername"].IsDefined())
                singleproxy["servername"] >>= sni;
            singleproxy["disable-sni"] >>= disable_sni;
            singleproxy["reduce-rtt"] >>= reduce_rtt;
            singleproxy["request-timeout"] >>= request_timeout;
            singleproxy["udp-relay-mode"] >>= udp_relay_mode;
            singleproxy["congestion-controller"] >>= congestion_controller;
            if(singleproxy["bbr-profile"].IsDefined())
                singleproxy["bbr-profile"] >>= node.BBRProfile;
            else if(singleproxy["bbrProfile"].IsDefined())
                singleproxy["bbrProfile"] >>= node.BBRProfile;
            singleproxy["cwnd"] >>= cwnd;
            singleproxy["max-udp-relay-packet-size"] >>= max_udp_relay_packet_size;
            singleproxy["max-open-streams"] >>= max_open_streams;
            singleproxy["fast-open"] >>= fast_open;
            singleproxy["version"] >>= version;
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
            if(singleproxy["fingerprint"].IsDefined())
                singleproxy["fingerprint"] >>= node.Fingerprint;
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= node.Certificate;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= node.CertificateKey;
            if(singleproxy["udp-over-stream"].IsDefined())
                udp_over_stream = safe_as<bool>(singleproxy["udp-over-stream"]);
            if(singleproxy["udp-over-stream-version"].IsDefined())
                udp_over_stream_version = safe_as<int>(singleproxy["udp-over-stream-version"]);
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= node.EchConfig;
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
            }

            TUICConstruct(node, group, ps, server, port, uuid, password, ip, heartbeat_interval, alpn, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, sni, fast_open, token, version, tfo, scv, underlying_proxy, udp_over_stream, udp_over_stream_version);
            if(!cwnd.empty())
                node.CWND = to_int(cwnd);
            break;
        case "anytls"_hash:
            group = ANYTLS_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= sni;
            singleproxy["alpn"] >>= alpnList;
            singleproxy["fingerprint"] >>= fingerprint;
            if(singleproxy["client-fingerprint"].IsDefined())
                singleproxy["client-fingerprint"] >>= node.ClientFingerprint;
            if(singleproxy["skip-cert-verify"].IsDefined())
                scv = safe_as<bool>(singleproxy["skip-cert-verify"]);
            if(singleproxy["certificate"].IsDefined())
                singleproxy["certificate"] >>= node.Certificate;
            if(singleproxy["private-key"].IsDefined())
                singleproxy["private-key"] >>= node.CertificateKey;
            if(singleproxy["ech-opts"].IsDefined())
            {
                if(singleproxy["ech-opts"]["enable"].IsDefined())
                    node.EchEnable = safe_as<bool>(singleproxy["ech-opts"]["enable"]);
                if(singleproxy["ech-opts"]["config"].IsDefined())
                    singleproxy["ech-opts"]["config"] >>= node.EchConfig;
                if(singleproxy["ech-opts"]["query-server-name"].IsDefined())
                    singleproxy["ech-opts"]["query-server-name"] >>= node.EchQueryServerName;
            }
            if(singleproxy["idle-session-check-interval"].IsDefined())
                singleproxy["idle-session-check-interval"] >>= idle_session_check_interval;
            if(singleproxy["idle-session-timeout"].IsDefined())
                singleproxy["idle-session-timeout"] >>= idle_session_timeout;
            if(singleproxy["min-idle-session"].IsDefined())
                singleproxy["min-idle-session"] >>= min_idle_session;
            if(singleproxy["padding-scheme"].IsDefined())
                singleproxy["padding-scheme"] >>= multiplexing;
            if(singleproxy["ip-version"].IsDefined())
                singleproxy["ip-version"] >>= ip_version;
            if(singleproxy["udp"].IsDefined())
                udp = safe_as<bool>(singleproxy["udp"]);
            anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, server, port, password, sni, alpnList, fingerprint, idle_session_check_interval, idle_session_timeout, min_idle_session, tfo, scv, tribool(), underlying_proxy, multiplexing, ip_version);
            node.UDP = udp;
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
            if(singleproxy["port-range"].IsDefined())
                singleproxy["port-range"] >>= port_range;
            if(singleproxy["handshake-mode"].IsDefined())
                singleproxy["handshake-mode"] >>= handshake_mode;
            if(singleproxy["traffic-pattern"].IsDefined())
                singleproxy["traffic-pattern"] >>= traffic_pattern;

            mieruConstruct(node, MIERU_DEFAULT_GROUP, ps, port, password, server, ports, user, multiplexing, transfer_protocol, udp, tribool(), scv, tribool(), "", port_range, handshake_mode, traffic_pattern);
            break;
        case "sudoku"_hash:
            group = SUDOKU_DEFAULT_GROUP;
            singleproxy["key"] >>= key;
            singleproxy["aead-method"] >>= aead;
            singleproxy["padding-min"] >>= padding_min;
            singleproxy["padding-max"] >>= padding_max;
            singleproxy["table-type"] >>= ascii;
            // Old field names (backward compatibility)
            singleproxy["http-mask"] >>= http_mask;
            singleproxy["http-mask-mode"] >>= http_mask_mode;
            singleproxy["http-mask-tls"] >>= http_mask_tls;
            singleproxy["http-mask-host"] >>= http_mask_host;
            singleproxy["http-mask-multiplex"] >>= http_mask_multiplex;
            if(singleproxy["disable-http-mask"].IsDefined())
                singleproxy["disable-http-mask"] >>= disable_http_mask;
            if(singleproxy["path-root"].IsDefined())
                singleproxy["path-root"] >>= path_root;
            // New httpmask object overrides legacy fields. This matches mihomo's option merge order.
            if(singleproxy["httpmask"].IsDefined())
            {
                const auto& httpmask = singleproxy["httpmask"];
                http_mask.clear();
                disable_http_mask.clear();
                http_mask_tls.clear();
                http_mask_host.clear();
                http_mask_multiplex.clear();
                if(httpmask["disable"].IsDefined())
                    httpmask["disable"] >>= disable_http_mask;
                if(httpmask["mode"].IsDefined())
                    httpmask["mode"] >>= http_mask_mode;
                if(httpmask["tls"].IsDefined())
                    httpmask["tls"] >>= http_mask_tls;
                if(httpmask["host"].IsDefined())
                    httpmask["host"] >>= http_mask_host;
                if(httpmask["path-root"].IsDefined())
                    httpmask["path-root"] >>= path_root;
                if(httpmask["multiplex"].IsDefined())
                    httpmask["multiplex"] >>= http_mask_multiplex;
            }
            if(singleproxy["handshake-timeout"].IsDefined())
                singleproxy["handshake-timeout"] >>= handshake_timeout;
            singleproxy["custom-table"] >>= custom_table;
            if(singleproxy["custom-tables"].IsDefined())
            {
                for(uint32_t k = 0; k < singleproxy["custom-tables"].size(); k++)
                {
                    std::string t;
                    singleproxy["custom-tables"][k] >>= t;
                    custom_tables.emplace_back(t);
                }
            }
            singleproxy["enable-pure-downlink"] >>= enable_pure_downlink;
            sudokuConstruct(node, group, ps, server, port, key, aead, padding_min, padding_max, ascii, http_mask, http_mask_mode, http_mask_tls, http_mask_host, http_mask_multiplex, enable_pure_downlink, disable_http_mask, path_root, handshake_timeout, custom_table, custom_tables, underlying_proxy);
            break;
        case "trusttunnel"_hash:
            group = TRUSTTUNNEL_DEFAULT_GROUP;
            singleproxy["username"] >>= user;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= sni;
            if (singleproxy["alpn"].IsSequence()) {
                for(uint32_t k = 0; k < singleproxy["alpn"].size(); k++)
                {
                    std::string alpn_item;
                    singleproxy["alpn"][k] >>= alpn_item;
                    alpnList.emplace_back(alpn_item);
                }
            }
            singleproxy["client-fingerprint"] >>= client_fingerprint;
            if(singleproxy["health-check"].IsDefined())
                health_check = safe_as<bool>(singleproxy["health-check"]);
            if(singleproxy["quic"].IsDefined())
                quic = safe_as<bool>(singleproxy["quic"]);
            singleproxy["congestion-controller"] >>= congestion_controller;
            if(singleproxy["bbr-profile"].IsDefined())
                singleproxy["bbr-profile"] >>= node.BBRProfile;
            else if(singleproxy["bbrProfile"].IsDefined())
                singleproxy["bbrProfile"] >>= node.BBRProfile;

            trusttunnelConstruct(node, group, ps, server, port, user, password, sni, alpnList, client_fingerprint, health_check, udp, scv, quic, congestion_controller, underlying_proxy);
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
    std::string fingerprint, client_fingerprint, sni, alpn, skip_cert_verify, udp_str, tfo_str, ip_version;
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
    alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
        alpnList.push_back(alpn);
    // Extended parameters
    sni = getUrlArg(addition, "sni");
    if(sni.empty())
        sni = getUrlArg(addition, "servername");
    fingerprint = getUrlArg(addition, "fp");
    if(fingerprint.empty())
        fingerprint = getUrlArg(addition, "fingerprint");
    client_fingerprint = getUrlArg(addition, "client-fingerprint");
    if(client_fingerprint.empty())
        client_fingerprint = getUrlArg(addition, "clientFingerprint");
    skip_cert_verify = getUrlArg(addition, "skip-cert-verify");
    if(skip_cert_verify.empty())
        skip_cert_verify = getUrlArg(addition, "allowInsecure");
    udp_str = getUrlArg(addition, "udp");
    tfo_str = getUrlArg(addition, "tfo");
    ip_version = getUrlArg(addition, "ip-version");
    if(ip_version.empty())
        ip_version = getUrlArg(addition, "ipVersion");
    // Convert boolean strings
    tribool udp = udp_str == "true" || udp_str == "1" ? tribool(true) : (udp_str == "false" || udp_str == "0" ? tribool(false) : tribool());
    tribool tfo = tfo_str == "true" || tfo_str == "1" ? tribool(true) : (tfo_str == "false" || tfo_str == "0" ? tribool(false) : tribool());
    tribool scv = skip_cert_verify == "true" || skip_cert_verify == "1" ? tribool(true) : (skip_cert_verify == "false" || skip_cert_verify == "0" ? tribool(false) : tribool());

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", path, host, "", tls, sni, alpnList, udp, tfo, scv, tribool(), "", fingerprint, client_fingerprint);
    if(!ip_version.empty())
        node.IPVersion = ip_version;
}

void explodeShadowrocket(std::string rocket, Proxy &node)
{
    std::string add, port, type, id, aid, net = "tcp", path, host, tls, cipher, remarks;
    std::string obfs; //for other style of link
    std::string fingerprint, client_fingerprint, sni, alpn, skip_cert_verify, udp_str, tfo_str, ip_version;
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
    alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
        alpnList.push_back(alpn);
    // Extended parameters
    sni = getUrlArg(addition, "sni");
    if(sni.empty())
        sni = getUrlArg(addition, "servername");
    fingerprint = getUrlArg(addition, "fp");
    if(fingerprint.empty())
        fingerprint = getUrlArg(addition, "fingerprint");
    client_fingerprint = getUrlArg(addition, "client-fingerprint");
    if(client_fingerprint.empty())
        client_fingerprint = getUrlArg(addition, "clientFingerprint");
    skip_cert_verify = getUrlArg(addition, "skip-cert-verify");
    if(skip_cert_verify.empty())
        skip_cert_verify = getUrlArg(addition, "allowInsecure");
    udp_str = getUrlArg(addition, "udp");
    tfo_str = getUrlArg(addition, "tfo");
    ip_version = getUrlArg(addition, "ip-version");
    if(ip_version.empty())
        ip_version = getUrlArg(addition, "ipVersion");
    // Convert boolean strings
    tribool udp = udp_str == "true" || udp_str == "1" ? tribool(true) : (udp_str == "false" || udp_str == "0" ? tribool(false) : tribool());
    tribool tfo = tfo_str == "true" || tfo_str == "1" ? tribool(true) : (tfo_str == "false" || tfo_str == "0" ? tribool(false) : tribool());
    tribool scv = skip_cert_verify == "true" || skip_cert_verify == "1" ? tribool(true) : (skip_cert_verify == "false" || skip_cert_verify == "0" ? tribool(false) : tribool());

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, sni, alpnList, udp, tfo, scv, tribool(), "", fingerprint, client_fingerprint);
    if(!ip_version.empty())
        node.IPVersion = ip_version;
}

void explodeKitsunebi(std::string kit, Proxy &node)
{
    std::string add, port, type, id, aid = "0", net = "tcp", path, host, tls, cipher = "auto", remarks;
    std::string fingerprint, client_fingerprint, sni, alpn, skip_cert_verify, udp_str, tfo_str, ip_version;
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
    alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if(!alpn.empty())
        alpnList.push_back(alpn);
    // Extended parameters
    sni = getUrlArg(addition, "sni");
    if(sni.empty())
        sni = getUrlArg(addition, "servername");
    fingerprint = getUrlArg(addition, "fp");
    if(fingerprint.empty())
        fingerprint = getUrlArg(addition, "fingerprint");
    client_fingerprint = getUrlArg(addition, "client-fingerprint");
    if(client_fingerprint.empty())
        client_fingerprint = getUrlArg(addition, "clientFingerprint");
    skip_cert_verify = getUrlArg(addition, "skip-cert-verify");
    if(skip_cert_verify.empty())
        skip_cert_verify = getUrlArg(addition, "allowInsecure");
    udp_str = getUrlArg(addition, "udp");
    tfo_str = getUrlArg(addition, "tfo");
    ip_version = getUrlArg(addition, "ip-version");
    if(ip_version.empty())
        ip_version = getUrlArg(addition, "ipVersion");
    // Convert boolean strings
    tribool udp = udp_str == "true" || udp_str == "1" ? tribool(true) : (udp_str == "false" || udp_str == "0" ? tribool(false) : tribool());
    tribool tfo = tfo_str == "true" || tfo_str == "1" ? tribool(true) : (tfo_str == "false" || tfo_str == "0" ? tribool(false) : tribool());
    tribool scv = skip_cert_verify == "true" || skip_cert_verify == "1" ? tribool(true) : (skip_cert_verify == "false" || skip_cert_verify == "0" ? tribool(false) : tribool());

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, sni, alpnList, udp, tfo, scv, tribool(), "", fingerprint, client_fingerprint);
    if(!ip_version.empty())
        node.IPVersion = ip_version;
}

void explodeStdWireguard(std::string wg, Proxy &node)
{
    // support both wireguard:// and wg://
    wg = regReplace(wg, "wg://", "wireguard://");
    wg = regReplace(wg, "wireguard://", "");
    std::string pubkey, host, port, addition, remarks;
    tribool udp;
    std::string privkey, selfip, selfipv6, psk, dns, mtu, keepalive, allowed_ips, client_id, dialer_proxy;
    size_t pos = wg.rfind("#");
    if(pos != std::string::npos)
    {
        remarks = urlDecode(wg.substr(pos + 1));
        wg.erase(pos);
    }
    pos = wg.find("/?");
    if(pos != std::string::npos)
    {
        addition = wg.substr(pos + 2);
        wg.erase(pos);
    }
    if(regGetMatch(wg, R"(^([^@]+)@([^:]+):(\d+)$)", 4, 0, &pubkey, &host, &port) != 0)
        return;
    // parse optional query parameters
    privkey = getUrlArg(addition, "private-key");
    selfip = getUrlArg(addition, "self-ip");
    selfipv6 = getUrlArg(addition, "self-ip-v6");
    psk = getUrlArg(addition, "preshared-key");
    dns = getUrlArg(addition, "dns");
    mtu = getUrlArg(addition, "mtu");
    keepalive = getUrlArg(addition, "keepalive");
    allowed_ips = getUrlArg(addition, "allowed-ips");
    client_id = getUrlArg(addition, "client-id");
    dialer_proxy = getUrlArg(addition, "dialer-proxy");
    std::string udp_str = getUrlArg(addition, "udp");
    if(!udp_str.empty())
        udp = tribool(udp_str == "true" || udp_str == "1");
    string_array dns_arr = split(dns, ",");
    string_array reserved_arr = split(getUrlArg(addition, "reserved"), ",");
    string_array peers_arr = split(getUrlArg(addition, "peers"), ",");

    wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, host, port, selfip, selfipv6, privkey, pubkey, psk, dns_arr, mtu, keepalive, "", client_id, udp, "", reserved_arr, peers_arr, dialer_proxy, tribool());
    if(!allowed_ips.empty())
        node.AllowedIPs = allowed_ips;
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
        sni = getUrlArg(addition, "peer");
    fingerprint = getUrlArg(addition, "pinSHA256");
    if(fingerprint.empty())
        fingerprint = getUrlArg(addition, "fingerprint");
    ports = getUrlArg(addition, "ports");
    if(ports.empty())
        ports = getUrlArg(addition, "mport");
    ca = getUrlArg(addition, "ca");
    ca_str = getUrlArg(addition, "ca-str");
    cwnd = getUrlArg(addition, "cwnd");
    hop_interval = getUrlArg(addition, "hop-interval");
    ech_enable = getUrlArg(addition, "ech-enable");
    if(ech_enable.empty())
        ech_enable = getUrlArg(addition, "ech");
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

void explodeStdMasque(std::string masque, Proxy &node)
{
    std::string add, port, remarks, addition;
    std::string private_key, public_key, ip, ipv6, mtu, network, congestion_controller;
    tribool udp, remote_dns_resolve;
    StringArray dnsservers;
    masque = masque.substr(8);
    string_size pos;
    pos = masque.rfind("#");
    if(pos != masque.npos)
    {
        remarks = urlDecode(masque.substr(pos + 1));
        masque.erase(pos);
    }
    pos = masque.rfind("?");
    if(pos != masque.npos)
    {
        addition = masque.substr(pos + 1);
        masque.erase(pos);
    }
    if(regGetMatch(masque, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
        return;
    private_key = getUrlArg(addition, "private_key");
    if(private_key.empty())
        private_key = getUrlArg(addition, "private-key");
    public_key = getUrlArg(addition, "public_key");
    if(public_key.empty())
        public_key = getUrlArg(addition, "public-key");
    ip = getUrlArg(addition, "ip");
    ipv6 = getUrlArg(addition, "ipv6");
    mtu = getUrlArg(addition, "mtu");
    network = getUrlArg(addition, "network");
    std::string udpstr = getUrlArg(addition, "udp");
    if(!udpstr.empty())
    {
        if(udpstr == "1" || udpstr == "true")
            udp = tribool(true);
        else
            udp = tribool(false);
    }
    std::string dproxy = getUrlArg(addition, "dialer_proxy");
    if(dproxy.empty())
        dproxy = getUrlArg(addition, "dialer-proxy");
    std::string rds = getUrlArg(addition, "remote_dns_resolve");
    if(rds.empty())
        rds = getUrlArg(addition, "remote-dns-resolve");
    if(!rds.empty())
    {
        if(rds == "1" || rds == "true")
            remote_dns_resolve = tribool(true);
        else
            remote_dns_resolve = tribool(false);
    }
    std::string dns = getUrlArg(addition, "dns");
    if(!dns.empty())
        dnsservers = split(dns, ",");
    congestion_controller = getUrlArg(addition, "congestion_controller");
    if(congestion_controller.empty())
        congestion_controller = getUrlArg(addition, "congestion-controller");
    if(remarks.empty())
        remarks = add + ":" + port;

    masqueConstruct(node, MASQUE_DEFAULT_GROUP, remarks, add, port, private_key, public_key, ip, ipv6, mtu, network, udp, dproxy, remote_dns_resolve, dnsservers, congestion_controller);
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
        if(regGetMatch(TUIC, R"(^(.*?):(.*?)@(.*?):(\d+)$)", 5, 0, &uuid, &password, &add, &port) == 0)
        {
            token = "";
        }
        else if(regGetMatch(TUIC, R"(^(.*?)@(.*?):(\d+)$)", 4, 0, &token, &add, &port) == 0)
        {
            uuid = "";
            password = "";
        }
        else
        {
            return;
        }
    }
    else
    {
        token = getUrlArg(addition, "token");
        uuid = getUrlArg(addition, "uuid");
        password = getUrlArg(addition, "password");
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

    TUICConstruct(node, TUIC_DEFAULT_GROUP, remarks, add, port, uuid, password, ip, heartbeat_interval, alpn, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, sni, fast_open, token, tuic_version, tfo, scv, std::string(), tribool(), 0);
}


void explodeStdMieru(std::string mieru, Proxy &node)
{
    std::string username, password, host, port, ports, profile, protocol, multiplexing, mtu, remarks;
    std::string addition, port_range, handshake_mode;
    tribool udp, tfo, scv, tls13;
    mieru = regReplace(mieru, "^mierus?://", "");
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
    if(regGetMatch(mieru, R"(^(.*?):(.*?)@(.*)$)", 4, 0, &username, &password, &host) != 0)
        return;
    username = urlDecode(username);
    password = urlDecode(password);
    // mierus simple links may contain repeated port/protocol pairs.
    // strategy: keep the first pair only, which matches current single-endpoint Proxy model.
    std::vector<std::string> port_items, protocol_items;
    for(const auto &item : split(addition, "&"))
    {
        auto eq = item.find('=');
        if(eq == std::string::npos)
            continue;
        const std::string key = urlDecode(item.substr(0, eq));
        const std::string value = urlDecode(item.substr(eq + 1));
        if(key == "port")
            port_items.emplace_back(value);
        else if(key == "protocol")
            protocol_items.emplace_back(value);
    }
    port = getUrlArg(addition, "port");
    if(!port_items.empty())
        port = port_items[0];
    if(port.find('-') != std::string::npos)
    {
        port_range = port;
        port.clear();
    }
    port_range = getUrlArg(addition, "port-range");
    if(port_range.empty())
        port_range = getUrlArg(addition, "port_range");
    if(port_range.empty() && port.find('-') != std::string::npos)
    {
        port_range = port;
        port.clear();
    }
    protocol = getUrlArg(addition, "protocol");
    if(!protocol_items.empty())
        protocol = protocol_items[0];
    if(protocol.empty())
        protocol = getUrlArg(addition, "transport");
    if(protocol.empty())
        protocol = "TCP";
    multiplexing = getUrlArg(addition, "multiplexing");
    if(multiplexing.empty())
        multiplexing = "MULTIPLEXING_LOW";
    handshake_mode = getUrlArg(addition, "handshake-mode");
    if(handshake_mode.empty())
        handshake_mode = getUrlArg(addition, "handshake_mode");
    mtu = getUrlArg(addition, "mtu");
    std::string udp_str = getUrlArg(addition, "udp");
    if(!udp_str.empty())
        udp = tribool(udp_str == "true" || udp_str == "1");
    std::string traffic_pattern = getUrlArg(addition, "traffic-pattern");
    if(traffic_pattern.empty())
        traffic_pattern = getUrlArg(addition, "traffic_pattern");
    if(remarks.empty())
        remarks = host;

    mieruConstruct(node, "MieruGroup", remarks, port, password, host, ports, username, multiplexing, protocol, udp, tfo, scv, tls13, "", port_range, handshake_mode, traffic_pattern);
}

void explodeStdAnyTLS(std::string anytls, Proxy &node)
{
    std::string add, port, password, sni, alpn, fingerprint, remarks, addition,idle_session_check_interval,idle_session_timeout,min_idle_session;
    std::string client_fingerprint;
    std::vector<std::string> alpnList;
    tribool tfo, scv;
    anytls = anytls.substr(9);
    string_size pos;
    pos = anytls.rfind("#");
    if(pos != anytls.npos)
    {
        remarks = urlDecode(anytls.substr(pos + 1));
        anytls.erase(pos);
    }
    pos = anytls.rfind("?");
    if(pos != anytls.npos)
    {
        addition = anytls.substr(pos + 1);
        anytls.erase(pos);
    }
    if(!anytls.empty() && anytls.back() == '/')
        anytls.pop_back();
    if(strFind(anytls, "@"))
    {
        if(regGetMatch(anytls, R"(^(.*?)@(.*?):(\d+)$)", 4, 0, &password, &add, &port) == 0)
        {
            password = urlDecode(password);
        }
        else if(regGetMatch(anytls, R"(^(.*?)@(.*)$)", 3, 0, &password, &add) == 0)
        {
            password = urlDecode(password);
            port = "443";
        }
        else
        {
            return;
        }
    }
    else
    {
        password = getUrlArg(addition, "password");
        if(password.empty()) return;
        if(regGetMatch(anytls, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
        {
            add = anytls;
            port = "443";
        }
    }
    if(port.empty())
        port = "443";
    sni = getUrlArg(addition, "sni");
    if(sni.empty())
        sni = getUrlArg(addition, "peer");
    alpn = getUrlArg(addition, "alpn");
    if (!alpn.empty()) alpnList.push_back(alpn);
    fingerprint = urlDecode(getUrlArg(addition, "hpkp"));
    client_fingerprint = getUrlArg(addition, "fp");
    if(client_fingerprint.empty())
        client_fingerprint = getUrlArg(addition, "client-fingerprint");
    tfo = tribool(getUrlArg(addition, "tfo"));
    scv = tribool(getUrlArg(addition, "insecure"));
    if(remarks.empty())
        remarks = add + ":" + port;
    anyTLSConstruct(node, "AnyTLS", remarks, add, port, password, sni, alpnList, fingerprint, idle_session_check_interval, idle_session_timeout, min_idle_session,tfo, scv, "");
    if(!client_fingerprint.empty())
        node.ClientFingerprint = client_fingerprint;
}

void explodeStdSudoku(std::string sudoku, Proxy &node)
{
    std::string add, port, key, aead, padding_min, padding_max, ascii, remarks, addition, http_mask;
    std::string http_mask_mode, http_mask_tls, http_mask_host, http_mask_multiplex, enable_pure_downlink, custom_table;
    std::string disable_http_mask, path_root, handshake_timeout;
    std::vector<std::string> custom_tables;
    string_size pos;

    // strip schema (allow sudoku:// and sudoku1://)
    pos = sudoku.find("://");
    if(pos != sudoku.npos)
        sudoku = sudoku.substr(pos + 3);

    pos = sudoku.rfind("#");
    if(pos != sudoku.npos)
    {
        remarks = urlDecode(sudoku.substr(pos + 1));
        sudoku.erase(pos);
    }

    pos = sudoku.rfind("?");
    if(pos != sudoku.npos)
    {
        addition = sudoku.substr(pos + 1);
        sudoku.erase(pos);
    }

    if(strFind(sudoku, "@"))
    {
        if(regGetMatch(sudoku, R"(^(.*)@(.*?):(\d+)$)", 4, 0, &key, &add, &port))
            return;
        key = urlDecode(key);
    }
    else
    {
        // try host:port
        if(regGetMatch(sudoku, R"(^(.*?):(\d+)$)", 3, 0, &add, &port))
        {
            // nothing
        }
        else
            return;
    }

    if(!addition.empty())
    {
        std::string key_from_query = getUrlArg(addition, "key");
        if(!key_from_query.empty())
            key = key_from_query;
        aead = getUrlArg(addition, "aead-method");
        if(aead.empty())
            aead = getUrlArg(addition, "aead_method");
        padding_min = getUrlArg(addition, "padding-min");
        if(padding_min.empty())
            padding_min = getUrlArg(addition, "padding_min");
        padding_max = getUrlArg(addition, "padding-max");
        if(padding_max.empty())
            padding_max = getUrlArg(addition, "padding_max");
        ascii = getUrlArg(addition, "table-type");
        if(ascii.empty())
            ascii = getUrlArg(addition, "table_type");
        http_mask = getUrlArg(addition, "http-mask");
        if(http_mask.empty())
            http_mask = getUrlArg(addition, "http_mask");
        http_mask_mode = getUrlArg(addition, "http-mask-mode");
        if(http_mask_mode.empty())
            http_mask_mode = getUrlArg(addition, "http_mask_mode");
        http_mask_tls = getUrlArg(addition, "http-mask-tls");
        if(http_mask_tls.empty())
            http_mask_tls = getUrlArg(addition, "http_mask_tls");
        http_mask_host = getUrlArg(addition, "http-mask-host");
        if(http_mask_host.empty())
            http_mask_host = getUrlArg(addition, "http_mask_host");
        http_mask_multiplex = getUrlArg(addition, "http-mask-multiplex");
        if(http_mask_multiplex.empty())
            http_mask_multiplex = getUrlArg(addition, "http_mask_multiplex");
        enable_pure_downlink = getUrlArg(addition, "enable-pure-downlink");
        if(enable_pure_downlink.empty())
            enable_pure_downlink = getUrlArg(addition, "enable_pure_downlink");
        disable_http_mask = getUrlArg(addition, "disable-http-mask");
        if(disable_http_mask.empty())
            disable_http_mask = getUrlArg(addition, "disable_http_mask");
        path_root = getUrlArg(addition, "path-root");
        if(path_root.empty())
            path_root = getUrlArg(addition, "path_root");
        handshake_timeout = getUrlArg(addition, "handshake-timeout");
        if(handshake_timeout.empty())
            handshake_timeout = getUrlArg(addition, "handshake_timeout");
        custom_table = getUrlArg(addition, "custom-table");
        if(custom_table.empty())
            custom_table = getUrlArg(addition, "custom_table");
        std::string custom_tables_str = getUrlArg(addition, "custom-tables");
        if(custom_tables_str.empty())
            custom_tables_str = getUrlArg(addition, "custom_tables");
        if(!custom_tables_str.empty())
            custom_tables = split(custom_tables_str, ",");
    }

    if(remarks.empty())
        remarks = add + ":" + port;

    sudokuConstruct(node, "SudokuGroup", remarks, add, port, key, aead, padding_min, padding_max, ascii, http_mask, http_mask_mode, http_mask_tls, http_mask_host, http_mask_multiplex, enable_pure_downlink, disable_http_mask, path_root, handshake_timeout, custom_table, custom_tables, "");
}

void explodeAnyTLS(std::string anytls, Proxy &node)
{
    anytls = regReplace(anytls, "(anytls)://", "anytls://");
    anytls = regReplace(anytls, "/\\?", "?", true, false);
    if(regMatch(anytls, "anytls://(.*?)[:](.*)"))
    {
        explodeStdAnyTLS(anytls, node);
        return;
    }
}

void explodeStdVLESS(std::string vless, Proxy &node)
{
    std::string add, port, type, uuid, aid, net, flow, public_key, short_id, fingerprint, mode, path, host, tls, remarks, sni, addition, alpn, encryption, security;
    std::string decoded, userinfo, hostinfo;
    string_array user_parts;
    std::vector<std::string> alpnList;
    tribool tfo, scv, vless_udp, v2ray_http_upgrade, v2ray_http_upgrade_fast_open;
    std::string packet_encoding, spider_x;
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
                    uuid = user_parts[1];
            }
            else
            {
                uuid = userinfo;
            }
            if(regGetMatch(hostinfo, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
                return;
        }
        else if(regGetMatch(vless, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
            return;
    }
    if(uuid.empty())
        return;

    if (!addition.empty())
    {
        sni = getUrlArg(addition, "sni");
        if(sni.empty())
            sni = getUrlArg(addition, "peer");
        net = getUrlArg(addition, "type");
        if(net.empty())
            net = "tcp";
        alpn = getUrlArg(addition, "alpn");
        if(!alpn.empty())
        {
            auto alpn_parts = split(alpn, ",");
            for(const auto &part : alpn_parts)
                alpnList.push_back(trim(part));
        }
        fingerprint = getUrlArg(addition, "fp");
        if(fingerprint.empty())
            fingerprint = getUrlArg(addition, "hpkp");
        flow = getUrlArg(addition, "flow");
        encryption = getUrlArg(addition, "encryption");
        public_key = getUrlArg(addition, "pbk");
        security = getUrlArg(addition, "security");
        short_id = getUrlArg(addition, "sid");
        if(short_id.empty())
            short_id = getUrlArg(addition, "short_id");
        spider_x = getUrlArg(addition, "spx");
        tfo = tribool(getUrlArg(addition, "tfo"));
        std::string insecure_val = getUrlArg(addition, "insecure");
        if (insecure_val.empty())
            insecure_val = getUrlArg(addition, "allowInsecure");
        scv = tribool(insecure_val);
        tls = security;  // Set tls to security value (tls/reality)

        std::string temp_val;
        if(!(temp_val = getUrlArg(addition, "udp")).empty())
            vless_udp = tribool(temp_val);
        if(!(temp_val = getUrlArg(addition, "xudp")).empty())
            node.XUDP = tribool(temp_val);
        if(!(temp_val = getUrlArg(addition, "fp")).empty() || !(temp_val = getUrlArg(addition, "client-fingerprint")).empty())
            node.ClientFingerprint = temp_val;
        if(!(temp_val = getUrlArg(addition, "packetEncoding")).empty() || !(temp_val = getUrlArg(addition, "packet-encoding")).empty())
        {
            packet_encoding = temp_val;
            node.PacketEncoding = temp_val;
        }
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
                host = getUrlArg(addition, "host");
                path = getUrlArg(addition, "path");
                break;
            case "xhttp"_hash:
                type = getUrlArg(addition, "headerType");
                host = getUrlArg(addition, "host");
                path = getUrlArg(addition, "path");
                mode = getUrlArg(addition, "mode");
                break;
            case "grpc"_hash:
                host = getUrlArg(addition, "sni");
                path = getUrlArg(addition, "serviceName");
                if(path.empty())
                    path = getUrlArg(addition, "grpc-service-name");
                mode = getUrlArg(addition, "mode");
                break;
            case "quic"_hash:
                type = getUrlArg(addition, "headerType");
                host = getUrlArg(addition, "quicSecurity");
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
    node.TLSSecure = security == "tls" || security == "reality";

    vlessConstruct(node, VLESS_DEFAULT_GROUP, remarks, add, port, type, uuid, net, "", flow, mode, path, host, "", tls, public_key, short_id, fingerprint, sni, alpnList, packet_encoding, encryption, vless_udp, tfo, scv, tribool(), "", v2ray_http_upgrade, v2ray_http_upgrade_fast_open, tribool(), tribool(), "", "", spider_x);
    return;
}

void explodeVLESS(std::string vless, Proxy &node)
{
    vless = regReplace(vless, "(vless)://", "vless://");
    vless = regReplace(vless, "/\\?", "?", true, false);
    explodeStdVLESS(vless, node);
}

void explodeSudoku(std::string sudoku, Proxy &node)
{
    sudoku = regReplace(sudoku, "(sudoku)://", "sudoku://");
    sudoku = regReplace(sudoku, "/\\?", "?", true, false);
    explodeStdSudoku(sudoku, node);
}

void explodeStdTrustTunnel(std::string trusttunnel, Proxy &node)
{
    std::string auth, endpoint, add, port, remarks, addition;
    std::string user, password, sni, alpn, client_fingerprint, congestion_controller;
    std::vector<std::string> alpnList;
    tribool health_check, udp, scv, quic;
    string_size pos;

    trusttunnel = regReplace(trusttunnel, "^trusttunnel://", "");
    pos = trusttunnel.rfind("#");
    if(pos != trusttunnel.npos)
    {
        remarks = urlDecode(trusttunnel.substr(pos + 1));
        trusttunnel.erase(pos);
    }
    pos = trusttunnel.rfind("?");
    if(pos != trusttunnel.npos)
    {
        addition = trusttunnel.substr(pos + 1);
        trusttunnel.erase(pos);
    }
    if(regGetMatch(trusttunnel, R"(^(.*?)@(.*)$)", 3, 0, &auth, &endpoint) != 0)
        return;
    std::string decoded_auth = urlSafeBase64Decode(auth);
    if(!strFind(decoded_auth, ":"))
        decoded_auth = base64Decode(auth);
    if(!strFind(decoded_auth, ":"))
        decoded_auth = urlDecode(auth);
    if(!strFind(decoded_auth, ":"))
        return;
    pos = decoded_auth.find(':');
    user = decoded_auth.substr(0, pos);
    password = decoded_auth.substr(pos + 1);
    if(!endpoint.empty() && endpoint.front() == '[')
    {
        const auto close = endpoint.find(']');
        if(close == std::string::npos || close + 1 >= endpoint.size() || endpoint[close + 1] != ':')
            return;
        add = endpoint.substr(0, close + 1);
        port = endpoint.substr(close + 2);
    }
    else
    {
        if(regGetMatch(endpoint, R"(^(.*?):(\d+)$)", 3, 0, &add, &port) != 0)
            return;
    }
    auto parse_bool = [](const std::string &v) -> tribool {
        if(v.empty())
            return tribool();
        const std::string lv = toLower(v);
        if(lv == "1" || lv == "true")
            return tribool(true);
        if(lv == "0" || lv == "false")
            return tribool(false);
        return tribool();
    };
    sni = getUrlArg(addition, "sni");
    if(sni.empty())
        sni = getUrlArg(addition, "peer");
    alpn = getUrlArg(addition, "alpn");
    if(!alpn.empty())
    {
        auto parts = split(alpn, ",");
        for(const auto &p : parts)
            alpnList.emplace_back(trim(p));
    }
    client_fingerprint = getUrlArg(addition, "client-fingerprint");
    if(client_fingerprint.empty())
        client_fingerprint = getUrlArg(addition, "client_fingerprint");
    health_check = parse_bool(getUrlArg(addition, "health-check"));
    if(health_check.is_undef())
        health_check = parse_bool(getUrlArg(addition, "health_check"));
    udp = parse_bool(getUrlArg(addition, "udp"));
    scv = parse_bool(getUrlArg(addition, "skip-cert-verify"));
    if(scv.is_undef())
        scv = parse_bool(getUrlArg(addition, "skip_cert_verify"));
    if(scv.is_undef())
        scv = parse_bool(getUrlArg(addition, "insecure"));
    quic = parse_bool(getUrlArg(addition, "quic"));
    congestion_controller = getUrlArg(addition, "congestion-controller");
    if(congestion_controller.empty())
        congestion_controller = getUrlArg(addition, "congestion_controller");
    if(remarks.empty())
        remarks = add + ":" + port;

    trusttunnelConstruct(node, TRUSTTUNNEL_DEFAULT_GROUP, remarks, add, port, user, password, sni, alpnList, client_fingerprint, health_check, udp, scv, quic, congestion_controller, "");
}

void explodeTTDeepLink(std::string tt, Proxy &node)
{
    std::string remarks;
    std::string payload;
    string_size pos = tt.rfind("#");
    if(pos != tt.npos)
    {
        remarks = urlDecode(tt.substr(pos + 1));
        tt.erase(pos);
    }
    if(!startsWith(tt, "tt://?"))
        return;
    payload = tt.substr(6);
    if(payload.empty())
        return;
    std::string raw = urlSafeBase64Decode(payload);
    if(raw.empty())
        return;
    auto read_varint = [&raw](string_size &offset, uint64_t &value) -> bool {
        if(offset >= raw.size())
            return false;
        const auto first = static_cast<unsigned char>(raw[offset]);
        const auto prefix = (first >> 6) & 0x03;
        const string_size len = static_cast<string_size>(1u << prefix);
        if(offset + len > raw.size())
            return false;
        value = first & 0x3Fu;
        for(string_size i = 1; i < len; i++)
            value = (value << 8) | static_cast<unsigned char>(raw[offset + i]);
        offset += len;
        return true;
    };
    auto parse_bool_byte = [](const std::string &v) -> tribool {
        if(v.empty())
            return tribool();
        const auto b = static_cast<unsigned char>(v[0]);
        if(b == 0x01)
            return tribool(true);
        if(b == 0x00)
            return tribool(false);
        return tribool();
    };
    auto split_addr = [](const std::string &address, std::string &host, std::string &port) -> bool {
        if(address.empty())
            return false;
        if(address.front() == '[')
        {
            const auto close = address.find(']');
            if(close == std::string::npos || close + 1 >= address.size() || address[close + 1] != ':')
                return false;
            host = address.substr(0, close + 1);
            port = address.substr(close + 2);
            return !host.empty() && !port.empty();
        }
        const auto p = address.rfind(':');
        if(p == std::string::npos || p == 0 || p + 1 >= address.size())
            return false;
        host = address.substr(0, p);
        port = address.substr(p + 1);
        return !host.empty() && !port.empty();
    };
    std::string hostname, add, port, sni, user, password;
    tribool scv, quic;
    string_size offset = 0;
    while(offset < raw.size())
    {
        uint64_t tag = 0, len = 0;
        if(!read_varint(offset, tag) || !read_varint(offset, len))
            return;
        if(offset + static_cast<string_size>(len) > raw.size())
            return;
        const std::string value = raw.substr(offset, static_cast<string_size>(len));
        offset += static_cast<string_size>(len);
        switch(tag)
        {
            case 0x01:
                hostname = value;
                break;
            case 0x02:
                if(add.empty() || port.empty())
                    split_addr(value, add, port);
                break;
            case 0x03:
                sni = value;
                break;
            case 0x05:
                user = value;
                break;
            case 0x06:
                password = value;
                break;
            case 0x07:
                scv = parse_bool_byte(value);
                break;
            case 0x09:
            {
                string_size protocol_off = 0;
                uint64_t proto = 0;
                if(read_varint(protocol_off, proto))
                {
                    if(proto == 0x02)
                        quic = tribool(true);
                    else if(proto == 0x01)
                        quic = tribool(false);
                }
                break;
            }
            case 0x0C:
                if(remarks.empty())
                    remarks = value;
                break;
            default:
                break;
        }
    }
    if(add.empty())
        add = hostname;
    if(port.empty())
        port = "443";
    if(sni.empty())
        sni = hostname;
    if(user.empty() || password.empty() || add.empty())
        return;
    if(remarks.empty())
        remarks = hostname.empty() ? (add + ":" + port) : hostname;

    trusttunnelConstruct(node, TRUSTTUNNEL_DEFAULT_GROUP, remarks, add, port, user, password, sni, {}, "", tribool(), tribool(), scv, quic, "", "");
}

void explodeTrustTunnel(std::string trusttunnel, Proxy &node)
{
    if(startsWith(trusttunnel, "tt://?"))
    {
        explodeTTDeepLink(trusttunnel, node);
        return;
    }
    trusttunnel = regReplace(trusttunnel, "(trusttunnel)://", "trusttunnel://");
    trusttunnel = regReplace(trusttunnel, "/\\?", "?", true, false);
    if(startsWith(trusttunnel, "trusttunnel://"))
        explodeStdTrustTunnel(trusttunnel, node);
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

static string_array splitLoonConfig(const std::string &config)
{
    string_array result;
    std::string current;
    bool in_quotes = false;
    int nesting_depth = 0;
    auto update_nesting = [&nesting_depth](char ch)
    {
        if(ch == '[' || ch == '{' || ch == '(')
            ++nesting_depth;
        else if((ch == ']' || ch == '}' || ch == ')') && nesting_depth > 0)
            --nesting_depth;
    };
    for(size_t i = 0; i < config.size(); ++i)
    {
        const char ch = config[i];
        if(ch == '"' && (i == 0 || config[i - 1] != '\\'))
            in_quotes = !in_quotes;
        if(!in_quotes)
        {
            if(ch == ',')
            {
                if(nesting_depth == 0)
                {
                    result.emplace_back(trim(current));
                    current.clear();
                    continue;
                }
            }
            else
                update_nesting(ch);
        }
        current.push_back(ch);
    }
    if(!current.empty())
        result.emplace_back(trim(current));
    return result;
}

static std::vector<std::string> parseLoonAlpn(const std::string &value)
{
    std::vector<std::string> alpn_list;
    for(const auto &item : split(value, ","))
    {
        const auto trimmed = trim(trimQuote(item));
        if(!trimmed.empty())
            alpn_list.emplace_back(trimmed);
    }
    return alpn_list;
}

static bool isLoonProxyType(const std::string &proxy_type)
{
    switch(hash_(toLower(trim(proxy_type))))
    {
    case "shadowsocks"_hash:
    case "shadowsocksr"_hash:
    case "vmess"_hash:
    case "vless"_hash:
    case "trojan"_hash:
    case "http"_hash:
    case "https"_hash:
    case "socks5"_hash:
    case "wireguard"_hash:
    case "hysteria2"_hash:
        return true;
    default:
        return false;
    }
}

static bool looksLikeLoon(const std::string &content)
{
    std::multimap<std::string, std::string> proxies;
    INIReader ini;
    std::string loon = content;
    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.set_isolated_items_section("Proxy");
    ini.add_direct_save_section("Proxy");
    if(loon.find("[Proxy]") != loon.npos)
        loon = regReplace(loon, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(loon);
    if(!ini.section_exist("Proxy"))
        return false;
    ini.enter_section("Proxy");
    ini.get_items(proxies);
    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";
    for(const auto &item : proxies)
    {
        std::string remarks, config;
        regGetMatch(item.second, proxystr, 3, 0, &remarks, &config);
        auto configs = splitLoonConfig(config);
        if(configs.empty())
            continue;
        if(isLoonProxyType(configs[0]))
            return true;
    }
    return false;
}

bool explodeLoon(std::string loon, std::vector<Proxy> &nodes)
{
    std::multimap<std::string, std::string> proxies;
    const auto original_size = nodes.size();
    uint32_t index = original_size;
    INIReader ini;
    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.set_isolated_items_section("Proxy");
    ini.add_direct_save_section("Proxy");
    if(loon.find("[Proxy]") != loon.npos)
        loon = regReplace(loon, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(loon);
    if(!ini.section_exist("Proxy"))
        return false;
    ini.enter_section("Proxy");
    ini.get_items(proxies);
    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";
    for(auto &x : proxies)
    {
        std::string remarks, server, port, method, username, password, sni; //common
        std::string plugin, pluginopts, obfs_mode, obfs_host; //ss
        std::string id, net = "tcp", tls, host, path, flow, shortid, aead = "0"; //v2/vless
        std::string protocol, protoparam, obfs, obfs_param; //ssr
        std::string ip, ipv6, private_key, public_key, mtu, peer_data, keepalive, psk, allowed_ips; //wireguard
        std::string up, down, ports, fingerprint; //hysteria2
        std::string underlying_proxy;
        std::string itemName, itemVal, config;
        std::vector<std::string> configs, alpn_list;
        string_array dns_servers, reserved;
        tribool udp, tfo, scv, tls13;
        bool parsed = false;
        size_t option_start = 0;
        Proxy node;

        regGetMatch(x.second, proxystr, 3, 0, &remarks, &config);
        remarks = remarks.empty() ? x.first : remarks;
        configs = splitLoonConfig(config);
        if(configs.empty())
            continue;
        const std::string proxy_type = toLower(trim(configs[0]));
        switch(hash_(proxy_type))
        {
        case "shadowsocks"_hash:
            if(configs.size() < 5)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            method = trim(configs[3]);
            password = trimQuote(trim(configs[4]));
            if(port == "0")
                continue;
            for(size_t i = 5; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "obfs-name"_hash:
                    plugin = "simple-obfs";
                    obfs_mode = itemVal;
                    break;
                case "obfs-host"_hash:
                    obfs_host = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            if(!plugin.empty())
            {
                pluginopts = "obfs=" + obfs_mode;
                if(!obfs_host.empty())
                    pluginopts += ";obfs-host=" + obfs_host;
            }
            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv, tribool(), underlying_proxy);
            parsed = true;
            break;
        case "shadowsocksr"_hash:
            if(configs.size() < 5)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            method = trim(configs[3]);
            password = trimQuote(trim(configs[4]));
            if(port == "0")
                continue;
            for(size_t i = 5; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "protocol"_hash:
                    protocol = itemVal;
                    break;
                case "protocol-param"_hash:
                    protoparam = itemVal;
                    break;
                case "obfs"_hash:
                    obfs = itemVal;
                    break;
                case "obfs-param"_hash:
                    obfs_param = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, password, obfs_param, protoparam, udp, tfo, scv, underlying_proxy);
            parsed = true;
            break;
        case "vmess"_hash:
            if(configs.size() < 5)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            method = trim(configs[3]);
            id = trimQuote(trim(configs[4]));
            if(port == "0")
                continue;
            for(size_t i = 5; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "transport"_hash:
                    net = itemVal;
                    break;
                case "alterid"_hash:
                    aead = itemVal;
                    break;
                case "path"_hash:
                    path = itemVal;
                    break;
                case "host"_hash:
                    host = itemVal;
                    break;
                case "over-tls"_hash:
                    tls = tribool(itemVal).get(false) ? "tls" : "";
                    break;
                case "tls-name"_hash:
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "tls13"_hash:
                    tls13 = itemVal;
                    break;
                case "alpn"_hash:
                    alpn_list = parseLoonAlpn(itemVal);
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, "", tls, sni, alpn_list, udp, tfo, scv, tls13, underlying_proxy);
            parsed = true;
            break;
        case "vless"_hash:
            if(configs.size() < 4)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            id = trimQuote(trim(configs[3]));
            if(port == "0")
                continue;
            for(size_t i = 4; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "transport"_hash:
                    net = itemVal;
                    break;
                case "path"_hash:
                    path = itemVal;
                    break;
                case "host"_hash:
                    host = itemVal;
                    break;
                case "flow"_hash:
                    flow = itemVal;
                    break;
                case "public-key"_hash:
                    public_key = itemVal;
                    break;
                case "short-id"_hash:
                    shortid = itemVal;
                    break;
                case "over-tls"_hash:
                    tls = tribool(itemVal).get(false) ? "tls" : "";
                    break;
                case "tls-name"_hash:
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "tls13"_hash:
                    tls13 = itemVal;
                    break;
                case "alpn"_hash:
                    alpn_list = parseLoonAlpn(itemVal);
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            vlessConstruct(node, VLESS_DEFAULT_GROUP, remarks, server, port, "", id, net, "", flow, "", path, host, "", tls, public_key, shortid, "", sni, alpn_list, "", "", udp, tfo, scv, tls13, underlying_proxy);
            parsed = true;
            break;
        case "trojan"_hash:
            if(configs.size() < 4)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            password = trimQuote(trim(configs[3]));
            if(port == "0")
                continue;
            for(size_t i = 4; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "transport"_hash:
                    net = itemVal;
                    break;
                case "path"_hash:
                    path = itemVal;
                    break;
                case "host"_hash:
                    host = itemVal;
                    break;
                case "tls-name"_hash:
                case "sni"_hash:
                    sni = itemVal;
                    if(host.empty())
                        host = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "alpn"_hash:
                    alpn_list = parseLoonAlpn(itemVal);
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, net, host, path, "", sni, alpn_list, true, udp, tfo, scv, tribool(), underlying_proxy);
            parsed = true;
            break;
        case "http"_hash:
        case "https"_hash:
            if(configs.size() < 3)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            option_start = 3;
            if(configs.size() > 3 && configs[3].find('=') == std::string::npos)
            {
                username = trimQuote(trim(configs[3]));
                option_start = 4;
                if(configs.size() > 4 && configs[4].find('=') == std::string::npos)
                {
                    password = trimQuote(trim(configs[4]));
                    option_start = 5;
                }
            }
            for(size_t i = option_start; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "tls-name"_hash:
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, proxy_type == "https", tfo, scv, tribool(), underlying_proxy, "", "", "", "", sni, udp);
            parsed = true;
            break;
        case "socks5"_hash:
            if(configs.size() < 3)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            {
                bool over_tls = false;
                option_start = 3;
                if(configs.size() > 3 && configs[3].find('=') == std::string::npos)
                {
                    username = trimQuote(trim(configs[3]));
                    option_start = 4;
                    if(configs.size() > 4 && configs[4].find('=') == std::string::npos)
                    {
                        password = trimQuote(trim(configs[4]));
                        option_start = 5;
                    }
                }
                for(size_t i = option_start; i < configs.size(); ++i)
                {
                    auto pos = configs[i].find('=');
                    if(pos == std::string::npos)
                        continue;
                    itemName = toLower(trim(configs[i].substr(0, pos)));
                    itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                    switch(hash_(itemName))
                    {
                    case "over-tls"_hash:
                        over_tls = tribool(itemVal).get(false);
                        break;
                    case "tls-name"_hash:
                    case "sni"_hash:
                        sni = itemVal;
                        break;
                    case "skip-cert-verify"_hash:
                        scv = itemVal;
                        break;
                    case "udp"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "underlying-proxy"_hash:
                        underlying_proxy = itemVal;
                        break;
                    default:
                        break;
                    }
                }
                socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv, underlying_proxy, "", over_tls, "", "", "", sni);
            }
            parsed = true;
            break;
        case "wireguard"_hash:
            for(size_t i = 1; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trim(configs[i].substr(pos + 1));
                switch(hash_(itemName))
                {
                case "interface-ip"_hash:
                    ip = trimQuote(itemVal);
                    break;
                case "interface-ipv6"_hash:
                    ipv6 = trimQuote(itemVal);
                    break;
                case "private-key"_hash:
                    private_key = trimQuote(itemVal);
                    break;
                case "dns"_hash:
                case "dnsv6"_hash:
                    dns_servers.emplace_back(trimQuote(itemVal));
                    break;
                case "mtu"_hash:
                    mtu = trimQuote(itemVal);
                    break;
                case "keepalive"_hash:
                case "keeyalive"_hash:
                    keepalive = trimQuote(itemVal);
                    break;
                case "peers"_hash:
                    peer_data = trim(itemVal);
                    break;
                case "udp"_hash:
                    udp = trimQuote(itemVal);
                    break;
                default:
                    break;
                }
            }
            if(!peer_data.empty())
            {
                auto peer_matches = regGetAllMatch(peer_data, R"(\{(.*?)\})", true);
                if(!peer_matches.empty())
                {
                    for(const auto &peer_field : splitLoonConfig(peer_matches[0]))
                    {
                        auto pos = peer_field.find('=');
                        if(pos == std::string::npos)
                            continue;
                        itemName = toLower(trim(peer_field.substr(0, pos)));
                        itemVal = trimQuote(trim(peer_field.substr(pos + 1)));
                        switch(hash_(itemName))
                        {
                        case "public-key"_hash:
                            public_key = itemVal;
                            break;
                        case "preshared-key"_hash:
                            psk = itemVal;
                            break;
                        case "allowed-ips"_hash:
                            allowed_ips = itemVal;
                            break;
                        case "endpoint"_hash:
                            if(itemVal.rfind(':') != std::string::npos)
                            {
                                server = itemVal.substr(0, itemVal.rfind(':'));
                                port = itemVal.substr(itemVal.rfind(':') + 1);
                            }
                            break;
                        case "reserved"_hash:
                        {
                            auto reserved_value = trimOf(itemVal, '[', true, false);
                            reserved_value = trimOf(reserved_value, ']', false, true);
                            for(const auto &item : split(reserved_value, ","))
                            {
                                const auto trimmed = trim(item);
                                if(!trimmed.empty())
                                    reserved.emplace_back(trimmed);
                            }
                            break;
                        }
                        default:
                            break;
                        }
                    }
                }
            }
            wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, server, port, ip, ipv6, private_key, public_key, psk, dns_servers, mtu, keepalive, "", "", udp);
            if(!allowed_ips.empty())
                node.AllowedIPs = allowed_ips;
            if(!reserved.empty())
                node.Reserved = reserved;
            parsed = true;
            break;
        case "hysteria2"_hash:
            if(configs.size() < 4)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            password = trimQuote(trim(configs[3]));
            if(port == "0")
                continue;
            for(size_t i = 4; i < configs.size(); ++i)
            {
                auto pos = configs[i].find('=');
                if(pos == std::string::npos)
                    continue;
                itemName = toLower(trim(configs[i].substr(0, pos)));
                itemVal = trimQuote(trim(configs[i].substr(pos + 1)));
                switch(hash_(itemName))
                {
                case "tls-name"_hash:
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "tls-cert-sha256"_hash:
                case "fingerprint"_hash:
                    fingerprint = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "udp"_hash:
                    udp = itemVal;
                    break;
                case "fast-open"_hash:
                    tfo = itemVal;
                    break;
                case "upload-bandwidth"_hash:
                    up = itemVal;
                    break;
                case "download-bandwidth"_hash:
                    down = itemVal;
                    break;
                case "ports"_hash:
                    ports = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    break;
                }
            }
            hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remarks, server, port, ports, up, down, password, "", "", "", sni, fingerprint, "", "", "", "", "", "", "", "", "", "", "", udp, tfo, scv, underlying_proxy);
            parsed = true;
            break;
        default:
            break;
        }
        if(!parsed)
            continue;
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
    return nodes.size() > original_size;
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
        std::string id, net, tls, host, edge, path, fp, flow, shortid; //v2
        std::string protocol, protoparam; //ssr
        std::string section, ip, ipv6, private_key, public_key, mtu, test_url, client_id, peer, keepalive; //wireguard
        std::string type, fingerprint; //vless
        std::string up, down, ports, hop_interval; //hysteria2/surfboard
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
        case "socks5-tls"_hash: //surfboard style socks5-tls proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            {
                const bool socks_tls = hash_(configs[0]) == "socks5-tls"_hash;
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
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv, underlying_proxy, "", socks_tls, "", "", "", sni);
            }
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
        case "https"_hash: //surfboard style https proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            tls = hash_(configs[0]) == "https"_hash ? "tls" : "";
            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitKeyValue(configs[i], "=");
                if(vArray.size() < 2)
                {
                    // Surfboard allows positional auth fields for http/https.
                    if(i == 3)
                        username = trim(configs[i]);
                    else if(i == 4)
                        password = trim(configs[i]);
                    continue;
                }
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
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, tls == "tls", tfo, scv, tribool(), underlying_proxy, "", "", "", "", sni, udp);
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
        case "hysteria2"_hash:
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
                case "download-bandwidth"_hash:
                    down = itemVal;
                    break;
                case "upload-bandwidth"_hash:
                    up = itemVal;
                    break;
                case "port-hopping"_hash:
                    ports = trimQuote(itemVal);
                    break;
                case "port-hopping-interval"_hash:
                    hop_interval = itemVal;
                    break;
                case "sni"_hash:
                    sni = itemVal;
                    break;
                case "server-cert-fingerprint-sha256"_hash:
                case "fingerprint"_hash:
                    fingerprint = itemVal;
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
                case "underlying-proxy"_hash:
                    underlying_proxy = itemVal;
                    break;
                default:
                    continue;
                }
            }
            hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remarks, server, port, ports, up, down, password, "", "", "", sni, fingerprint, "", "", "", "", hop_interval, "", "", "", "", "", "", udp, tfo, scv, underlying_proxy);
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
                        case "http"_hash:
                        case "vmess-http"_hash:
                            net = "http";
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
                    case "tls-host"_hash:
                        host = itemVal;
                        break;
                    case "tls-verification"_hash:
                        scv = itemVal == "false";
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
                    case "reality-base64-pubkey"_hash:
                        public_key = itemVal;
                        break;
                    case "reality-hex-shortid"_hash:
                        shortid = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, "", tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13, underlying_proxy, fingerprint, fp);
                if(!public_key.empty())
                    node.PublicKey = public_key;
                if(!shortid.empty())
                    node.ShortID = shortid;
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
                    case "obfs"_hash:
                        if(itemVal == "wss")
                            net = "ws";
                        break;
                    case "obfs-host"_hash:
                        host = itemVal;
                        sni = itemVal;
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
                    case "tls-verification"_hash:
                        scv = itemVal == "false";
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "fp"_hash:
                        fp = itemVal;
                        break;
                    case "reality-base64-pubkey"_hash:
                        public_key = itemVal;
                        break;
                    case "reality-hex-shortid"_hash:
                        shortid = itemVal;
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

                trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, net, host, path, fp, sni, std::vector<std::string>{}, tls == "true" || net == "ws", udp, tfo, scv, tls13, underlying_proxy);
                if(!public_key.empty())
                    node.PublicKey = public_key;
                if(!shortid.empty())
                    node.ShortID = shortid;
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
                    case "tls-host"_hash:
                        sni = itemVal;
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "reality-base64-pubkey"_hash:
                        public_key = itemVal;
                        break;
                    case "reality-hex-shortid"_hash:
                        shortid = itemVal;
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

                httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, tls == "true", tfo, scv, tls13, underlying_proxy, "", "", "", "", sni, udp);
                if(!public_key.empty())
                    node.PublicKey = public_key;
                if(!shortid.empty())
                    node.ShortID = shortid;
                break;
            case "socks5"_hash: //quantumult x style socks5 links
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
                    case "tls-host"_hash:
                        sni = itemVal;
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "reality-base64-pubkey"_hash:
                        public_key = itemVal;
                        break;
                    case "reality-hex-shortid"_hash:
                        shortid = itemVal;
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

                socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv, underlying_proxy, "", tls == "true", "", "", "", sni);
                if(!public_key.empty())
                    node.PublicKey = public_key;
                if(!shortid.empty())
                    node.ShortID = shortid;
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
                                case "http"_hash:
                                    net = "http";
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
                        case "tls-host"_hash:
                            host = itemVal;
                            sni = itemVal;
                            break;
                        case "over-tls"_hash:
                            tls = itemVal == "true" ? "tls" : "";
                            break;
                        case "tls-verification"_hash:
                            scv = itemVal == "false";
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
                        case "reality-base64-pubkey"_hash:
                            public_key = itemVal;
                            break;
                        case "reality-hex-shortid"_hash:
                            shortid = itemVal;
                            break;
                        case "vless-flow"_hash:
                            flow = itemVal;
                            break;
                        case "fingerprint"_hash:
                            fingerprint = itemVal;
                            break;
                        case "underlying-proxy"_hash:
                            underlying_proxy = itemVal;
                            break;
                        case "aead"_hash:
                            aead = itemVal == "true" ? "0" : "1";
                            break;
                        default:
                            continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                vlessConstruct(node, VLESS_DEFAULT_GROUP, remarks, server, port, type, id, net, "", flow, "", path, host, "", tls, public_key, shortid, fingerprint, sni, std::vector<std::string>{}, "", "", udp, tfo, scv, tls13, underlying_proxy, tribool(), tribool(), tribool(), tribool(), "", "", "");
                break;
            case "anytls"_hash:
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
                    case "tls-host"_hash:
                        sni = itemVal;
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
                    case "reality-base64-pubkey"_hash:
                        public_key = itemVal;
                        break;
                    case "reality-hex-shortid"_hash:
                        shortid = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;
                anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, server, port, password, sni, std::vector<std::string>{}, "", "", "", "", tfo, scv, tls13, underlying_proxy);
                if(!public_key.empty())
                    node.PublicKey = public_key;
                if(!shortid.empty())
                    node.ShortID = shortid;
                break;
            case "hysteria2"_hash:
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
                    case "up"_hash:
                    case "upload-bandwidth"_hash:
                        up = itemVal;
                        break;
                    case "down"_hash:
                    case "download-bandwidth"_hash:
                        down = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "sni"_hash:
                    case "tls-host"_hash:
                        sni = itemVal;
                        break;
                    case "server-cert-fingerprint-sha256"_hash:
                    case "fingerprint"_hash:
                    case "tls-cert-sha256"_hash:
                        fingerprint = itemVal;
                        break;
                    case "port-hopping"_hash:
                        ports = trimQuote(itemVal);
                        break;
                    case "port-hopping-interval"_hash:
                        hop_interval = itemVal;
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
                    case "underlying-proxy"_hash:
                        underlying_proxy = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;
                hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remarks, server, port, ports, up, down, password, "", "", "", sni, fingerprint, "", "", "", "", hop_interval, "", "", "", "", "", "", udp, tfo, scv, underlying_proxy);
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
        rapidjson::Value &transport = singboxNode["transport"];
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
                    rapidjson::Value &headers = transport["headers"];
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
            std::string token, uuid,/*ip , password*/ heartbeat_interval, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, fast_open, tuic_version;   //tuic
            std::string short_id, packet_encoding, encryption, spider_x; // vless
            std::string idle_session_check_interval, idle_session_timeout, min_idle_session; // anyTLS
            string_array dns_server;
            tribool udp = tribool(), tfo = tribool(), scv = tribool(), disablesni = tribool();
            rapidjson::Value &singboxNode = outbounds[i];
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
                    rapidjson::Value &tlsObj = singboxNode["tls"];
                    if(tlsObj.HasMember("enabled") && tlsObj["enabled"].IsBool() && tlsObj["enabled"].GetBool())
                        tls = "tls";
                    sni = GetMember(tlsObj, "server_name");
                    if(tlsObj.HasMember("alpn") && tlsObj["alpn"].IsArray() && !tlsObj["alpn"].Empty())
                    {
                        auto &alpns = tlsObj["alpn"];
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
                        scv = tlsObj["insecure"].GetBool();
                    if(tlsObj.HasMember("disable_sni") && tlsObj["disable_sni"].IsBool())
                        disablesni = tlsObj["disable_sni"].GetBool();
                    if(tlsObj.HasMember("certificate") && tlsObj["certificate"].IsString())
                        ca_str = tlsObj["certificate"].GetString();
                    if(tlsObj.HasMember("reality") && tlsObj["reality"].IsObject())
                    {
                        tls = "reality";
                        rapidjson::Value &reality = tlsObj["reality"];
                        if(reality.HasMember("server_name") && reality["server_name"].IsString())
                            host = reality["server_name"].GetString();
                        if(reality.HasMember("public_key") && reality["public_key"].IsString())
                            public_key = reality["public_key"].GetString();
                        if(reality.HasMember("short_id") && reality["short_id"].IsString())
                            short_id = reality["short_id"].GetString();
                    }
                }
                else
                    tls = "false";
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
                            auth_str = GetMember(singboxNode, "auth_str");
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
                            rapidjson::Value &obfsOpt = singboxNode["obfs"];
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
                        encryption = GetMember(singboxNode, "encryption");
                        packet_encoding = GetMember(singboxNode, "packet_encoding");
                        if(singboxNode.HasMember("transport") && singboxNode["transport"].IsObject())
                        {
                            rapidjson::Value &transport = singboxNode["transport"];
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
                                        rapidjson::Value &headers = transport["headers"];
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
                        vlessConstruct(node, group, ps, server, port, type, id, net, "", flow, mode, path, host, "", tls, public_key, short_id, fingerprint, sni, alpnList, packet_encoding, encryption, udp, tfo, scv, tribool(), underlying_proxy, tribool(), tribool(), tribool(), tribool(), "", "", spider_x);
                        break;
                    case "tuic"_hash:
                        group = TUIC_DEFAULT_GROUP;
                        token = GetMember(singboxNode, "token");
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
                        TUICConstruct(node, group, ps, server, port, uuid, password, ip, heartbeat_interval, alpn, disable_sni, reduce_rtt, request_timeout, udp_relay_mode, congestion_controller, max_udp_relay_packet_size, max_open_streams, sni, fast_open, token, tuic_version, tfo, scv, underlying_proxy, tribool(), 0);
                        break;
                    case "anytls"_hash:
                        group = ANYTLS_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, server, port, password, sni, alpnList, fingerprint, idle_session_check_interval, idle_session_timeout, min_idle_session, tfo, scv, underlying_proxy);
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
    else if(startsWith(link, "masque://"))
        explodeMasque(link, node);
    else if(startsWith(link, "tuic://"))
        explodeTUIC(link, node);
    else if(startsWith(link, "anytls://"))
        explodeAnyTLS(link, node);
    else if(startsWith(link, "vless://") || startsWith(link, "vless1://"))
        explodeVLESS(link, node);
    else if(startsWith(link, "sudoku://") || startsWith(link, "sudoku1://"))
        explodeSudoku(link, node);
    else if(startsWith(link, "mierus://") || startsWith(link, "mieru://"))
        explodeMierus(link, node);
    else if(startsWith(link, "wireguard://") || startsWith(link, "wg://"))
        explodeWireguard(link, node);
    else if(startsWith(link, "trusttunnel://") || startsWith(link, "tt://?"))
        explodeTrustTunnel(link, node);
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
                        continue;
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
        throw;
    }
    //try to parse as loon configuration
    if(!processed && looksLikeLoon(sub) && explodeLoon(sub, nodes))
    {
        processed = true;
    }

    //try to parse as surge configuration
    if(!processed && explodeSurge(sub, nodes))
    {
        processed = true;
    }

    //try to parse as normal subscription
    if(!processed)
    {
        sub = urlSafeBase64Decode(sub);
        if(regFind(sub, "(?i)(vmess|shadowsocks|shadowsocksr|http|https|trojan|vless|hysteria2|wireguard|socks5)\\s*?="))
        {
            if(looksLikeLoon(sub) && explodeLoon(sub, nodes))
                return;
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
