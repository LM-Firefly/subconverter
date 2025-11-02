#ifndef SUBPARSER_H_INCLUDED
#define SUBPARSER_H_INCLUDED

#include <string>

#include "config/proxy.h"

enum class ConfType
{
    Unknow,
    SS,
    SSR,
    V2Ray,
    SSConf,
    SSTap,
    Netch,
    SOCKS,
    HTTP,
    SUB,
    Local
};

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &sni, const std::vector<std::string> &alpnList, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "", const std::string &fingerprint = "", const std::string &clientFingerprint = "", tribool v2ray_http_upgrade = tribool(), tribool v2ray_http_upgrade_fast_open = tribool());
void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &protocol, const std::string &method, const std::string &obfs, const std::string &password, const std::string &obfsparam, const std::string &protoparam, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &method, const std::string &plugin, const std::string &pluginopts, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool udp_over_tcp = tribool(), const std::string &underlying_proxy = "");
void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, bool tls, tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "");
void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &network, const std::string &host, const std::string &path, const std::string &fp, const std::string &sni, const std::vector<std::string> &alpnList, bool tlssecure, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "", tribool v2ray_http_upgrade = tribool(), tribool v2ray_http_upgrade_fast_open = tribool());
void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &obfs, const std::string &host, uint16_t version = 0, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void hysteriaConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &ports, const std::string &protocol, const std::string &obfs_protocol, const std::string &up, const std::string &up_speed, const std::string &down, const std::string &down_speed, const std::string &auth, const std::string &auth_str, const std::string &obfs, const std::string &sni, const std::string &fingerprint, const std::string &ca, const std::string &ca_str, const std::string &recv_window_conn, const std::string &recv_window, const std::string &disable_mtu_discovery, const std::string &hop_interval, const std::string &alpn, tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void hysteria2Construct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &ports, const std::string &up, const std::string &down, const std::string &password, const std::string &obfs, const std::string &obfs_password, const std::string &sni, const std::string &fingerprint, const std::string &alpn, const std::string &ca, const std::string &caStr, const std::string &cwnd, const std::string &hop_interval, const std::string &ech_enable, const std::string &ech_config, const std::string &initial_stream_receive_window, const std::string &max_stream_receive_window, const std::string &initial_connection_receive_window, const std::string &max_connection_receive_window, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void TUICConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &uuid, const std::string &password, const std::string &ip, const std::string &heartbeat_interval, const std::string &alpn, const std::string &disable_sni, const std::string &reduce_rtt, const std::string &request_timeout, const std::string &udp_relay_mode, const std::string &congestion_controller, const std::string &max_udp_relay_packet_size, const std::string &max_open_streams, const std::string &sni, const std::string &fast_open, tribool tfo, tribool scv, const std::string &underlying_proxy = "");
void anyTLSConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &sni, const std::string &alpn, const std::string &fingerprint, const std::string &idle_session_check_interval, const std::string &idle_session_timeout, const std::string &min_idle_session, tribool tfo, tribool scv, tribool tls13 = tribool(), const std::string &underlying_proxy = "");
void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &uuid, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &public_key, const std::string &short_id, const std::string &fingerprint, const std::string &sni, const std::vector<std::string> &alpnList,const std::string &packet_encoding, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(),const std::string& underlying_proxy="", tribool v2ray_http_upgrade = tribool(), tribool v2ray_http_upgrade_fast_open = tribool());
void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &port, const std::string &password, const std::string &host, const std::string &ports, const std::string &username,const std::string &multiplexing, const std::string &transfer_protocol, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy);

void explodeVmess(std::string vmess, Proxy &node);
void explodeSSR(std::string ssr, Proxy &node);
void explodeSS(std::string ss, Proxy &node);
void explodeTrojan(std::string trojan, Proxy &node);
void explodeHysteria(std::string hysteria, Proxy &node);
void explodeHysteria2(std::string hysteria2, Proxy &node);
void explodeTUIC(std::string TUIC, Proxy &node);
void explodeAnyTLS(std::string anytls, Proxy &node);
void explodeVLESS(std::string vless, Proxy &node);
void explodeMierus(std::string mieru, Proxy &node);
void explodeQuan(const std::string &quan, Proxy &node);
void explodeStdVMess(std::string vmess, Proxy &node);
void explodeShadowrocket(std::string kit, Proxy &node);
void explodeKitsunebi(std::string kit, Proxy &node);
void explodeStdHysteria(std::string hysteria, Proxy &node);
void explodeStdHysteria2(std::string hysteria2, Proxy &node);
void explodeStdTUIC(std::string TUIC, Proxy &node);
void explodeStdAnyTLS(std::string anytls, Proxy &node);
void explodeStdVLESS(std::string vless, Proxy &node);
void explodeStdMieru(std::string mieru, Proxy &node);

/// Parse a link
void explode(const std::string &link, Proxy &node);
void explodeSSD(std::string link, std::vector<Proxy> &nodes);
void explodeSub(std::string sub, std::vector<Proxy> &nodes);
int explodeConf(const std::string &filepath, std::vector<Proxy> &nodes);
int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes);

#endif // SUBPARSER_H_INCLUDED
