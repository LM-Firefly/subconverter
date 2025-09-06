#ifndef PROXY_H_INCLUDED
#define PROXY_H_INCLUDED

#include <string>
#include <vector>

#include "utils/tribool.h"

using String = std::string;
using StringArray = std::vector<String>;

enum class ProxyType
{
    Unknown,
    Shadowsocks,
    ShadowsocksR,
    VMess,
    Trojan,
    Snell,
    HTTP,
    HTTPS,
    SOCKS5,
    WireGuard,
    Hysteria,
    Hysteria2,
    VLESS,
    TUIC,
    AnyTLS,
    Mieru
};

inline String getProxyTypeName(ProxyType type)
{
    switch(type)
    {
    case ProxyType::Shadowsocks:
        return "SS";
    case ProxyType::ShadowsocksR:
        return "SSR";
    case ProxyType::VMess:
        return "VMess";
    case ProxyType::Trojan:
        return "Trojan";
    case ProxyType::Snell:
        return "Snell";
    case ProxyType::HTTP:
        return "HTTP";
    case ProxyType::HTTPS:
        return "HTTPS";
    case ProxyType::SOCKS5:
        return "SOCKS5";
    case ProxyType::WireGuard:
        return "WireGuard";
    case ProxyType::Hysteria:
        return "Hysteria";
    case ProxyType::Hysteria2:
        return "Hysteria2";
    case ProxyType::VLESS:
        return "Vless";
    case ProxyType::TUIC:
        return "TUIC";
    case ProxyType::AnyTLS:
        return "AnyTLS";
    case ProxyType::Mieru:
        return "Mieru";
    default:
        return "Unknown";
    }
}

struct Proxy
{
    ProxyType Type = ProxyType::Unknown;
    uint32_t Id = 0;
    uint32_t GroupId = 0;
    String Group;
    String Remark;
    String Hostname;
    uint16_t Port = 0;

    String Username;
    String Password;
    String EncryptMethod;
    String Plugin;
    String PluginOption;
    String Protocol;
    String ProtocolParam;
    String OBFS;
    String OBFSParam;
    String UserId;
    uint16_t AlterId = 0;
    String TransferProtocol;
    String FakeType;
    bool TLSSecure = false;

    tribool SmuxEnabled;
    int SmuxMaxConnections = 0;
    int SmuxMaxStreams = 0;
    int SmuxMinStreams = 0;
    tribool SmuxPadding;
    tribool SmuxStatistic;
    tribool SmuxOnlyTcp;

    String RestlsScript;
    String ShortId;
    tribool Tfo;
    tribool PortHopping;
    String PortRange;
    String IpWhitelist;
    String Psk;
    String ScMaxTime;
    String ScMaxSize;
    String ScMinTime;
    String ScMinSize;
    String ScSize;
    String ScTime;
    String Smux;
    tribool UnderlyingProxyEnable;

    String Host;
    String Path;
    String Edge;
    StringArray H2Hosts; // h2-opts.host 数组
    StringArray H2Paths; // h2-opts.path 数组
    StringArray HTTPPaths; // http-opts.path 数组
    std::map<String, StringArray> HTTPHeaders; // http-opts.headers 多值
    StringArray GRPCServiceNames; // grpc-opts.grpc-service-name 数组

    String QUICSecure;
    String QUICSecret;

    tribool UDP;
    tribool XUDP;
    tribool TCPFastOpen;
    tribool AllowInsecure;
    tribool TLS13;
    tribool UDPoverTCP;

    String IPVersion;
    String UnderlyingProxy;

    uint16_t SnellVersion = 0;
    String ServerName;

    String SelfIP;
    String SelfIPv6;
    String PublicKey;
    String PrivateKey;
    String PreSharedKey;
    StringArray DnsServers;
    uint16_t Mtu = 0;
    String AllowedIPs = "0.0.0.0/0, ::/0";
    uint16_t KeepAlive = 0;
    String TestUrl;
    String ClientId;

    String Ports;
    String Up;
    uint32_t UpSpeed;
    String Down;
    uint32_t DownSpeed;
    String Auth;
    String AuthStr;
    String SNI;
    String OBFSPassword;
    String Fingerprint;
    String Ca;
    String CaStr;
    String Alpn;
    std::vector<String> AlpnList;
    uint32_t RecvWindowConn;
    uint32_t RecvWindow;
    tribool DisableMtuDiscovery;
    uint32_t HopInterval;
    uint32_t CWND = 0;

    String UUID;
    String IP;
    String HeartbeatInterval;
    tribool DisableSNI;
    tribool ReduceRTT;
    uint32_t RequestTimeout;
    String UdpRelayMode;
    String CongestionController;
    uint32_t MaxUdpRelayPacketSize;
    tribool FastOpen;
    uint32_t MaxOpenStreams;

    String Flow;
    uint32_t XTLS;
    String PacketEncoding;
    String ShortID;

    String Network;
    String ClientFingerprint;
    String EchConfig;
    tribool EchEnable;
    tribool SupportX25519Mlkem768;
    String GrpcServiceName;
    String GRPCMode;
    String WsPath;
    String WsHeaders;
    std::string WsEarlyDataHeaderName;
    int WsMaxEarlyData = 0;
    tribool V2rayHttpUpgrade;
    tribool V2rayHttpUpgradeFastOpen;
    
    uint32_t InitialStreamReceiveWindow = 0;
    uint32_t MaxStreamReceiveWindow = 0;
    uint32_t InitialConnectionReceiveWindow = 0;
    uint32_t MaxConnectionReceiveWindow = 0;

    uint32_t IdleSessionCheckInterval;
    uint32_t IdleSessionTimeout;
    uint32_t MinIdleSession;

    String Multiplexing;
    String TLSStr;
};

#define SS_DEFAULT_GROUP "SSProvider"
#define SSR_DEFAULT_GROUP "SSRProvider"
#define V2RAY_DEFAULT_GROUP "V2RayProvider"
#define SOCKS_DEFAULT_GROUP "SocksProvider"
#define HTTP_DEFAULT_GROUP "HTTPProvider"
#define TROJAN_DEFAULT_GROUP "TrojanProvider"
#define SNELL_DEFAULT_GROUP "SnellProvider"
#define WG_DEFAULT_GROUP "WireGuardProvider"
#define HYSTERIA_DEFAULT_GROUP "HysteriaProvider"
#define HYSTERIA2_DEFAULT_GROUP "Hysteria2Provider"
#define VLESS_DEFAULT_GROUP "VlessProvider"
#define TUIC_DEFAULT_GROUP "TUICProvider"
#define ANYTLS_DEFAULT_GROUP "AnyTLSProvider"
#define MIERU_DEFAULT_GROUP "MieruProvider"

#endif // PROXY_H_INCLUDED
