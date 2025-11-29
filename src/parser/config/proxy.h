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
    VLESS,
    Trojan,
    Snell,
    HTTP,
    HTTPS,
    SOCKS5,
    WireGuard,
    Hysteria,
    Hysteria2,
    TUIC,
    AnyTLS,
    Mieru,
    Sudoku
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
    case ProxyType::VLESS:
        return "VLESS";
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
    case ProxyType::TUIC:
        return "TUIC";
    case ProxyType::AnyTLS:
        return "AnyTLS";
    case ProxyType::Mieru:
        return "Mieru";
    case ProxyType::Sudoku:
        return "SUDOKU";
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
    String UnderlyingProxy;
    String IPVersion;

    tribool UDP;
    tribool XUDP;
    tribool TCPFastOpen;
    tribool UDPoverTCP;
    tribool TLS13;
    tribool AllowInsecure;
    tribool UDPOverStream;
    int UDPOverStreamVersion = 0;
    int UDPOverTCPVersion = 0;

    String ServerName;
    String Fingerprint;
    String ClientFingerprint;
    String Certificate;
    String CertificateKey;
    String TLSStr;
    bool TLSSecure = false;

    String EchConfig;
    tribool EchEnable;

    uint16_t SnellVersion = 0;

    String OBFS;
    String OBFSParam;
    String OBFSPassword;
    String Plugin;
    String PluginOption;

    String Protocol;
    String ProtocolParam;

    tribool SmuxEnabled;
    int SmuxMaxConnections = 0;
    int SmuxMaxStreams = 0;
    int SmuxMinStreams = 0;
    tribool SmuxPadding;
    tribool SmuxStatistic;
    tribool SmuxOnlyTcp;

    String KCPKey;
    String KCPCrypt;
    String KCPMode;
    uint16_t KCPConn = 1;
    uint16_t KCPAutoExpire = 0;
    uint16_t KCPScavengeTTL = 600;
    uint16_t KCPMtu = 1350;
    uint32_t KCPRateLimit = 0;
    uint16_t KCPSndWnd = 128;
    uint16_t KCPRcvWnd = 512;
    uint16_t KCPDataShard = 10;
    uint16_t KCPParityShard = 3;
    uint8_t KCPDSCP = 0;
    bool KCPNoComp = false;
    bool KCPAckNoDelay = false;
    uint16_t KCPNodelay = 0;
    uint16_t KCPInterval = 50;
    uint16_t KCPResend = 0;
    uint32_t KCPSockbuf = 4194304;
    uint16_t KCPSmuxver = 1;
    uint32_t KCPSmuxbuf = 4194304;
    uint16_t KCPFramesize = 8192;
    uint32_t KCPStreambuf = 2097152;
    uint16_t KCPKeepalive = 10;

    String UserId;
    uint16_t AlterId = 0;
    String FakeType;

    String UUID;

    String TransferProtocol;

    String Host;
    String Path;
    String Edge;
    String WsPath;
    String WsHeaders;
    std::string WsEarlyDataHeaderName;
    int WsMaxEarlyData = 0;

    String GrpcServiceName;
    String GRPCMode;

    String QUICSecure;
    String QUICSecret;

    String QUICInitStreamReceiveWindow;
    String QUICMaxStreamReceiveWindow;
    String QUICInitConnReceiveWindow;
    String QUICMaxConnReceiveWindow;

    tribool V2rayHttpUpgrade;
    tribool V2rayHttpUpgradeFastOpen;

    String Alpn;
    std::vector<String> AlpnList;

    String Flow;
    uint32_t XTLS = 0;
    String PacketEncoding;
    String ShortID;
    tribool FlowShow;
    tribool PacketAddr;
    tribool GlobalPadding;
    tribool AuthenticatedLength;
    String Encryption;
    tribool SupportX25519Mlkem768;

    bool TrojanSSOpts = false;
    String TrojanSSMethod;
    String TrojanSSPassword;

    String Ports;
    String Up;
    String Down;
    uint32_t UpSpeed = 0;
    uint32_t DownSpeed = 0;
    String Auth;
    String AuthStr;
    String SNI;
    String Ca;
    String CaStr;
    uint32_t RecvWindowConn = 0;
    uint32_t RecvWindow = 0;
    tribool DisableMtuDiscovery;
    uint32_t HopInterval = 0;
    uint32_t CWND = 0;

    uint32_t InitialStreamReceiveWindow = 0;
    uint32_t MaxStreamReceiveWindow = 0;
    uint32_t InitialConnectionReceiveWindow = 0;
    uint32_t MaxConnectionReceiveWindow = 0;

    String IP;
    String HeartbeatInterval;
    tribool DisableSNI;
    tribool ReduceRTT;
    uint32_t RequestTimeout = 0;
    String UdpRelayMode;
    String CongestionController;
    uint32_t MaxUdpRelayPacketSize = 0;
    tribool FastOpen;
    uint32_t MaxOpenStreams = 0;
    uint16_t TuicVersion = 0;

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
    StringArray Reserved;
    StringArray Peers;
    String DialerProxy;
    tribool RemoteDnsResolve;

    String PaddingScheme;
    uint32_t IdleSessionCheckInterval = 0;
    uint32_t IdleSessionTimeout = 0;
    uint32_t MinIdleSession = 0;

    String AmneziaJC;
    String AmneziaJMin;
    String AmneziaJMax;
    String AmneziaS1;
    String AmneziaS2;
    String AmneziaS3;
    String AmneziaS4;
    String AmneziaH1;
    String AmneziaH2;
    String AmneziaH3;
    String AmneziaH4;
    String AmneziaI1;
    String AmneziaI2;
    String AmneziaI3;
    String AmneziaI4;
    String AmneziaI5;
    String AmneziaJ1;
    String AmneziaJ2;
    String AmneziaJ3;
    String AmneziaItime;

    String PortRange;
    String Multiplexing;
    String HandshakeMode;

    String Key;
    String AEAD;
    int PaddingMin = 0;
    int PaddingMax = 0;
    String TableType;
    tribool HTTPMask;
    String HTTPMaskMode;
    tribool HTTPMaskTLS;
    String HTTPMaskHost;
    String HTTPMaskMultiplex;
    tribool EnablePureDownlink;
    String CustomTable;
    StringArray CustomTables;
};

#define SS_DEFAULT_GROUP "SSProvider"
#define SSR_DEFAULT_GROUP "SSRProvider"
#define V2RAY_DEFAULT_GROUP "V2RayProvider"
#define VLESS_DEFAULT_GROUP "VLESSProvider"
#define SOCKS_DEFAULT_GROUP "SocksProvider"
#define HTTP_DEFAULT_GROUP "HTTPProvider"
#define TROJAN_DEFAULT_GROUP "TrojanProvider"
#define SNELL_DEFAULT_GROUP "SnellProvider"
#define WG_DEFAULT_GROUP "WireGuardProvider"
#define HYSTERIA_DEFAULT_GROUP "HysteriaProvider"
#define HYSTERIA2_DEFAULT_GROUP "Hysteria2Provider"
#define TUIC_DEFAULT_GROUP "TUICProvider"
#define ANYTLS_DEFAULT_GROUP "AnyTLSProvider"
#define MIERU_DEFAULT_GROUP "MieruProvider"
#define SUDOKU_DEFAULT_GROUP "SudokuProvider"

#endif // PROXY_H_INCLUDED
