#ifndef SCRIPT_QUICKJS_H_INCLUDED
#define SCRIPT_QUICKJS_H_INCLUDED

#include "parser/config/proxy.h"
#include "utils/defer.h"

#ifndef NO_JS_RUNTIME

#include <quickjspp.hpp>

void script_runtime_init(qjs::Runtime &runtime);
int script_context_init(qjs::Context &context);
int script_cleanup(qjs::Context &context);
void script_print_stack(qjs::Context &context);

inline JSValue JS_NewString(JSContext *ctx, const std::string& str)
{
    return JS_NewStringLen(ctx, str.c_str(), str.size());
}

inline std::string JS_GetPropertyIndexToString(JSContext *ctx, JSValueConst obj, uint32_t index) {
    JSValue val = JS_GetPropertyUint32(ctx, obj, index);
    size_t len;
    const char *str = JS_ToCStringLen(ctx, &len, val);
    std::string result(str, len);
    JS_FreeCString(ctx, str);
    JS_FreeValue(ctx, val);
    return result;
}

namespace qjs
{
    template<typename T>
    static T unwrap_free(JSContext *ctx, JSValue v, const char* key) noexcept
    {
        auto obj = JS_GetPropertyStr(ctx, v, key);
        T t = js_traits<T>::unwrap(ctx, obj);
        JS_FreeValue(ctx, obj);
        return t;
    }

    template<>
    struct js_traits<tribool>
    {
        static JSValue wrap(JSContext *ctx, const tribool &t) noexcept
        {
            auto obj = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, obj, "value", JS_NewBool(ctx, t.get()));
            JS_SetPropertyStr(ctx, obj, "isDefined", JS_NewBool(ctx, !t.is_undef()));
            return obj;
        }

        static tribool unwrap(JSContext *ctx, JSValueConst v)
        {
            tribool t;
            bool defined = unwrap_free<bool>(ctx, v, "isDefined");
            if(defined)
            {
                bool value = unwrap_free<bool>(ctx, v, "value");
                t.set(value);
            }
            return t;
        }
    };

    template<>
    struct js_traits<StringArray>
    {
        static StringArray unwrap(JSContext *ctx, JSValueConst v) {
            StringArray arr;
            auto length = unwrap_free<uint32_t>(ctx, v, "length");
            for (uint32_t i = 0; i < length; i++) {
                arr.push_back(JS_GetPropertyIndexToString(ctx, v, i));
            }
            return arr;
        }

        static JSValue wrap(JSContext *ctx, const StringArray& arr) {
            JSValue jsArray = JS_NewArray(ctx);
            for (std::size_t i = 0; i < arr.size(); i++) {
                JS_SetPropertyUint32(ctx, jsArray, i, JS_NewString(ctx, arr[i]));
            }
            return jsArray;
        }
    };

    template<>
    struct js_traits<StringMap>
    {
        static JSValue wrap(JSContext *ctx, const StringMap& map) noexcept
        {
            JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
            if (JS_IsException(obj)) {
                return obj;
            }
            for (const auto& [key, value] : map) {
                JS_SetPropertyStr(ctx, obj, key.c_str(), JS_NewString(ctx, value));
            }
            return obj;
        }

        static StringMap unwrap(JSContext *ctx, JSValueConst v)
        {
            StringMap map;
            JSPropertyEnum *tab = nullptr;
            uint32_t len = 0;
            if (JS_GetOwnPropertyNames(ctx, &tab, &len, v, JS_GPN_STRING_MASK) < 0)
                return map;
            for (uint32_t i = 0; i < len; i++) {
                const char *key = JS_AtomToCString(ctx, tab[i].atom);
                JSValue val = JS_GetProperty(ctx, v, tab[i].atom);
                size_t vlen;
                const char *str = JS_ToCStringLen(ctx, &vlen, val);
                if (key && str)
                    map[std::string(key)] = std::string(str, vlen);
                JS_FreeCString(ctx, str);
                JS_FreeValue(ctx, val);
                JS_FreeCString(ctx, key);
                JS_FreeAtom(ctx, tab[i].atom);
            }
            js_free(ctx, tab);
            return map;
        }
    };

    template<>
    struct js_traits<Proxy>
    {
        static JSValue wrap(JSContext *ctx, const Proxy &n) noexcept
        {
            JSValue obj = JS_NewObjectProto(ctx, JS_NULL);
            if (JS_IsException(obj)) {
                return obj;
            }

            JS_DefinePropertyValueStr(ctx, obj, "Type", js_traits<ProxyType>::wrap(ctx, n.Type), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Id", JS_NewUint32(ctx, n.Id), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GroupId", JS_NewUint32(ctx, n.GroupId), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Group", JS_NewString(ctx, n.Group), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Remark", JS_NewString(ctx, n.Remark), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Server", JS_NewString(ctx, n.Hostname), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Port", JS_NewInt32(ctx, n.Port), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "Username", JS_NewString(ctx, n.Username), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Password", JS_NewString(ctx, n.Password), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EncryptMethod", JS_NewString(ctx, n.EncryptMethod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Plugin", JS_NewString(ctx, n.Plugin), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PluginOption", JS_NewString(ctx, n.PluginOption), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Protocol", JS_NewString(ctx, n.Protocol), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ProtocolParam", JS_NewString(ctx, n.ProtocolParam), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OBFS", JS_NewString(ctx, n.OBFS), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OBFSParam", JS_NewString(ctx, n.OBFSParam), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UserId", JS_NewString(ctx, n.UserId), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "AlterId", JS_NewInt32(ctx, n.AlterId), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TransferProtocol", JS_NewString(ctx, n.TransferProtocol), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "FakeType", JS_NewString(ctx, n.FakeType), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TLSSecure", JS_NewBool(ctx, n.TLSSecure), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "Host", JS_NewString(ctx, n.Host), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Path", JS_NewString(ctx, n.Path), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Edge", JS_NewString(ctx, n.Edge), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "QUICSecure", JS_NewString(ctx, n.QUICSecure), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "QUICSecret", JS_NewString(ctx, n.QUICSecret), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "UDP", js_traits<tribool>::wrap(ctx, n.UDP), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TCPFastOpen", js_traits<tribool>::wrap(ctx, n.TCPFastOpen), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AllowInsecure", js_traits<tribool>::wrap(ctx, n.AllowInsecure), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TLS13", js_traits<tribool>::wrap(ctx, n.TLS13), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "SnellVersion", JS_NewInt32(ctx, n.SnellVersion), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ServerName", JS_NewString(ctx, n.ServerName), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "SelfIP", JS_NewString(ctx, n.SelfIP), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SelfIPv6", JS_NewString(ctx, n.SelfIPv6), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PublicKey", JS_NewString(ctx, n.PublicKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PrivateKey", JS_NewString(ctx, n.PrivateKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PreSharedKey", JS_NewString(ctx, n.PreSharedKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "DnsServers", js_traits<StringArray>::wrap(ctx, n.DnsServers), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Mtu", JS_NewUint32(ctx, n.Mtu), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AllowedIPs", JS_NewString(ctx, n.AllowedIPs), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KeepAlive", JS_NewUint32(ctx, n.KeepAlive), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TestUrl", JS_NewString(ctx, n.TestUrl), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ClientId", JS_NewString(ctx, n.ClientId), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "Ports", JS_NewString(ctx, n.Ports), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Up", JS_NewString(ctx, n.Up), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UpSpeed", JS_NewUint32(ctx, n.UpSpeed), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Down", JS_NewString(ctx, n.Down), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "DownSpeed", JS_NewUint32(ctx, n.DownSpeed), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Auth", JS_NewString(ctx, n.Auth), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AuthStr", JS_NewString(ctx, n.AuthStr), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SNI", JS_NewString(ctx, n.SNI), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OBFSPassword", JS_NewString(ctx, n.OBFSPassword), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Fingerprint", JS_NewString(ctx, n.Fingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Ca", JS_NewString(ctx, n.Ca), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CaStr", JS_NewString(ctx, n.CaStr), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "RecvWindowConn", JS_NewUint32(ctx, n.RecvWindowConn), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RecvWindow", JS_NewUint32(ctx, n.RecvWindow), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "DisableMtuDiscovery", js_traits<tribool>::wrap(ctx, n.DisableMtuDiscovery), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HopInterval", JS_NewUint32(ctx, n.HopInterval), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CWND", JS_NewUint32(ctx, n.CWND), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Alpn", JS_NewString(ctx, n.Alpn), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AlpnList", js_traits<StringArray>::wrap(ctx, n.AlpnList), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "UUID", JS_NewString(ctx, n.UUID), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "IP", JS_NewString(ctx, n.IP), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HeartbeatInterval", JS_NewString(ctx, n.HeartbeatInterval), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "DisableSNI", js_traits<tribool>::wrap(ctx, n.DisableSNI), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ReduceRTT", js_traits<tribool>::wrap(ctx, n.ReduceRTT), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RequestTimeout", JS_NewUint32(ctx, n.RequestTimeout), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UdpRelayMode", JS_NewString(ctx, n.UdpRelayMode), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CongestionController", JS_NewString(ctx, n.CongestionController), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "MaxUdpRelayPacketSize", JS_NewUint32(ctx, n.MaxUdpRelayPacketSize), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "FastOpen", js_traits<tribool>::wrap(ctx, n.FastOpen), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "MaxOpenStreams", JS_NewUint32(ctx, n.MaxOpenStreams), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "IdleSessionCheckInterval", JS_NewUint32(ctx, n.IdleSessionCheckInterval), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "IdleSessionTimeout", JS_NewUint32(ctx, n.IdleSessionTimeout), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "MinIdleSession", JS_NewUint32(ctx, n.MinIdleSession), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "Flow", JS_NewString(ctx, n.Flow), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XTLS", JS_NewUint32(ctx, n.XTLS), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PacketEncoding", JS_NewString(ctx, n.PacketEncoding), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ShortID", JS_NewString(ctx, n.ShortID), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "SmuxMaxConnections", JS_NewInt32(ctx, n.SmuxMaxConnections), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SmuxMaxStreams", JS_NewInt32(ctx, n.SmuxMaxStreams), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SmuxMinStreams", JS_NewInt32(ctx, n.SmuxMinStreams), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SmuxPadding", js_traits<tribool>::wrap(ctx, n.SmuxPadding), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SmuxStatistic", js_traits<tribool>::wrap(ctx, n.SmuxStatistic), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SmuxOnlyTcp", js_traits<tribool>::wrap(ctx, n.SmuxOnlyTcp), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SmuxProtocol", JS_NewString(ctx, n.SmuxProtocol), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "ClientFingerprint", JS_NewString(ctx, n.ClientFingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EchConfig", JS_NewString(ctx, n.EchConfig), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EchEnable", js_traits<tribool>::wrap(ctx, n.EchEnable), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SupportX25519Mlkem768", js_traits<tribool>::wrap(ctx, n.SupportX25519Mlkem768), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcServiceName", JS_NewString(ctx, n.GrpcServiceName), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GRPCMode", JS_NewString(ctx, n.GRPCMode), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcUserAgent", JS_NewString(ctx, n.GrpcUserAgent), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcPingInterval", JS_NewUint32(ctx, n.GrpcPingInterval), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "WsPath", JS_NewString(ctx, n.WsPath), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "WsHeaders", JS_NewString(ctx, n.WsHeaders), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "WsEarlyDataHeaderName", JS_NewString(ctx, n.WsEarlyDataHeaderName), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "WsMaxEarlyData", JS_NewInt32(ctx, n.WsMaxEarlyData), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "V2rayHttpUpgrade", js_traits<tribool>::wrap(ctx, n.V2rayHttpUpgrade), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "V2rayHttpUpgradeFastOpen", js_traits<tribool>::wrap(ctx, n.V2rayHttpUpgradeFastOpen), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "InitialStreamReceiveWindow", JS_NewUint32(ctx, n.InitialStreamReceiveWindow), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "MaxStreamReceiveWindow", JS_NewUint32(ctx, n.MaxStreamReceiveWindow), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "InitialConnectionReceiveWindow", JS_NewUint32(ctx, n.InitialConnectionReceiveWindow), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "MaxConnectionReceiveWindow", JS_NewUint32(ctx, n.MaxConnectionReceiveWindow), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "Multiplexing", JS_NewString(ctx, n.Multiplexing), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TLSStr", JS_NewString(ctx, n.TLSStr), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "SmuxEnabled", js_traits<tribool>::wrap(ctx, n.SmuxEnabled), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XUDP", js_traits<tribool>::wrap(ctx, n.XUDP), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UDPoverTCP", js_traits<tribool>::wrap(ctx, n.UDPoverTCP), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UnderlyingProxy", JS_NewString(ctx, n.UnderlyingProxy), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "IPVersion", JS_NewString(ctx, n.IPVersion), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TuicVersion", JS_NewUint32(ctx, n.TuicVersion), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "Key", JS_NewString(ctx, n.Key), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AEAD", JS_NewString(ctx, n.AEAD), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PaddingMin", JS_NewInt32(ctx, n.PaddingMin), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PaddingMax", JS_NewInt32(ctx, n.PaddingMax), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TableType", JS_NewString(ctx, n.TableType), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPMask", js_traits<tribool>::wrap(ctx, n.HTTPMask), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPMaskMode", JS_NewString(ctx, n.HTTPMaskMode), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPMaskTLS", js_traits<tribool>::wrap(ctx, n.HTTPMaskTLS), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPMaskHost", JS_NewString(ctx, n.HTTPMaskHost), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPMaskMultiplex", JS_NewString(ctx, n.HTTPMaskMultiplex), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EnablePureDownlink", js_traits<tribool>::wrap(ctx, n.EnablePureDownlink), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CustomTable", JS_NewString(ctx, n.CustomTable), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CustomTables", js_traits<StringArray>::wrap(ctx, n.CustomTables), JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, obj, "PortRange", JS_NewString(ctx, n.PortRange), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HandshakeMode", JS_NewString(ctx, n.HandshakeMode), JS_PROP_C_W_E);

            // Common additional fields
            JS_DefinePropertyValueStr(ctx, obj, "UDPOverStream", js_traits<tribool>::wrap(ctx, n.UDPOverStream), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UDPOverStreamVersion", JS_NewInt32(ctx, n.UDPOverStreamVersion), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UDPOverTCPVersion", JS_NewInt32(ctx, n.UDPOverTCPVersion), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Certificate", JS_NewString(ctx, n.Certificate), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CertificateKey", JS_NewString(ctx, n.CertificateKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EchQueryServerName", JS_NewString(ctx, n.EchQueryServerName), JS_PROP_C_W_E);

            // SS KCP fields
            JS_DefinePropertyValueStr(ctx, obj, "KCPKey", JS_NewString(ctx, n.KCPKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPCrypt", JS_NewString(ctx, n.KCPCrypt), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPMode", JS_NewString(ctx, n.KCPMode), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPConn", JS_NewUint32(ctx, n.KCPConn), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPAutoExpire", JS_NewUint32(ctx, n.KCPAutoExpire), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPScavengeTTL", JS_NewUint32(ctx, n.KCPScavengeTTL), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPMtu", JS_NewUint32(ctx, n.KCPMtu), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPRateLimit", JS_NewUint32(ctx, n.KCPRateLimit), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPSndWnd", JS_NewUint32(ctx, n.KCPSndWnd), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPRcvWnd", JS_NewUint32(ctx, n.KCPRcvWnd), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPDataShard", JS_NewUint32(ctx, n.KCPDataShard), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPParityShard", JS_NewUint32(ctx, n.KCPParityShard), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPDSCP", JS_NewUint32(ctx, n.KCPDSCP), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPNoComp", JS_NewBool(ctx, n.KCPNoComp), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPAckNoDelay", JS_NewBool(ctx, n.KCPAckNoDelay), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPNodelay", JS_NewUint32(ctx, n.KCPNodelay), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPInterval", JS_NewUint32(ctx, n.KCPInterval), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPResend", JS_NewUint32(ctx, n.KCPResend), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPSockbuf", JS_NewUint32(ctx, n.KCPSockbuf), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPSmuxver", JS_NewUint32(ctx, n.KCPSmuxver), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPSmuxbuf", JS_NewUint32(ctx, n.KCPSmuxbuf), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPFramesize", JS_NewUint32(ctx, n.KCPFramesize), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPStreambuf", JS_NewUint32(ctx, n.KCPStreambuf), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "KCPKeepalive", JS_NewUint32(ctx, n.KCPKeepalive), JS_PROP_C_W_E);

            // VMess/VLESS additional fields
            JS_DefinePropertyValueStr(ctx, obj, "Token", JS_NewString(ctx, n.Token), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "WsHeadersMap", JS_NewString(ctx, n.WsHeadersMap), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPHeaders", JS_NewString(ctx, n.HTTPHeaders), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPOptsMethod", JS_NewString(ctx, n.HTTPOptsMethod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPOptsPaths", js_traits<StringArray>::wrap(ctx, n.HTTPOptsPaths), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HTTPOptsHeaders", JS_NewString(ctx, n.HTTPOptsHeaders), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "H2Hosts", js_traits<StringArray>::wrap(ctx, n.H2Hosts), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcMaxConnections", JS_NewUint32(ctx, n.GrpcMaxConnections), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcMinStreams", JS_NewUint32(ctx, n.GrpcMinStreams), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcMaxStreams", JS_NewUint32(ctx, n.GrpcMaxStreams), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPNoGRPCHeader", js_traits<tribool>::wrap(ctx, n.XHTTPNoGRPCHeader), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPXPaddingBytes", JS_NewString(ctx, n.XHTTPXPaddingBytes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPXPaddingObfsMode", js_traits<tribool>::wrap(ctx, n.XHTTPXPaddingObfsMode), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPXPaddingKey", JS_NewString(ctx, n.XHTTPXPaddingKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPXPaddingHeader", JS_NewString(ctx, n.XHTTPXPaddingHeader), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPXPaddingPlacement", JS_NewString(ctx, n.XHTTPXPaddingPlacement), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPXPaddingMethod", JS_NewString(ctx, n.XHTTPXPaddingMethod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPUplinkHTTPMethod", JS_NewString(ctx, n.XHTTPUplinkHTTPMethod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPSessionPlacement", JS_NewString(ctx, n.XHTTPSessionPlacement), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPSessionKey", JS_NewString(ctx, n.XHTTPSessionKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPSessionTable", JS_NewString(ctx, n.XHTTPSessionTable), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPSessionLength", JS_NewString(ctx, n.XHTTPSessionLength), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPSeqPlacement", JS_NewString(ctx, n.XHTTPSeqPlacement), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPSeqKey", JS_NewString(ctx, n.XHTTPSeqKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPUplinkDataPlacement", JS_NewString(ctx, n.XHTTPUplinkDataPlacement), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPUplinkDataKey", JS_NewString(ctx, n.XHTTPUplinkDataKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPUplinkChunkSize", JS_NewString(ctx, n.XHTTPUplinkChunkSize), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPScMaxEachPostBytes", JS_NewString(ctx, n.XHTTPScMaxEachPostBytes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPScMaxBufferedPosts", JS_NewString(ctx, n.XHTTPScMaxBufferedPosts), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPScMinPostsIntervalMs", JS_NewString(ctx, n.XHTTPScMinPostsIntervalMs), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPHeaders", JS_NewString(ctx, n.XHTTPHeaders), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPReuseMaxConnections", JS_NewString(ctx, n.XHTTPReuseMaxConnections), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPReuseMaxConcurrency", JS_NewString(ctx, n.XHTTPReuseMaxConcurrency), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPReuseCMaxReuseTimes", JS_NewString(ctx, n.XHTTPReuseCMaxReuseTimes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPReuseHMaxRequestTimes", JS_NewString(ctx, n.XHTTPReuseHMaxRequestTimes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPReuseHMaxReusableSecs", JS_NewString(ctx, n.XHTTPReuseHMaxReusableSecs), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPReuseHKeepAlivePeriod", JS_NewUint32(ctx, n.XHTTPReuseHKeepAlivePeriod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadPath", JS_NewString(ctx, n.XHTTPDownloadPath), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadHost", JS_NewString(ctx, n.XHTTPDownloadHost), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadHeaders", JS_NewString(ctx, n.XHTTPDownloadHeaders), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadReuseMaxConnections", JS_NewString(ctx, n.XHTTPDownloadReuseMaxConnections), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadReuseMaxConcurrency", JS_NewString(ctx, n.XHTTPDownloadReuseMaxConcurrency), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadReuseCMaxReuseTimes", JS_NewString(ctx, n.XHTTPDownloadReuseCMaxReuseTimes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadReuseHMaxRequestTimes", JS_NewString(ctx, n.XHTTPDownloadReuseHMaxRequestTimes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadReuseHMaxReusableSecs", JS_NewString(ctx, n.XHTTPDownloadReuseHMaxReusableSecs), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadReuseHKeepAlivePeriod", JS_NewUint32(ctx, n.XHTTPDownloadReuseHKeepAlivePeriod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadServer", JS_NewString(ctx, n.XHTTPDownloadServer), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadPort", JS_NewUint32(ctx, n.XHTTPDownloadPort), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadTLS", js_traits<tribool>::wrap(ctx, n.XHTTPDownloadTLS), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadALPN", js_traits<StringArray>::wrap(ctx, n.XHTTPDownloadALPN), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadECHEnable", js_traits<tribool>::wrap(ctx, n.XHTTPDownloadECHEnable), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadECHConfig", JS_NewString(ctx, n.XHTTPDownloadECHConfig), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadECHQueryServerName", JS_NewString(ctx, n.XHTTPDownloadECHQueryServerName), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadRealityPublicKey", JS_NewString(ctx, n.XHTTPDownloadRealityPublicKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadRealityShortID", JS_NewString(ctx, n.XHTTPDownloadRealityShortID), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadRealitySpiderX", JS_NewString(ctx, n.XHTTPDownloadRealitySpiderX), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadRealitySupportX25519Mlkem768", js_traits<tribool>::wrap(ctx, n.XHTTPDownloadRealitySupportX25519Mlkem768), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadSkipCertVerify", js_traits<tribool>::wrap(ctx, n.XHTTPDownloadSkipCertVerify), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadFingerprint", JS_NewString(ctx, n.XHTTPDownloadFingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadCertificate", JS_NewString(ctx, n.XHTTPDownloadCertificate), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadPrivateKey", JS_NewString(ctx, n.XHTTPDownloadPrivateKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadServerName", JS_NewString(ctx, n.XHTTPDownloadServerName), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "XHTTPDownloadClientFingerprint", JS_NewString(ctx, n.XHTTPDownloadClientFingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SpiderX", JS_NewString(ctx, n.SpiderX), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "FlowShow", js_traits<tribool>::wrap(ctx, n.FlowShow), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PacketAddr", js_traits<tribool>::wrap(ctx, n.PacketAddr), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GlobalPadding", js_traits<tribool>::wrap(ctx, n.GlobalPadding), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AuthenticatedLength", js_traits<tribool>::wrap(ctx, n.AuthenticatedLength), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Encryption", JS_NewString(ctx, n.Encryption), JS_PROP_C_W_E);

            // Trojan additional
            JS_DefinePropertyValueStr(ctx, obj, "TrojanSSOpts", JS_NewBool(ctx, n.TrojanSSOpts), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TrojanSSMethod", JS_NewString(ctx, n.TrojanSSMethod), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TrojanSSPassword", JS_NewString(ctx, n.TrojanSSPassword), JS_PROP_C_W_E);

            // Snell additional
            JS_DefinePropertyValueStr(ctx, obj, "ObfsPassword", JS_NewString(ctx, n.ObfsPassword), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsVersion", JS_NewUint32(ctx, n.ObfsVersion), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsAlpn", js_traits<StringArray>::wrap(ctx, n.ObfsAlpn), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsFingerprint", JS_NewString(ctx, n.ObfsFingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsCertificate", JS_NewString(ctx, n.ObfsCertificate), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsPrivateKey", JS_NewString(ctx, n.ObfsPrivateKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsSkipCertVerify", js_traits<tribool>::wrap(ctx, n.ObfsSkipCertVerify), JS_PROP_C_W_E);

            // WireGuard additional
            JS_DefinePropertyValueStr(ctx, obj, "Reserved", js_traits<StringArray>::wrap(ctx, n.Reserved), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Peers", js_traits<StringArray>::wrap(ctx, n.Peers), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "DialerProxy", JS_NewString(ctx, n.DialerProxy), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RemoteDnsResolve", js_traits<tribool>::wrap(ctx, n.RemoteDnsResolve), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaJC", JS_NewString(ctx, n.AmneziaJC), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaJMin", JS_NewString(ctx, n.AmneziaJMin), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaJMax", JS_NewString(ctx, n.AmneziaJMax), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaS1", JS_NewString(ctx, n.AmneziaS1), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaS2", JS_NewString(ctx, n.AmneziaS2), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaS3", JS_NewString(ctx, n.AmneziaS3), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaS4", JS_NewString(ctx, n.AmneziaS4), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaH1", JS_NewString(ctx, n.AmneziaH1), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaH2", JS_NewString(ctx, n.AmneziaH2), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaH3", JS_NewString(ctx, n.AmneziaH3), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaH4", JS_NewString(ctx, n.AmneziaH4), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaI1", JS_NewString(ctx, n.AmneziaI1), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaI2", JS_NewString(ctx, n.AmneziaI2), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaI3", JS_NewString(ctx, n.AmneziaI3), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaI4", JS_NewString(ctx, n.AmneziaI4), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaI5", JS_NewString(ctx, n.AmneziaI5), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaJ1", JS_NewString(ctx, n.AmneziaJ1), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaJ2", JS_NewString(ctx, n.AmneziaJ2), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaJ3", JS_NewString(ctx, n.AmneziaJ3), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "AmneziaItime", JS_NewString(ctx, n.AmneziaItime), JS_PROP_C_W_E);

            // OpenVPN
            JS_DefinePropertyValueStr(ctx, obj, "OpenVPNDev", JS_NewString(ctx, n.OpenVPNDev), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OpenVPNTLSCrypt", JS_NewString(ctx, n.OpenVPNTLSCrypt), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "CompLZO", JS_NewString(ctx, n.CompLZO), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OpenVPNPing", JS_NewUint32(ctx, n.OpenVPNPing), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OpenVPNPingRestart", JS_NewUint32(ctx, n.OpenVPNPingRestart), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "OpenVPNPeerInfo", js_traits<StringMap>::wrap(ctx, n.OpenVPNPeerInfo), JS_PROP_C_W_E);

            // Tailscale
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleAuthKey", JS_NewString(ctx, n.TailscaleAuthKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleControlURL", JS_NewString(ctx, n.TailscaleControlURL), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleStateDir", JS_NewString(ctx, n.TailscaleStateDir), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleEphemeral", js_traits<tribool>::wrap(ctx, n.TailscaleEphemeral), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleAcceptRoutes", js_traits<tribool>::wrap(ctx, n.TailscaleAcceptRoutes), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleExitNode", JS_NewString(ctx, n.TailscaleExitNode), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TailscaleExitNodeAllowLANAccess", js_traits<tribool>::wrap(ctx, n.TailscaleExitNodeAllowLANAccess), JS_PROP_C_W_E);

            // Hysteria/Hysteria2 additional
            JS_DefinePropertyValueStr(ctx, obj, "Hysteria2HopInterval", JS_NewString(ctx, n.Hysteria2HopInterval), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "UdpMTU", JS_NewUint32(ctx, n.UdpMTU), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsMinPacketSize", JS_NewUint32(ctx, n.ObfsMinPacketSize), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "ObfsMaxPacketSize", JS_NewUint32(ctx, n.ObfsMaxPacketSize), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmEnable", js_traits<tribool>::wrap(ctx, n.RealmEnable), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmServerURL", JS_NewString(ctx, n.RealmServerURL), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmToken", JS_NewString(ctx, n.RealmToken), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmID", JS_NewString(ctx, n.RealmID), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmStunServers", js_traits<StringArray>::wrap(ctx, n.RealmStunServers), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmSNI", JS_NewString(ctx, n.RealmSNI), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmSkipCertVerify", js_traits<tribool>::wrap(ctx, n.RealmSkipCertVerify), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmFingerprint", JS_NewString(ctx, n.RealmFingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmCertificate", JS_NewString(ctx, n.RealmCertificate), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmPrivateKey", JS_NewString(ctx, n.RealmPrivateKey), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "RealmALPN", js_traits<StringArray>::wrap(ctx, n.RealmALPN), JS_PROP_C_W_E);

            // MASQUE
            JS_DefinePropertyValueStr(ctx, obj, "MasqueIPv6", JS_NewString(ctx, n.MasqueIPv6), JS_PROP_C_W_E);

            // TUIC/AnyTLS additional
            JS_DefinePropertyValueStr(ctx, obj, "BBRProfile", JS_NewString(ctx, n.BBRProfile), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "Reuse", js_traits<tribool>::wrap(ctx, n.Reuse), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "PaddingScheme", JS_NewString(ctx, n.PaddingScheme), JS_PROP_C_W_E);

            // GOST
            JS_DefinePropertyValueStr(ctx, obj, "GostRelayForward", JS_NewBool(ctx, n.GostRelayForward), JS_PROP_C_W_E);

            // Mieru additional
            JS_DefinePropertyValueStr(ctx, obj, "PathRoot", JS_NewString(ctx, n.PathRoot), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "HandshakeTimeout", JS_NewUint32(ctx, n.HandshakeTimeout), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "TrafficPattern", JS_NewString(ctx, n.TrafficPattern), JS_PROP_C_W_E);

            // TrustTunnel additional
            JS_DefinePropertyValueStr(ctx, obj, "HealthCheck", js_traits<tribool>::wrap(ctx, n.HealthCheck), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "QUIC", js_traits<tribool>::wrap(ctx, n.QUIC), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "DisableHTTPMask", js_traits<tribool>::wrap(ctx, n.DisableHTTPMask), JS_PROP_C_W_E);

            return obj;
        }

        static Proxy unwrap(JSContext *ctx, JSValueConst v)
        {
            Proxy node;
            node.Type = unwrap_free<ProxyType>(ctx, v, "Type");
            node.Id = unwrap_free<int32_t>(ctx, v, "Id");
            node.GroupId = unwrap_free<int32_t>(ctx, v, "GroupId");
            node.Group = unwrap_free<std::string>(ctx, v, "Group");
            node.Remark = unwrap_free<std::string>(ctx, v, "Remark");
            node.Hostname = unwrap_free<std::string>(ctx, v, "Server");
            node.Port = unwrap_free<uint32_t>(ctx, v, "Port");

            node.Username = unwrap_free<std::string>(ctx, v, "Username");
            node.Password = unwrap_free<std::string>(ctx, v, "Password");
            node.EncryptMethod = unwrap_free<std::string>(ctx, v, "EncryptMethod");
            node.Plugin = unwrap_free<std::string>(ctx, v, "Plugin");
            node.PluginOption = unwrap_free<std::string>(ctx, v, "PluginOption");
            node.Protocol = unwrap_free<std::string>(ctx, v, "Protocol");
            node.ProtocolParam = unwrap_free<std::string>(ctx, v, "ProtocolParam");
            node.OBFS = unwrap_free<std::string>(ctx, v, "OBFS");
            node.OBFSParam = unwrap_free<std::string>(ctx, v, "OBFSParam");
            node.UserId = unwrap_free<std::string>(ctx, v, "UserId");
            node.AlterId = unwrap_free<uint32_t>(ctx, v, "AlterId");
            node.TransferProtocol = unwrap_free<std::string>(ctx, v, "TransferProtocol");
            node.FakeType = unwrap_free<std::string>(ctx, v, "FakeType");
            node.TLSSecure = unwrap_free<bool>(ctx, v, "TLSSecure");

            node.Host = unwrap_free<std::string>(ctx, v, "Host");
            node.Path = unwrap_free<std::string>(ctx, v, "Path");
            node.Edge = unwrap_free<std::string>(ctx, v, "Edge");

            node.QUICSecure = unwrap_free<std::string>(ctx, v, "QUICSecure");
            node.QUICSecret = unwrap_free<std::string>(ctx, v, "QUICSecret");

            node.UDP = unwrap_free<tribool>(ctx, v, "UDP");
            node.TCPFastOpen = unwrap_free<tribool>(ctx, v, "TCPFastOpen");
            node.AllowInsecure = unwrap_free<tribool>(ctx, v, "AllowInsecure");
            node.TLS13 = unwrap_free<tribool>(ctx, v, "TLS13");

            node.SnellVersion = unwrap_free<int32_t>(ctx, v, "SnellVersion");
            node.ServerName = unwrap_free<std::string>(ctx, v, "ServerName");

            node.SelfIP = unwrap_free<std::string>(ctx, v, "SelfIP");
            node.SelfIPv6 = unwrap_free<std::string>(ctx, v, "SelfIPv6");
            node.PublicKey = unwrap_free<std::string>(ctx, v, "PublicKey");
            node.PrivateKey = unwrap_free<std::string>(ctx, v, "PrivateKey");
            node.PreSharedKey = unwrap_free<std::string>(ctx, v, "PreSharedKey");
            node.DnsServers = unwrap_free<StringArray>(ctx, v, "DnsServers");
            node.Mtu = unwrap_free<uint32_t>(ctx, v, "Mtu");
            node.AllowedIPs = unwrap_free<std::string>(ctx, v, "AllowedIPs");
            node.KeepAlive = unwrap_free<uint32_t>(ctx, v, "KeepAlive");
            node.TestUrl = unwrap_free<std::string>(ctx, v, "TestUrl");
            node.ClientId = unwrap_free<std::string>(ctx, v, "ClientId");

            node.Ports = unwrap_free<std::string>(ctx, v, "Ports");
            node.Up = unwrap_free<std::string>(ctx, v, "Up");
            node.UpSpeed = unwrap_free<uint32_t>(ctx, v, "UpSpeed");
            node.Down = unwrap_free<std::string>(ctx, v, "Down");
            node.DownSpeed = unwrap_free<uint32_t>(ctx, v, "DownSpeed");
            node.Auth = unwrap_free<std::string>(ctx, v, "Auth");
            node.AuthStr = unwrap_free<std::string>(ctx, v, "AuthStr");
            node.SNI = unwrap_free<std::string>(ctx, v, "SNI");
            node.OBFSPassword = unwrap_free<std::string>(ctx, v, "OBFSPassword");
            node.Fingerprint = unwrap_free<std::string>(ctx, v, "Fingerprint");
            node.Ca = unwrap_free<std::string>(ctx, v, "Ca");
            node.CaStr = unwrap_free<std::string>(ctx, v, "CaStr");

            node.RecvWindowConn = unwrap_free<uint32_t>(ctx, v, "RecvWindowConn");
            node.RecvWindow = unwrap_free<uint32_t>(ctx, v, "RecvWindow");
            node.DisableMtuDiscovery = unwrap_free<tribool>(ctx, v, "DisableMtuDiscovery");
            node.HopInterval = unwrap_free<uint32_t>(ctx, v, "HopInterval");
            node.CWND = unwrap_free<uint32_t>(ctx, v, "CWND");
            node.Alpn = unwrap_free<std::string>(ctx, v, "Alpn");
            node.AlpnList = unwrap_free<StringArray>(ctx, v, "AlpnList");

            node.UUID = unwrap_free<std::string>(ctx, v, "UUID");
            node.IP = unwrap_free<std::string>(ctx, v, "IP");
            node.HeartbeatInterval = unwrap_free<std::string>(ctx, v, "HeartbeatInterval");
            node.DisableSNI = unwrap_free<tribool>(ctx, v, "DisableSNI");
            node.ReduceRTT = unwrap_free<tribool>(ctx, v, "ReduceRTT");
            node.RequestTimeout = unwrap_free<uint32_t>(ctx, v, "RequestTimeout");
            node.UdpRelayMode = unwrap_free<std::string>(ctx, v, "UdpRelayMode");
            node.CongestionController = unwrap_free<std::string>(ctx, v, "CongestionController");
            node.MaxUdpRelayPacketSize = unwrap_free<uint32_t>(ctx, v, "MaxUdpRelayPacketSize");

            node.FastOpen = unwrap_free<tribool>(ctx, v, "FastOpen");
            node.MaxOpenStreams = unwrap_free<uint32_t>(ctx, v, "MaxOpenStreams");

            node.IdleSessionCheckInterval = unwrap_free<uint32_t>(ctx, v, "IdleSessionCheckInterval");
            node.IdleSessionTimeout = unwrap_free<uint32_t>(ctx, v, "IdleSessionTimeout");
            node.MinIdleSession = unwrap_free<uint32_t>(ctx, v, "MinIdleSession");

            node.Flow = unwrap_free<std::string>(ctx, v, "Flow");
            node.XTLS = unwrap_free<uint32_t>(ctx, v, "XTLS");
            node.PacketEncoding = unwrap_free<std::string>(ctx, v, "PacketEncoding");
            node.ShortID = unwrap_free<std::string>(ctx, v, "ShortID");

            node.SmuxMaxConnections = unwrap_free<int32_t>(ctx, v, "SmuxMaxConnections");
            node.SmuxMaxStreams = unwrap_free<int32_t>(ctx, v, "SmuxMaxStreams");
            node.SmuxMinStreams = unwrap_free<int32_t>(ctx, v, "SmuxMinStreams");
            node.SmuxPadding = unwrap_free<tribool>(ctx, v, "SmuxPadding");
            node.SmuxStatistic = unwrap_free<tribool>(ctx, v, "SmuxStatistic");
            node.SmuxOnlyTcp = unwrap_free<tribool>(ctx, v, "SmuxOnlyTcp");
            node.SmuxProtocol = unwrap_free<std::string>(ctx, v, "SmuxProtocol");

            node.ClientFingerprint = unwrap_free<std::string>(ctx, v, "ClientFingerprint");
            node.EchConfig = unwrap_free<std::string>(ctx, v, "EchConfig");
            node.EchEnable = unwrap_free<tribool>(ctx, v, "EchEnable");
            node.SupportX25519Mlkem768 = unwrap_free<tribool>(ctx, v, "SupportX25519Mlkem768");
            node.GrpcServiceName = unwrap_free<std::string>(ctx, v, "GrpcServiceName");
            node.GRPCMode = unwrap_free<std::string>(ctx, v, "GRPCMode");
            node.GrpcUserAgent = unwrap_free<std::string>(ctx, v, "GrpcUserAgent");
            node.GrpcPingInterval = unwrap_free<uint32_t>(ctx, v, "GrpcPingInterval");

            node.WsPath = unwrap_free<std::string>(ctx, v, "WsPath");
            node.WsHeaders = unwrap_free<std::string>(ctx, v, "WsHeaders");
            node.WsEarlyDataHeaderName = unwrap_free<std::string>(ctx, v, "WsEarlyDataHeaderName");
            node.WsMaxEarlyData = unwrap_free<int32_t>(ctx, v, "WsMaxEarlyData");
            node.V2rayHttpUpgrade = unwrap_free<tribool>(ctx, v, "V2rayHttpUpgrade");
            node.V2rayHttpUpgradeFastOpen = unwrap_free<tribool>(ctx, v, "V2rayHttpUpgradeFastOpen");

            node.InitialStreamReceiveWindow = unwrap_free<uint32_t>(ctx, v, "InitialStreamReceiveWindow");
            node.MaxStreamReceiveWindow = unwrap_free<uint32_t>(ctx, v, "MaxStreamReceiveWindow");
            node.InitialConnectionReceiveWindow = unwrap_free<uint32_t>(ctx, v, "InitialConnectionReceiveWindow");
            node.MaxConnectionReceiveWindow = unwrap_free<uint32_t>(ctx, v, "MaxConnectionReceiveWindow");

            node.Multiplexing = unwrap_free<std::string>(ctx, v, "Multiplexing");
            node.TLSStr = unwrap_free<std::string>(ctx, v, "TLSStr");

            node.SmuxEnabled = unwrap_free<tribool>(ctx, v, "SmuxEnabled");
            node.XUDP = unwrap_free<tribool>(ctx, v, "XUDP");
            node.UDPoverTCP = unwrap_free<tribool>(ctx, v, "UDPoverTCP");
            node.UnderlyingProxy = unwrap_free<std::string>(ctx, v, "UnderlyingProxy");
            node.IPVersion = unwrap_free<std::string>(ctx, v, "IPVersion");
            node.TuicVersion = unwrap_free<uint32_t>(ctx, v, "TuicVersion");

            node.Key = unwrap_free<std::string>(ctx, v, "Key");
            node.AEAD = unwrap_free<std::string>(ctx, v, "AEAD");
            node.PaddingMin = unwrap_free<int32_t>(ctx, v, "PaddingMin");
            node.PaddingMax = unwrap_free<int32_t>(ctx, v, "PaddingMax");
            node.TableType = unwrap_free<std::string>(ctx, v, "TableType");
            node.HTTPMask = unwrap_free<tribool>(ctx, v, "HTTPMask");
            node.HTTPMaskMode = unwrap_free<std::string>(ctx, v, "HTTPMaskMode");
            node.HTTPMaskTLS = unwrap_free<tribool>(ctx, v, "HTTPMaskTLS");
            node.HTTPMaskHost = unwrap_free<std::string>(ctx, v, "HTTPMaskHost");
            node.HTTPMaskMultiplex = unwrap_free<std::string>(ctx, v, "HTTPMaskMultiplex");
            node.EnablePureDownlink = unwrap_free<tribool>(ctx, v, "EnablePureDownlink");
            node.CustomTable = unwrap_free<std::string>(ctx, v, "CustomTable");
            node.CustomTables = unwrap_free<StringArray>(ctx, v, "CustomTables");
            node.PortRange = unwrap_free<std::string>(ctx, v, "PortRange");
            node.HandshakeMode = unwrap_free<std::string>(ctx, v, "HandshakeMode");

            // Common additional fields
            node.UDPOverStream = unwrap_free<tribool>(ctx, v, "UDPOverStream");
            node.UDPOverStreamVersion = unwrap_free<int32_t>(ctx, v, "UDPOverStreamVersion");
            node.UDPOverTCPVersion = unwrap_free<int32_t>(ctx, v, "UDPOverTCPVersion");
            node.Certificate = unwrap_free<std::string>(ctx, v, "Certificate");
            node.CertificateKey = unwrap_free<std::string>(ctx, v, "CertificateKey");
            node.EchQueryServerName = unwrap_free<std::string>(ctx, v, "EchQueryServerName");

            // SS KCP fields
            node.KCPKey = unwrap_free<std::string>(ctx, v, "KCPKey");
            node.KCPCrypt = unwrap_free<std::string>(ctx, v, "KCPCrypt");
            node.KCPMode = unwrap_free<std::string>(ctx, v, "KCPMode");
            node.KCPConn = unwrap_free<uint32_t>(ctx, v, "KCPConn");
            node.KCPAutoExpire = unwrap_free<uint32_t>(ctx, v, "KCPAutoExpire");
            node.KCPScavengeTTL = unwrap_free<uint32_t>(ctx, v, "KCPScavengeTTL");
            node.KCPMtu = unwrap_free<uint32_t>(ctx, v, "KCPMtu");
            node.KCPRateLimit = unwrap_free<uint32_t>(ctx, v, "KCPRateLimit");
            node.KCPSndWnd = unwrap_free<uint32_t>(ctx, v, "KCPSndWnd");
            node.KCPRcvWnd = unwrap_free<uint32_t>(ctx, v, "KCPRcvWnd");
            node.KCPDataShard = unwrap_free<uint32_t>(ctx, v, "KCPDataShard");
            node.KCPParityShard = unwrap_free<uint32_t>(ctx, v, "KCPParityShard");
            node.KCPDSCP = unwrap_free<uint32_t>(ctx, v, "KCPDSCP");
            node.KCPNoComp = unwrap_free<bool>(ctx, v, "KCPNoComp");
            node.KCPAckNoDelay = unwrap_free<bool>(ctx, v, "KCPAckNoDelay");
            node.KCPNodelay = unwrap_free<uint32_t>(ctx, v, "KCPNodelay");
            node.KCPInterval = unwrap_free<uint32_t>(ctx, v, "KCPInterval");
            node.KCPResend = unwrap_free<uint32_t>(ctx, v, "KCPResend");
            node.KCPSockbuf = unwrap_free<uint32_t>(ctx, v, "KCPSockbuf");
            node.KCPSmuxver = unwrap_free<uint32_t>(ctx, v, "KCPSmuxver");
            node.KCPSmuxbuf = unwrap_free<uint32_t>(ctx, v, "KCPSmuxbuf");
            node.KCPFramesize = unwrap_free<uint32_t>(ctx, v, "KCPFramesize");
            node.KCPStreambuf = unwrap_free<uint32_t>(ctx, v, "KCPStreambuf");
            node.KCPKeepalive = unwrap_free<uint32_t>(ctx, v, "KCPKeepalive");

            // VMess/VLESS additional fields
            node.Token = unwrap_free<std::string>(ctx, v, "Token");
            node.WsHeadersMap = unwrap_free<std::string>(ctx, v, "WsHeadersMap");
            node.HTTPHeaders = unwrap_free<std::string>(ctx, v, "HTTPHeaders");
            node.HTTPOptsMethod = unwrap_free<std::string>(ctx, v, "HTTPOptsMethod");
            node.HTTPOptsPaths = unwrap_free<StringArray>(ctx, v, "HTTPOptsPaths");
            node.HTTPOptsHeaders = unwrap_free<std::string>(ctx, v, "HTTPOptsHeaders");
            node.H2Hosts = unwrap_free<StringArray>(ctx, v, "H2Hosts");
            node.GrpcMaxConnections = unwrap_free<uint32_t>(ctx, v, "GrpcMaxConnections");
            node.GrpcMinStreams = unwrap_free<uint32_t>(ctx, v, "GrpcMinStreams");
            node.GrpcMaxStreams = unwrap_free<uint32_t>(ctx, v, "GrpcMaxStreams");
            node.XHTTPNoGRPCHeader = unwrap_free<tribool>(ctx, v, "XHTTPNoGRPCHeader");
            node.XHTTPXPaddingBytes = unwrap_free<std::string>(ctx, v, "XHTTPXPaddingBytes");
            node.XHTTPXPaddingObfsMode = unwrap_free<tribool>(ctx, v, "XHTTPXPaddingObfsMode");
            node.XHTTPXPaddingKey = unwrap_free<std::string>(ctx, v, "XHTTPXPaddingKey");
            node.XHTTPXPaddingHeader = unwrap_free<std::string>(ctx, v, "XHTTPXPaddingHeader");
            node.XHTTPXPaddingPlacement = unwrap_free<std::string>(ctx, v, "XHTTPXPaddingPlacement");
            node.XHTTPXPaddingMethod = unwrap_free<std::string>(ctx, v, "XHTTPXPaddingMethod");
            node.XHTTPUplinkHTTPMethod = unwrap_free<std::string>(ctx, v, "XHTTPUplinkHTTPMethod");
            node.XHTTPSessionPlacement = unwrap_free<std::string>(ctx, v, "XHTTPSessionPlacement");
            node.XHTTPSessionKey = unwrap_free<std::string>(ctx, v, "XHTTPSessionKey");
            node.XHTTPSessionTable = unwrap_free<std::string>(ctx, v, "XHTTPSessionTable");
            node.XHTTPSessionLength = unwrap_free<std::string>(ctx, v, "XHTTPSessionLength");
            node.XHTTPSeqPlacement = unwrap_free<std::string>(ctx, v, "XHTTPSeqPlacement");
            node.XHTTPSeqKey = unwrap_free<std::string>(ctx, v, "XHTTPSeqKey");
            node.XHTTPUplinkDataPlacement = unwrap_free<std::string>(ctx, v, "XHTTPUplinkDataPlacement");
            node.XHTTPUplinkDataKey = unwrap_free<std::string>(ctx, v, "XHTTPUplinkDataKey");
            node.XHTTPUplinkChunkSize = unwrap_free<std::string>(ctx, v, "XHTTPUplinkChunkSize");
            node.XHTTPScMaxEachPostBytes = unwrap_free<std::string>(ctx, v, "XHTTPScMaxEachPostBytes");
            node.XHTTPScMaxBufferedPosts = unwrap_free<std::string>(ctx, v, "XHTTPScMaxBufferedPosts");
            node.XHTTPScMinPostsIntervalMs = unwrap_free<std::string>(ctx, v, "XHTTPScMinPostsIntervalMs");
            node.XHTTPHeaders = unwrap_free<std::string>(ctx, v, "XHTTPHeaders");
            node.XHTTPReuseMaxConnections = unwrap_free<std::string>(ctx, v, "XHTTPReuseMaxConnections");
            node.XHTTPReuseMaxConcurrency = unwrap_free<std::string>(ctx, v, "XHTTPReuseMaxConcurrency");
            node.XHTTPReuseCMaxReuseTimes = unwrap_free<std::string>(ctx, v, "XHTTPReuseCMaxReuseTimes");
            node.XHTTPReuseHMaxRequestTimes = unwrap_free<std::string>(ctx, v, "XHTTPReuseHMaxRequestTimes");
            node.XHTTPReuseHMaxReusableSecs = unwrap_free<std::string>(ctx, v, "XHTTPReuseHMaxReusableSecs");
            node.XHTTPReuseHKeepAlivePeriod = unwrap_free<uint32_t>(ctx, v, "XHTTPReuseHKeepAlivePeriod");
            node.XHTTPDownloadPath = unwrap_free<std::string>(ctx, v, "XHTTPDownloadPath");
            node.XHTTPDownloadHost = unwrap_free<std::string>(ctx, v, "XHTTPDownloadHost");
            node.XHTTPDownloadHeaders = unwrap_free<std::string>(ctx, v, "XHTTPDownloadHeaders");
            node.XHTTPDownloadReuseMaxConnections = unwrap_free<std::string>(ctx, v, "XHTTPDownloadReuseMaxConnections");
            node.XHTTPDownloadReuseMaxConcurrency = unwrap_free<std::string>(ctx, v, "XHTTPDownloadReuseMaxConcurrency");
            node.XHTTPDownloadReuseCMaxReuseTimes = unwrap_free<std::string>(ctx, v, "XHTTPDownloadReuseCMaxReuseTimes");
            node.XHTTPDownloadReuseHMaxRequestTimes = unwrap_free<std::string>(ctx, v, "XHTTPDownloadReuseHMaxRequestTimes");
            node.XHTTPDownloadReuseHMaxReusableSecs = unwrap_free<std::string>(ctx, v, "XHTTPDownloadReuseHMaxReusableSecs");
            node.XHTTPDownloadReuseHKeepAlivePeriod = unwrap_free<uint32_t>(ctx, v, "XHTTPDownloadReuseHKeepAlivePeriod");
            node.XHTTPDownloadServer = unwrap_free<std::string>(ctx, v, "XHTTPDownloadServer");
            node.XHTTPDownloadPort = unwrap_free<uint32_t>(ctx, v, "XHTTPDownloadPort");
            node.XHTTPDownloadTLS = unwrap_free<tribool>(ctx, v, "XHTTPDownloadTLS");
            node.XHTTPDownloadALPN = unwrap_free<StringArray>(ctx, v, "XHTTPDownloadALPN");
            node.XHTTPDownloadECHEnable = unwrap_free<tribool>(ctx, v, "XHTTPDownloadECHEnable");
            node.XHTTPDownloadECHConfig = unwrap_free<std::string>(ctx, v, "XHTTPDownloadECHConfig");
            node.XHTTPDownloadECHQueryServerName = unwrap_free<std::string>(ctx, v, "XHTTPDownloadECHQueryServerName");
            node.XHTTPDownloadRealityPublicKey = unwrap_free<std::string>(ctx, v, "XHTTPDownloadRealityPublicKey");
            node.XHTTPDownloadRealityShortID = unwrap_free<std::string>(ctx, v, "XHTTPDownloadRealityShortID");
            node.XHTTPDownloadRealitySpiderX = unwrap_free<std::string>(ctx, v, "XHTTPDownloadRealitySpiderX");
            node.XHTTPDownloadRealitySupportX25519Mlkem768 = unwrap_free<tribool>(ctx, v, "XHTTPDownloadRealitySupportX25519Mlkem768");
            node.XHTTPDownloadSkipCertVerify = unwrap_free<tribool>(ctx, v, "XHTTPDownloadSkipCertVerify");
            node.XHTTPDownloadFingerprint = unwrap_free<std::string>(ctx, v, "XHTTPDownloadFingerprint");
            node.XHTTPDownloadCertificate = unwrap_free<std::string>(ctx, v, "XHTTPDownloadCertificate");
            node.XHTTPDownloadPrivateKey = unwrap_free<std::string>(ctx, v, "XHTTPDownloadPrivateKey");
            node.XHTTPDownloadServerName = unwrap_free<std::string>(ctx, v, "XHTTPDownloadServerName");
            node.XHTTPDownloadClientFingerprint = unwrap_free<std::string>(ctx, v, "XHTTPDownloadClientFingerprint");
            node.SpiderX = unwrap_free<std::string>(ctx, v, "SpiderX");
            node.FlowShow = unwrap_free<tribool>(ctx, v, "FlowShow");
            node.PacketAddr = unwrap_free<tribool>(ctx, v, "PacketAddr");
            node.GlobalPadding = unwrap_free<tribool>(ctx, v, "GlobalPadding");
            node.AuthenticatedLength = unwrap_free<tribool>(ctx, v, "AuthenticatedLength");
            node.Encryption = unwrap_free<std::string>(ctx, v, "Encryption");

            // Trojan additional
            node.TrojanSSOpts = unwrap_free<bool>(ctx, v, "TrojanSSOpts");
            node.TrojanSSMethod = unwrap_free<std::string>(ctx, v, "TrojanSSMethod");
            node.TrojanSSPassword = unwrap_free<std::string>(ctx, v, "TrojanSSPassword");

            // Snell additional
            node.ObfsPassword = unwrap_free<std::string>(ctx, v, "ObfsPassword");
            node.ObfsVersion = unwrap_free<uint32_t>(ctx, v, "ObfsVersion");
            node.ObfsAlpn = unwrap_free<StringArray>(ctx, v, "ObfsAlpn");
            node.ObfsFingerprint = unwrap_free<std::string>(ctx, v, "ObfsFingerprint");
            node.ObfsCertificate = unwrap_free<std::string>(ctx, v, "ObfsCertificate");
            node.ObfsPrivateKey = unwrap_free<std::string>(ctx, v, "ObfsPrivateKey");
            node.ObfsSkipCertVerify = unwrap_free<tribool>(ctx, v, "ObfsSkipCertVerify");

            // WireGuard additional
            node.Reserved = unwrap_free<StringArray>(ctx, v, "Reserved");
            node.Peers = unwrap_free<StringArray>(ctx, v, "Peers");
            node.DialerProxy = unwrap_free<std::string>(ctx, v, "DialerProxy");
            node.RemoteDnsResolve = unwrap_free<tribool>(ctx, v, "RemoteDnsResolve");
            node.AmneziaJC = unwrap_free<std::string>(ctx, v, "AmneziaJC");
            node.AmneziaJMin = unwrap_free<std::string>(ctx, v, "AmneziaJMin");
            node.AmneziaJMax = unwrap_free<std::string>(ctx, v, "AmneziaJMax");
            node.AmneziaS1 = unwrap_free<std::string>(ctx, v, "AmneziaS1");
            node.AmneziaS2 = unwrap_free<std::string>(ctx, v, "AmneziaS2");
            node.AmneziaS3 = unwrap_free<std::string>(ctx, v, "AmneziaS3");
            node.AmneziaS4 = unwrap_free<std::string>(ctx, v, "AmneziaS4");
            node.AmneziaH1 = unwrap_free<std::string>(ctx, v, "AmneziaH1");
            node.AmneziaH2 = unwrap_free<std::string>(ctx, v, "AmneziaH2");
            node.AmneziaH3 = unwrap_free<std::string>(ctx, v, "AmneziaH3");
            node.AmneziaH4 = unwrap_free<std::string>(ctx, v, "AmneziaH4");
            node.AmneziaI1 = unwrap_free<std::string>(ctx, v, "AmneziaI1");
            node.AmneziaI2 = unwrap_free<std::string>(ctx, v, "AmneziaI2");
            node.AmneziaI3 = unwrap_free<std::string>(ctx, v, "AmneziaI3");
            node.AmneziaI4 = unwrap_free<std::string>(ctx, v, "AmneziaI4");
            node.AmneziaI5 = unwrap_free<std::string>(ctx, v, "AmneziaI5");
            node.AmneziaJ1 = unwrap_free<std::string>(ctx, v, "AmneziaJ1");
            node.AmneziaJ2 = unwrap_free<std::string>(ctx, v, "AmneziaJ2");
            node.AmneziaJ3 = unwrap_free<std::string>(ctx, v, "AmneziaJ3");
            node.AmneziaItime = unwrap_free<std::string>(ctx, v, "AmneziaItime");

            // OpenVPN
            node.OpenVPNDev = unwrap_free<std::string>(ctx, v, "OpenVPNDev");
            node.OpenVPNTLSCrypt = unwrap_free<std::string>(ctx, v, "OpenVPNTLSCrypt");
            node.CompLZO = unwrap_free<std::string>(ctx, v, "CompLZO");
            node.OpenVPNPing = unwrap_free<uint32_t>(ctx, v, "OpenVPNPing");
            node.OpenVPNPingRestart = unwrap_free<uint32_t>(ctx, v, "OpenVPNPingRestart");
            node.OpenVPNPeerInfo = unwrap_free<StringMap>(ctx, v, "OpenVPNPeerInfo");

            // Tailscale
            node.TailscaleAuthKey = unwrap_free<std::string>(ctx, v, "TailscaleAuthKey");
            node.TailscaleControlURL = unwrap_free<std::string>(ctx, v, "TailscaleControlURL");
            node.TailscaleStateDir = unwrap_free<std::string>(ctx, v, "TailscaleStateDir");
            node.TailscaleEphemeral = unwrap_free<tribool>(ctx, v, "TailscaleEphemeral");
            node.TailscaleAcceptRoutes = unwrap_free<tribool>(ctx, v, "TailscaleAcceptRoutes");
            node.TailscaleExitNode = unwrap_free<std::string>(ctx, v, "TailscaleExitNode");
            node.TailscaleExitNodeAllowLANAccess = unwrap_free<tribool>(ctx, v, "TailscaleExitNodeAllowLANAccess");

            // Hysteria/Hysteria2 additional
            node.Hysteria2HopInterval = unwrap_free<std::string>(ctx, v, "Hysteria2HopInterval");
            node.UdpMTU = unwrap_free<uint32_t>(ctx, v, "UdpMTU");
            node.ObfsMinPacketSize = unwrap_free<uint32_t>(ctx, v, "ObfsMinPacketSize");
            node.ObfsMaxPacketSize = unwrap_free<uint32_t>(ctx, v, "ObfsMaxPacketSize");
            node.RealmEnable = unwrap_free<tribool>(ctx, v, "RealmEnable");
            node.RealmServerURL = unwrap_free<std::string>(ctx, v, "RealmServerURL");
            node.RealmToken = unwrap_free<std::string>(ctx, v, "RealmToken");
            node.RealmID = unwrap_free<std::string>(ctx, v, "RealmID");
            node.RealmStunServers = unwrap_free<StringArray>(ctx, v, "RealmStunServers");
            node.RealmSNI = unwrap_free<std::string>(ctx, v, "RealmSNI");
            node.RealmSkipCertVerify = unwrap_free<tribool>(ctx, v, "RealmSkipCertVerify");
            node.RealmFingerprint = unwrap_free<std::string>(ctx, v, "RealmFingerprint");
            node.RealmCertificate = unwrap_free<std::string>(ctx, v, "RealmCertificate");
            node.RealmPrivateKey = unwrap_free<std::string>(ctx, v, "RealmPrivateKey");
            node.RealmALPN = unwrap_free<StringArray>(ctx, v, "RealmALPN");

            // MASQUE
            node.MasqueIPv6 = unwrap_free<std::string>(ctx, v, "MasqueIPv6");

            // TUIC/AnyTLS additional
            node.BBRProfile = unwrap_free<std::string>(ctx, v, "BBRProfile");
            node.Reuse = unwrap_free<tribool>(ctx, v, "Reuse");
            node.PaddingScheme = unwrap_free<std::string>(ctx, v, "PaddingScheme");

            // GOST
            node.GostRelayForward = unwrap_free<bool>(ctx, v, "GostRelayForward");

            // Mieru additional
            node.PathRoot = unwrap_free<std::string>(ctx, v, "PathRoot");
            node.HandshakeTimeout = unwrap_free<uint32_t>(ctx, v, "HandshakeTimeout");
            node.TrafficPattern = unwrap_free<std::string>(ctx, v, "TrafficPattern");

            // TrustTunnel additional
            node.HealthCheck = unwrap_free<tribool>(ctx, v, "HealthCheck");
            node.QUIC = unwrap_free<tribool>(ctx, v, "QUIC");
            node.DisableHTTPMask = unwrap_free<tribool>(ctx, v, "DisableHTTPMask");

            return node;
        }
    };
}

template <typename Fn>
void script_safe_runner(qjs::Runtime *runtime, qjs::Context *context, Fn runnable, bool clean_context = false)
{
    qjs::Runtime *internal_runtime = runtime;
    qjs::Context *internal_context = context;
    defer(if(clean_context) {delete internal_context; delete internal_runtime;} )
    if(clean_context)
    {
        internal_runtime = new qjs::Runtime();
        script_runtime_init(*internal_runtime);
        internal_context = new qjs::Context(*internal_runtime);
        script_context_init(*internal_context);
    }
    if(internal_runtime && internal_context)
        runnable(*internal_context);
}

#else
template <typename... Args>
void script_safe_runner(Args... args) { }
#endif // NO_JS_RUNTIME

#endif // SCRIPT_QUICKJS_H_INCLUDED
