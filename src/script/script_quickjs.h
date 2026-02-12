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

            JS_DefinePropertyValueStr(ctx, obj, "ClientFingerprint", JS_NewString(ctx, n.ClientFingerprint), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EchConfig", JS_NewString(ctx, n.EchConfig), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "EchEnable", js_traits<tribool>::wrap(ctx, n.EchEnable), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "SupportX25519Mlkem768", js_traits<tribool>::wrap(ctx, n.SupportX25519Mlkem768), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GrpcServiceName", JS_NewString(ctx, n.GrpcServiceName), JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, obj, "GRPCMode", JS_NewString(ctx, n.GRPCMode), JS_PROP_C_W_E);

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

            node.ClientFingerprint = unwrap_free<std::string>(ctx, v, "ClientFingerprint");
            node.EchConfig = unwrap_free<std::string>(ctx, v, "EchConfig");
            node.EchEnable = unwrap_free<tribool>(ctx, v, "EchEnable");
            node.SupportX25519Mlkem768 = unwrap_free<tribool>(ctx, v, "SupportX25519Mlkem768");
            node.GrpcServiceName = unwrap_free<std::string>(ctx, v, "GrpcServiceName");
            node.GRPCMode = unwrap_free<std::string>(ctx, v, "GRPCMode");

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
