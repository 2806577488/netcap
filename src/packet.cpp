#include "netcap/packet.hpp"

namespace netcap {

const char* linktype_name(int lt) {
  switch (lt) {
    case DLT_NULL: return "NULL/loopback";
    case DLT_EN10MB: return "Ethernet";
    case DLT_RAW: return "raw IP";
    case DLT_LINUX_SLL: return "Linux cooked v1";
    case DLT_LINUX_SLL2: return "Linux cooked v2";
    case DLT_IEEE802_11: return "IEEE 802.11";
    case DLT_IPV4: return "raw IPv4";
    case DLT_IPV6: return "raw IPv6";
    default: return "unknown";
  }
}

const char* app_kind_name(AppKind k) {
  switch (k) {
    case AppKind::Http: return "HTTP";
    case AppKind::Tls: return "TLS";
    case AppKind::Dns: return "DNS";
    case AppKind::Quic: return "QUIC";
    case AppKind::Ssh: return "SSH";
    case AppKind::Dhcp: return "DHCP";
    case AppKind::Mdns: return "mDNS";
    case AppKind::Unknown: return "unknown";
  }
  return "unknown";
}

const char* app_kind_tag(AppKind k) {
  switch (k) {
    case AppKind::Http: return "HTTP";
    case AppKind::Tls: return "TLS";
    case AppKind::Dns: return "DNS";
    case AppKind::Quic: return "QUIC";
    case AppKind::Ssh: return "SSH";
    case AppKind::Dhcp: return "DHCP";
    case AppKind::Mdns: return "MDNS";
    case AppKind::Unknown: return "";
  }
  return "";
}

}  // namespace netcap
