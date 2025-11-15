/*
 * libzt IPv4 input hook and public filter setter
 *
 * This file wires lwIP's LWIP_HOOK_IP4_INPUT to a user-provided callback
 * set via zts_set_ip4_input_filter(). If the callback returns nonzero,
 * the pbuf is consumed and not passed to lwIP.
 */

#include <cstdlib>
#include "ZeroTierSockets.h"

extern "C" {
#include "lwip/pbuf.h"
#include "lwip/netif.h"
}
#include <atomic>
#include <stdint.h>

// Forward declarations needed by early hook implementations
static struct netif* find_netif_by_ip4_host(uint32_t ip_host);
// Define logging and local ZT IP earlier to be available to hooks
static std::atomic<int> g_pkt_diag{0};
static uint32_t g_zt_ip_host = 0;

static zts_ip4_filter_cb g_ip4_filter_cb = nullptr;

extern "C" ZTS_API int ZTCALL zts_set_ip4_input_filter(zts_ip4_filter_cb cb)
{
    g_ip4_filter_cb = cb;
    return ZTS_ERR_OK;
}

extern "C" int zts_lwip_hook_ip4_input(struct pbuf* p, struct netif* input_netif)
{
    if (!p) {
        return 0;
    }

    // If packet diagnostics are enabled and this packet arrived on the ZT netif, log basic header info
    if (g_pkt_diag.load(std::memory_order_relaxed) != 0 && g_zt_ip_host != 0 && input_netif) {
        struct netif* zt = find_netif_by_ip4_host(g_zt_ip_host);
        if (zt && input_netif == zt) {
            // Peek first 20 bytes (IPv4 header min)
            uint8_t hdr[20];
            u16_t copied_hdr = pbuf_copy_partial(p, hdr, sizeof(hdr), 0);
            if (copied_hdr >= 20 && (hdr[0] >> 4) == 4) {
                uint8_t ihl = (uint8_t)((hdr[0] & 0x0F) * 4);
                uint8_t proto = hdr[9];
                ip4_addr_t src, dst;
                IP4_ADDR(&src, hdr[12], hdr[13], hdr[14], hdr[15]);
                IP4_ADDR(&dst, hdr[16], hdr[17], hdr[18], hdr[19]);
                char srcbuf[16], dstbuf[16];
                ip4addr_ntoa_r(&src, srcbuf, sizeof(srcbuf));
                ip4addr_ntoa_r(&dst, dstbuf, sizeof(dstbuf));
                printf("ZT_PKT_IN netif=%c%c%u len=%u proto=%u src=%s dst=%s\n",
                       input_netif->name[0], input_netif->name[1], input_netif->num,
                       (unsigned)p->tot_len, (unsigned)proto, srcbuf, dstbuf);
                fflush(stdout);
            }
        }
    }

    if (!g_ip4_filter_cb) {
        return 0; // no filter set, continue normal input
    }

    const unsigned short ip_len = (unsigned short)p->tot_len;
    if (ip_len == 0) {
        return 0;
    }

    // Allocate linear buffer for entire IP packet
    uint8_t* buf = (uint8_t*)malloc(ip_len);
    if (!buf) {
        return 0;
    }
    // Copy full packet (starting at IP header) into contiguous buffer
    const u16_t copied = pbuf_copy_partial(p, buf, ip_len, 0);
    if (copied != ip_len) {
        free(buf);
        return 0;
    }

    int consume = 0;
    // Invoke user filter
    consume = g_ip4_filter_cb((const uint8_t*)buf, (unsigned short)ip_len);

    if (consume) {
        // Filter consumed packet: free pbuf and do not pass into lwIP
        pbuf_free(p);
        free(buf);
        return 1; // consumed
    }

    free(buf);
    return 0; // continue normal processing
}

/* -------------------- Route hook plumbing for IPv4 -------------------- */
extern "C" {
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/etharp.h"
}

#include <vector>
#include <mutex>
#include <string>
#include <cstring>
#include <atomic>

struct ZtRouteV4 {
    uint32_t net;      // host-order IPv4 network address
    uint8_t  prefix;   // prefix length (0..32)
    uint32_t via;      // host-order IPv4 next hop
    uint16_t metric;   // optional
};

static std::mutex g_routes_mu;
static std::vector<ZtRouteV4> g_routes_v4;
static ip4_addr_t g_hook_ret_gw;     // storage for ETHARP_GET_GW return
static std::atomic<int> g_routes_enabled{0}; // master switch for routing hooks (0=off,1=on)

/* Helpers */
static inline uint32_t ip4_to_host(const ip4_addr_t* a) {
    return lwip_ntohl(ip4_addr_get_u32(a));
}
static inline ip4_addr_t host_to_ip4(uint32_t h) {
    ip4_addr_t a; ip4_addr_set_u32(&a, lwip_htonl(h)); return a;
}
static inline uint32_t mask_from_prefix(uint8_t pfx) {
    if (pfx == 0) return 0u;
    if (pfx >= 32) return 0xFFFFFFFFu;
    return (pfx == 0) ? 0 : (0xFFFFFFFFu << (32 - pfx));
}
static inline bool match_route(uint32_t dst_host, const ZtRouteV4& r) {
    const uint32_t m = mask_from_prefix(r.prefix);
    return (dst_host & m) == (r.net & m);
}
static struct netif* find_netif_by_ip4_host(uint32_t ip_host)
{
    ip4_addr_t want = host_to_ip4(ip_host);
    for (struct netif* n = netif_list; n; n = n->next) {
#if LWIP_IPV4
        const ip4_addr_t* nip = netif_ip4_addr(n);
        if (nip && ip4_addr_cmp(nip, &want)) {
            return n;
        }
#endif
    }
    /* fallback */
    return netif_default;
}

/* Longest-prefix match */
static bool find_lpm(uint32_t dst_host, ZtRouteV4& out)
{
    std::lock_guard<std::mutex> lk(g_routes_mu);
    int best = -1;
    uint8_t best_pfx = 0;
    for (size_t i = 0; i < g_routes_v4.size(); ++i) {
        if (match_route(dst_host, g_routes_v4[i])) {
            if (g_routes_v4[i].prefix > best_pfx) {
                best_pfx = g_routes_v4[i].prefix;
                best = (int)i;
            }
        }
    }
    if (best >= 0) {
        out = g_routes_v4[(size_t)best];
        return true;
    }
    return false;
}

/* Exported C API to manage routes and ZT netif selection */
extern "C" ZTS_API int ZTCALL zts_route_hooks_clear(void)
{
    std::lock_guard<std::mutex> lk(g_routes_mu);
    g_routes_v4.clear();
    return ZTS_ERR_OK;
}

extern "C" ZTS_API int ZTCALL zts_route_hooks_enable(int enabled)
{
    g_routes_enabled.store(enabled ? 1 : 0, std::memory_order_relaxed);
    return ZTS_ERR_OK;
}

extern "C" ZTS_API int ZTCALL zts_route_hooks_set_zt_ip(const char* ip4_str)
{
    if (!ip4_str || !*ip4_str) { return ZTS_ERR_ARG; }
    ip4_addr_t a4;
    if (!ip4addr_aton(ip4_str, &a4)) { return ZTS_ERR_ARG; }
    g_zt_ip_host = ip4_to_host(&a4);
    return ZTS_ERR_OK;
}

extern "C" ZTS_API int ZTCALL zts_packet_diag_enable(int enabled)
{
    g_pkt_diag.store(enabled ? 1 : 0, std::memory_order_relaxed);
    return ZTS_ERR_OK;
}

static bool parse_cidr(const char* cidr, uint32_t& net_host, uint8_t& pfx)
{
    if (!cidr || !*cidr) return false;
    const char* slash = std::strchr(cidr, '/');
    if (!slash) return false;
    std::string ip(cidr, (size_t)(slash - cidr));
    int bits = std::atoi(slash + 1);
    if (bits < 0 || bits > 32) return false;
    ip4_addr_t a;
    if (!ip4addr_aton(ip.c_str(), &a)) return false;
    pfx = (uint8_t)bits;
    uint32_t m = mask_from_prefix(pfx);
    net_host = ip4_to_host(&a) & m;
    return true;
}

extern "C" ZTS_API int ZTCALL zts_route_hooks_add_v4(const char* cidr, const char* via_ip, uint16_t metric)
{
    if (!cidr || !via_ip) return ZTS_ERR_ARG;
    uint32_t net_host = 0; uint8_t pfx = 0;
    if (!parse_cidr(cidr, net_host, pfx)) return ZTS_ERR_ARG;
    ip4_addr_t via4;
    if (!ip4addr_aton(via_ip, &via4)) return ZTS_ERR_ARG;
    ZtRouteV4 r { net_host, pfx, ip4_to_host(&via4), metric };
    {
        std::lock_guard<std::mutex> lk(g_routes_mu);
        g_routes_v4.push_back(r);
    }
    return ZTS_ERR_OK;
}

extern "C" ZTS_API int ZTCALL zts_route_hooks_count(void)
{
    std::lock_guard<std::mutex> lk(g_routes_mu);
    return (int)g_routes_v4.size();
}

/* Populate table from ZT controller routes */
extern "C" ZTS_API int ZTCALL zts_route_hooks_set_from_zt(uint64_t net_id)
{
    (void)net_id;
    // Query via core query API
    if (zts_core_lock_obtain() != ZTS_ERR_OK) {
        return ZTS_ERR_SERVICE;
    }
    int rc = ZTS_ERR_OK;
    do {
        int cnt = zts_core_query_route_count(net_id);
        if (cnt < 0) { rc = ZTS_ERR_SERVICE; break; }
        std::vector<ZtRouteV4> tmp;
        tmp.reserve((size_t)cnt);
        for (int i = 0; i < cnt; ++i) {
            char target[ZTS_IP_MAX_STR_LEN] = {0};
            char via[ZTS_IP_MAX_STR_LEN] = {0};
            uint16_t flags = 0, metric = 0;
            if (zts_core_query_route(net_id, (unsigned)i, target, via, ZTS_IP_MAX_STR_LEN, &flags, &metric) != ZTS_ERR_OK) {
                continue;
            }
            uint32_t net_host = 0; uint8_t pfx = 0;
            if (!parse_cidr(target, net_host, pfx)) {
                // try "a.b.c.d/m" is expected; skip non-IPv4 entries (e.g., IPv6)
                continue;
            }
            ip4_addr_t via4;
            if (!ip4addr_aton(via, &via4)) {
                continue;
            }
            ZtRouteV4 r { net_host, pfx, ip4_to_host(&via4), metric };
            tmp.push_back(r);
        }
        {
            std::lock_guard<std::mutex> lk(g_routes_mu);
            g_routes_v4.swap(tmp);
        }
    } while (0);
    zts_core_lock_release();
    return rc;
}

/* lwIP hook: choose outgoing netif for IPv4 destination */
extern "C" struct netif* zts_lwip_hook_ip4_route(const ip4_addr_t* dest)
{
    if (!dest) return NULL;
    if (g_routes_enabled.load(std::memory_order_relaxed) == 0) {
        return NULL;
    }
    uint32_t d = ip4_to_host(dest);
    // Do not override routing for traffic addressed to ourselves (e.g., L2TP forwarder on ZT_IP)
    if (g_zt_ip_host != 0 && d == g_zt_ip_host) {
        return NULL;
    }
    ZtRouteV4 r{};
    if (!find_lpm(d, r)) {
        return NULL; // let lwIP decide
    }
    if (g_zt_ip_host == 0) {
        return NULL; // ZT netif unknown; do not override
    }
    struct netif* zt = find_netif_by_ip4_host(g_zt_ip_host);
    if (g_pkt_diag.load(std::memory_order_relaxed) != 0) {
        char dstbuf[16];
        ip4_addr_t dst = host_to_ip4(d);
        ip4addr_ntoa_r(&dst, dstbuf, sizeof(dstbuf));
        printf("ROUTE_MATCH dst=%s/%u -> out=ZT netif=%c%c%u\n",
               dstbuf, (unsigned)r.prefix,
               zt ? zt->name[0] : '?', zt ? zt->name[1] : '?', zt ? zt->num : 0);
        fflush(stdout);
    }
    return zt;
}

/* lwIP hook: provide per-destination gateway for ARP on the chosen netif */
extern "C" const ip4_addr_t* zts_lwip_hook_etharp_get_gw(struct netif* out, const ip4_addr_t* dest)
{
    if (!out || !dest) return NULL;
    if (g_routes_enabled.load(std::memory_order_relaxed) == 0) {
        return NULL;
    }
    if (g_zt_ip_host == 0) return NULL;
    struct netif* zt = find_netif_by_ip4_host(g_zt_ip_host);
    if (out != zt) {
        return NULL; // only override for ZT egress
    }
    uint32_t d = ip4_to_host(dest);
    // Do not supply a gateway for traffic addressed to ourselves (on-link local)
    if (d == g_zt_ip_host) {
        return NULL;
    }
    ZtRouteV4 r{};
    if (!find_lpm(d, r)) {
        return NULL;
    }
    g_hook_ret_gw = host_to_ip4(r.via);
    if (g_pkt_diag.load(std::memory_order_relaxed) != 0) {
        char dstbuf[16], viabuf[16];
        ip4_addr_t dst = host_to_ip4(d);
        ip4addr_ntoa_r(&dst, dstbuf, sizeof(dstbuf));
        ip4addr_ntoa_r(&g_hook_ret_gw, viabuf, sizeof(viabuf));
        printf("ROUTE_NH dst=%s via=%s out=ZT netif=%c%c%u\n",
               dstbuf, viabuf, out->name[0], out->name[1], out->num);
        fflush(stdout);
    }
    return &g_hook_ret_gw;
}

/* lwIP hook: called during ip4_forward path to decide whether a packet can be forwarded.
   We use this hook for diagnostics only and do not alter forwarding (return -1). */
extern "C" int zts_lwip_hook_ip4_canforward(struct pbuf* p, u32_t dest_addr_hostorder)
{
    LWIP_UNUSED_ARG(p);
    if (g_pkt_diag.load(std::memory_order_relaxed) == 0) {
        return -1; // no decision, continue normal
    }
    uint32_t d = (uint32_t)dest_addr_hostorder;
    // If forwarding towards ZT per our route table, emit a concise log
    ZtRouteV4 r{};
    if (find_lpm(d, r)) {
        // Try to peek header for proto/src for better context
        if (p && p->tot_len >= 20) {
            uint8_t hdr[20];
            u16_t copied_hdr = pbuf_copy_partial(p, hdr, sizeof(hdr), 0);
            if (copied_hdr >= 20 && (hdr[0] >> 4) == 4) {
                uint8_t proto = hdr[9];
                ip4_addr_t src, dst, via;
                IP4_ADDR(&src, hdr[12], hdr[13], hdr[14], hdr[15]);
                dst = host_to_ip4(d);
                via = host_to_ip4(r.via);
                char srcbuf[16], dstbuf[16], viabuf[16];
                ip4addr_ntoa_r(&src, srcbuf, sizeof(srcbuf));
                ip4addr_ntoa_r(&dst, dstbuf, sizeof(dstbuf));
                ip4addr_ntoa_r(&via, viabuf, sizeof(viabuf));
                printf("ZT_PKT_OUT len=%u proto=%u src=%s dst=%s via=%s\n",
                       (unsigned)p->tot_len, (unsigned)proto, srcbuf, dstbuf, viabuf);
                fflush(stdout);
            }
        } else {
            ip4_addr_t dst = host_to_ip4(d), via = host_to_ip4(r.via);
            char dstbuf[16], viabuf[16];
            ip4addr_ntoa_r(&dst, dstbuf, sizeof(dstbuf));
            ip4addr_ntoa_r(&via, viabuf, sizeof(viabuf));
            printf("ZT_PKT_OUT dst=%s via=%s len=%u\n", dstbuf, viabuf, (unsigned)(p ? p->tot_len : 0));
            fflush(stdout);
        }
    }
    return -1; // keep default behavior
}
