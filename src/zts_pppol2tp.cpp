/*
 * zts_pppol2tp.cpp
 *
 * Purpose:
 *   Provide a minimal C API entrypoint to bootstrap an L2TPv2 (PPPoL2TP) client
 *   inside libzt's embedded lwIP instance to support the "in-process UDP bridge"
 *   design agreed with the application.
 *
 * Overview:
 *   - PPPoL2TP (client/LAC) is created using lwIP's PPP API and configured to
 *     transmit its UDP datagrams to a given ZeroTier IPv4 address + fixed forwarder port.
 *   - The application must run a user-space UDP bridge:
 *       libzt UDP (ZT_IP:L2TP_FWD_PORT) <--> host UDP (MikroTik_IP:1701)
 *   - On PPP link up, we optionally set the PPP netif as the default route so lwIP
 *     forwards non-local traffic via PPP (which will be bridged to MikroTik).
 *
 * Forward-compatibility:
 *   This API is transport-neutral and assumes lwIP UDP. If later we add a host-UDP
 *   transport into PPPoL2TP (patching lwIP to use POSIX UDP), this function can
 *   internally switch to that transport without changing its signature.
 *
 * Notes:
 *   - IPv4-only. (PPPoL2TP in lwIP supports IPv4; IPv6 would require enabling PPP_IPV6_SUPPORT.)
 *   - Authentication (PAP/CHAP/MSCHAPv2) is enabled via lwipopts.h and set at runtime here.
 *   - Minimal memory pools for one PPP session are enabled in lwipopts.h; adjust if needed.
 */

#include "ZeroTierSockets.h" // for ZTS_API / ZTCALL visibility
#include <sys/types.h> // for u_char on POSIX (needed by ppp_set_auth)

extern "C" {
#include "lwip/opt.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "netif/ppp/pppapi.h"
#include "netif/ppp/ppp.h"
#include "netif/ppp/pppol2tp.h"
}

#include <cstring>
#include <string>

/* Static PPP context
 * We keep the PPP netif and pcb static to ensure lifetime >= process and to
 * avoid allocating from application code. Only a single PPP session is needed. */
static struct netif g_ppp_netif;
static ppp_pcb* g_ppp_pcb = nullptr;
static int g_set_default_route = 0;

/* Simple link status callback
 * On PPPERR_NONE (link up), optionally set PPP as lwIP default route.
 * This ensures that non-local IPv4 traffic is forwarded towards PPP. */
static void ppp_link_status_cb(ppp_pcb* pcb, int err_code, void* ctx)
{
    (void)pcb;
    (void)ctx;
    switch (err_code) {
        case PPPERR_NONE:
            /* Link is up, set default route if requested */
            if (g_set_default_route) {
                netif_set_default(&g_ppp_netif);
            }
            break;
        default:
            /* Other states (down, auth failed, etc.) are intentionally left as no-ops here.
             * The application can observe behavior via logs on the app side. */
            break;
    }
}

/* Helper: locate the ZT netif by matching the provided IPv4 string
 * Rationale:
 *   PPPoL2TP needs an 'underlay' netif for its UDP transport. We want the ZT
 *   netif owning zt_bind_ip so PPP UDP is sent via ZeroTier's lwIP netif. */
static struct netif* find_zt_netif_by_ip4(const char* ip4_str)
{
    if (!ip4_str || !*ip4_str) {
        return nullptr;
    }
    ip4_addr_t target_addr{};
    if (!ip4addr_aton(ip4_str, &target_addr)) {
        return nullptr;
    }

    /* Iterate lwIP's global netif list and find the one with this IPv4 */
    for (struct netif* n = netif_list; n != nullptr; n = n->next) {
#if LWIP_IPV4
        const ip4_addr_t* n_ip4 = netif_ip4_addr(n);
        if (n_ip4 && ip4_addr_cmp(n_ip4, &target_addr)) {
            return n;
        }
#endif
    }
    /* Fallback: if nothing matched, try netif_default (commonly the ZT netif) */
    return netif_default;
}

/* Public C API: Start PPPoL2TP over lwIP UDP targeting ZT_IP:L2TP_FWD_PORT
 * See ZeroTierSockets.h for detailed documentation and intent. */
extern "C" ZTS_API int ZTCALL zts_pppol2tp_start_bridge(const char* zt_bind_ip,
                                                        unsigned short zt_forward_port,
                                                        const char* ppp_user,
                                                        const char* ppp_pass,
                                                        const char* l2tp_secret,
                                                        int set_default_route)
{
#if !LWIP_IPV4 || !PPP_SUPPORT || !PPPOL2TP_SUPPORT
    (void)zt_bind_ip; (void)zt_forward_port; (void)ppp_user; (void)ppp_pass; (void)l2tp_secret; (void)set_default_route;
    return ZTS_ERR_SERVICE;
#else
    if (!zt_bind_ip || !*zt_bind_ip) {
        return ZTS_ERR_ARG;
    }
    /* Underlay netif to carry the UDP L2TP transport (the ZeroTier netif). */
    struct netif* zt_netif = find_zt_netif_by_ip4(zt_bind_ip);
    if (!zt_netif) {
        return ZTS_ERR_SERVICE;
    }

    /* Parse remote ip/port (PPPoL2TP UDP peer) = our own ZT IPv4 with fixed forwarder port */
    ip_addr_t remote_ip{};
    ip4_addr_t remote_ip4{};
    if (!ip4addr_aton(zt_bind_ip, &remote_ip4)) {
        return ZTS_ERR_ARG;
    }
    ip_addr_copy_from_ip4(remote_ip, remote_ip4);
    const u16_t remote_port = (u16_t)zt_forward_port;

    g_set_default_route = set_default_route ? 1 : 0;

    /* Create PPP over L2TP session.
     * - pppif: PPP netif holder. We keep it static/global for lifetime reasons.
     * - netif: the 'underlay' interface (ZeroTier lwIP netif)
     * - ipaddr/port: L2TP tunnel peer (ZT_IP:forward_port)
     * - secret: L2TP control secret (optional; may be NULL/0) */
    const u8_t* secret_ptr = (const u8_t*)l2tp_secret;
    u8_t secret_len = (u8_t)((l2tp_secret && *l2tp_secret) ? (u8_t)strlen(l2tp_secret) : 0);

    g_ppp_pcb = pppapi_pppol2tp_create(&g_ppp_netif,
                                       zt_netif,
                                       (ip_addr_t*)&remote_ip,
                                       remote_port,
                                       secret_ptr,
                                       secret_len,
                                       ppp_link_status_cb,
                                       nullptr);
    if (!g_ppp_pcb) {
        return ZTS_ERR_SERVICE;
    }

    /* Configure PPP auth (PAP/CHAP/MSCHAPv2). lwIP implements multiple auth types. */
    if (ppp_user && ppp_pass) {
        u8_t auth_types = PPPAUTHTYPE_PAP | PPPAUTHTYPE_CHAP | PPPAUTHTYPE_MSCHAP_V2;
        /* lwIP ppp_set_auth expects const char* for user/pass */
        ppp_set_auth(g_ppp_pcb, auth_types, ppp_user, ppp_pass);
    }

    /* Initiate the PPP session. */
    err_t e = pppapi_connect(g_ppp_pcb, 0);
    if (e != ERR_OK) {
        return ZTS_ERR_SERVICE;
    }
    return ZTS_ERR_OK;
#endif
}
