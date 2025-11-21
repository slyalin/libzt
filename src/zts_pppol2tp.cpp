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

/* Diagnostics: on-demand dump of netif inventory (declared in zts_hooks.cpp) */
extern "C" int zts_diag_dump_netifs(const char* tag);

#include <cstring>
#include <string>
#include <cstdlib>
#include <atomic>
#include <chrono>

#ifndef PPPERR_CONNECT_TIMEOUT
#ifdef PPPERR_CONNECTTIME
#define PPPERR_CONNECT_TIMEOUT PPPERR_CONNECTTIME
#endif
#endif

/* Static PPP context
 * We keep the PPP netif and pcb static to ensure lifetime >= process and to
 * avoid allocating from application code. Only a single PPP session is needed. */
static struct netif g_ppp_netif;
static ppp_pcb* g_ppp_pcb = nullptr;
static int g_set_default_route = 0;
/* Keep stable copies of credentials for PPP lifetime */
static std::string g_auth_user;
static std::string g_auth_pass;
/* Legacy fixed reconnect knob retained for compatibility but superseded by backoff */
static int g_reconnect_secs = 10;
static std::atomic<int> g_force_reconnect_on_user{0};
/* Backoff and dampening parameters */
static int g_reconnect_min_secs = 5;
static int g_reconnect_max_secs = 120;
static double g_backoff_factor = 2.0;
static int g_current_backoff = 5;
static int g_min_uptime_secs = 60;
static std::chrono::steady_clock::time_point g_up_since{};
/* LCP echo settings */
static int g_lcp_echo_secs = 30;
static int g_lcp_echo_fails = 3;

/* Diagnostics helpers */
static const char* ppp_err_str(int err_code)
{
    switch (err_code) {
        case PPPERR_NONE: return "NONE";
#ifdef PPPERR_PARAM
        case PPPERR_PARAM: return "PARAM";
#endif
#ifdef PPPERR_OPEN
        case PPPERR_OPEN: return "OPEN";
#endif
#ifdef PPPERR_DEVICE
        case PPPERR_DEVICE: return "DEVICE";
#endif
#ifdef PPPERR_ALLOC
        case PPPERR_ALLOC: return "ALLOC";
#endif
#ifdef PPPERR_USER
        case PPPERR_USER: return "USER";
#endif
#ifdef PPPERR_CONNECT
        case PPPERR_CONNECT: return "CONNECT";
#endif
#ifdef PPPERR_AUTHFAIL
        case PPPERR_AUTHFAIL: return "AUTHFAIL";
#endif
#ifdef PPPERR_PROTOCOL
        case PPPERR_PROTOCOL: return "PROTOCOL";
#endif
#ifdef PPPERR_PEERDEAD
        case PPPERR_PEERDEAD: return "PEERDEAD";
#endif
#ifdef PPPERR_IDLETIMEOUT
        case PPPERR_IDLETIMEOUT: return "IDLETIMEOUT";
#endif
#ifdef PPPERR_CONNECT_TIMEOUT
        case PPPERR_CONNECT_TIMEOUT: return "CONNECT_TIMEOUT";
#endif
#ifdef PPPERR_LOOPBACK
        case PPPERR_LOOPBACK: return "LOOPBACK";
#endif
        default: return "UNKNOWN";
    }
}

/* Netif status callback to observe IPCP assignment */
static void ppp_netif_status_cb(struct netif* n)
{
#if LWIP_IPV4
    const ip4_addr_t* ip = netif_ip4_addr(n);
    const ip4_addr_t* mask = netif_ip4_netmask(n);
    const ip4_addr_t* gw = netif_ip4_gw(n);
    printf("PPPoL2TP: netif status %c%c%u ip=%s mask=%s gw=%s\n",
           n->name[0], n->name[1], n->num,
           ip ? ip4addr_ntoa(ip) : "0.0.0.0",
           mask ? ip4addr_ntoa(mask) : "0.0.0.0",
           gw ? ip4addr_ntoa(gw) : "0.0.0.0");
    printf("PPPoL2TP: netif %c%c%u flags=0x%02x mtu=%u\n",
           n->name[0], n->name[1], n->num, (unsigned)n->flags, (unsigned)n->mtu);
#else
    printf("PPPoL2TP: netif status %c%c%u (IPv4 disabled)\n", n->name[0], n->name[1], n->num);
#endif
}

/* Human-readable PPP phase name */
static const char* ppp_phase_name(u8_t phase)
{
    switch (phase) {
#ifdef PPP_PHASE_DEAD
        case PPP_PHASE_DEAD: return "DEAD";
#endif
#ifdef PPP_PHASE_INITIALIZE
        case PPP_PHASE_INITIALIZE: return "INITIALIZE";
#endif
#ifdef PPP_PHASE_ESTABLISH
        case PPP_PHASE_ESTABLISH: return "ESTABLISH";
#endif
#ifdef PPP_PHASE_AUTHENTICATE
        case PPP_PHASE_AUTHENTICATE: return "AUTHENTICATE";
#endif
#ifdef PPP_PHASE_CALLBACK
        case PPP_PHASE_CALLBACK: return "CALLBACK";
#endif
#ifdef PPP_PHASE_NETWORK
        case PPP_PHASE_NETWORK: return "NETWORK";
#endif
#ifdef PPP_PHASE_RUNNING
        case PPP_PHASE_RUNNING: return "RUNNING";
#endif
#ifdef PPP_PHASE_TERMINATE
        case PPP_PHASE_TERMINATE: return "TERMINATE";
#endif
#ifdef PPP_PHASE_HOLDOFF
        case PPP_PHASE_HOLDOFF: return "HOLDOFF";
#endif
        default: return "UNKNOWN";
    }
}

/* PPP phase change callback for diagnostics */
static void ppp_phase_cb(ppp_pcb* pcb, u8_t phase, void* ctx)
{
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(ctx);
    printf("PPPoL2TP: phase change %u (%s)\n", (unsigned)phase, ppp_phase_name(phase));
#ifdef PPP_PHASE_RUNNING
    if (phase == PPP_PHASE_RUNNING) {
        /* Dump netifs after PPP is fully up to observe post-PPPoL2TP state */
        zts_diag_dump_netifs("NETIF_INVENTORY_PPP_RUNNING");
    }
#endif
}

/* Simple link status callback
 * On PPPERR_NONE (link up), optionally set PPP as lwIP default route.
 * This ensures that non-local IPv4 traffic is forwarded towards PPP. */
static void ppp_link_status_cb(ppp_pcb* pcb, int err_code, void* ctx)
{
    (void)pcb;
    (void)ctx;
    printf("PPPoL2TP: link status change err=%d (%s)\n", err_code, ppp_err_str(err_code));
    switch (err_code) {
        case PPPERR_NONE:
            printf("PPPoL2TP: link up\n");
#if LWIP_IPV4
            {
                const ip4_addr_t* a = netif_ip4_addr(&g_ppp_netif);
                if (a) {
                    printf("PPPoL2TP: IPCP IPv4 %s\n", ip4addr_ntoa(a));
                }
            }
#endif
            /* Link is up, set default route if requested */
            if (g_set_default_route) {
                netif_set_default(&g_ppp_netif);
                printf("PPPoL2TP: default route set to PPP\n");
                /* Snapshot netifs immediately after making PPP default */
                zts_diag_dump_netifs("NETIF_INVENTORY_AFTER_PPP_LINKUP");
            }
            break;
        case PPPERR_AUTHFAIL:
            printf("PPPoL2TP: authentication failed\n");
            break;
        case PPPERR_OPEN:
            printf("PPPoL2TP: open failed\n");
            break;
        case PPPERR_CONNECT:
            printf("PPPoL2TP: connection failed\n");
            break;
        case PPPERR_PROTOCOL:
            printf("PPPoL2TP: protocol error (LCP/IPCP)\n");
            break;
        case PPPERR_CONNECT_TIMEOUT:
            printf("PPPoL2TP: connect timeout\n");
            break;
        case PPPERR_USER:
            printf("PPPoL2TP: terminated by user\n");
            break;
        default:
            /* Other states (down, etc.) */
            printf("PPPoL2TP: link status change err=%d\n", err_code);
            break;
    }
    /* Track stable uptime for dampening/backoff reset */
    if (err_code == PPPERR_NONE) {
        auto now = std::chrono::steady_clock::now();
        if (g_up_since.time_since_epoch().count() == 0) {
            g_up_since = now;
        } else {
            auto up_s = std::chrono::duration_cast<std::chrono::seconds>(now - g_up_since).count();
            if (up_s >= g_min_uptime_secs) {
                if (g_current_backoff != g_reconnect_min_secs) {
                    printf("PPPoL2TP: stable uptime >= %d sec, reset backoff to %d sec\n",
                           g_min_uptime_secs, g_reconnect_min_secs);
                }
                g_current_backoff = g_reconnect_min_secs;
                g_up_since = now; /* keep clock fresh */
            }
        }
    }

    /* Intentional close via watchdog: reconnect too (use min delay) */
    if (err_code == PPPERR_USER && g_force_reconnect_on_user.load()) {
        int delay = g_reconnect_min_secs;
        printf("PPPoL2TP: USER close (watchdog), scheduling reconnect in %d sec\n", delay);
        g_force_reconnect_on_user.store(0);
        if (g_ppp_pcb) {
            ppp_connect(g_ppp_pcb, (u16_t)delay);
        }
    }

    /* Auto-reconnect on any error except explicit user termination, with backoff+jitter */
    if (err_code != PPPERR_NONE && err_code != PPPERR_USER) {
        int base = (g_current_backoff > 0) ? g_current_backoff : g_reconnect_min_secs;
        int jitter = (base + 9) / 10; /* ~10% */
        int delay = base;
        if ((rand() & 1) != 0) {
            delay = base + jitter;
        } else {
            delay = base - jitter;
        }
        if (delay < g_reconnect_min_secs) delay = g_reconnect_min_secs;
        if (delay > g_reconnect_max_secs) delay = g_reconnect_max_secs;

        printf("PPPoL2TP: scheduling reconnect in %d sec (err=%d (%s), backoff=%d, factor=%.2f, limits=[%d,%d])\n",
               delay, err_code, ppp_err_str(err_code), base, g_backoff_factor, g_reconnect_min_secs, g_reconnect_max_secs);

        if (g_ppp_pcb) {
            /* We are in tcpip_thread context; ppp_connect() is safe here */
            ppp_connect(g_ppp_pcb, (u16_t)delay);
        }

        /* Increase backoff for next time, clamp to max */
        int next_backoff = (int)(base * g_backoff_factor);
        if (next_backoff < g_reconnect_min_secs) next_backoff = g_reconnect_min_secs;
        if (next_backoff > g_reconnect_max_secs) next_backoff = g_reconnect_max_secs;
        g_current_backoff = next_backoff;

        /* Reset uptime clock on failure */
        g_up_since = std::chrono::steady_clock::now();
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
        printf("PPPoL2TP: ZT netif not found for %s\n", zt_bind_ip);
        return ZTS_ERR_SERVICE;
    }

    /* Parse remote ip/port (PPPoL2TP UDP peer) = our own ZT IPv4 with fixed forwarder port */
    ip_addr_t remote_ip{};
    ip4_addr_t remote_ip4{};
    if (!ip4addr_aton(zt_bind_ip, &remote_ip4)) {
        return ZTS_ERR_ARG;
    }
    ip_addr_copy_from_ip4(remote_ip, remote_ip4);
    printf("PPPoL2TP: create: zt=%s:%u default_route=%d user=%s secret=%s\n",
           zt_bind_ip, (unsigned)zt_forward_port, set_default_route,
           (ppp_user && *ppp_user) ? "<set>" : "<none>",
           (l2tp_secret && *l2tp_secret) ? "<set>" : "<none>");
    const u16_t remote_port = (u16_t)zt_forward_port;

    g_set_default_route = set_default_route ? 1 : 0;
    /* Configure LCP echo and backoff from env (with sane defaults) */
    {
        const char* es = std::getenv("L2TP_LCP_ECHO_SECS");
        const char* ef = std::getenv("L2TP_LCP_ECHO_FAILS");
        g_lcp_echo_secs = (es && *es) ? std::max(0, atoi(es)) : 30;
        g_lcp_echo_fails = (ef && *ef) ? std::max(0, atoi(ef)) : 3;
        printf("PPPoL2TP: LCP echo interval %d sec, fails %d\n", g_lcp_echo_secs, g_lcp_echo_fails);
    }
    {
        const char* vmin = std::getenv("L2TP_RECONNECT_MIN_SECS");
        const char* vmax = std::getenv("L2TP_RECONNECT_MAX_SECS");
        const char* vbf  = std::getenv("L2TP_RECONNECT_BACKOFF");
        const char* vupt = std::getenv("L2TP_MIN_UPTIME_SECS");
        g_reconnect_min_secs = (vmin && *vmin) ? std::max(1, atoi(vmin)) : 5;
        g_reconnect_max_secs = (vmax && *vmax) ? std::max(g_reconnect_min_secs, atoi(vmax)) : 120;
        g_backoff_factor = (vbf && *vbf) ? std::max(1.0, atof(vbf)) : 2.0;
        g_min_uptime_secs = (vupt && *vupt) ? std::max(1, atoi(vupt)) : 60;
        g_current_backoff = g_reconnect_min_secs;
        printf("PPPoL2TP: reconnect backoff min=%d max=%d factor=%.2f min_uptime=%d\n",
               g_reconnect_min_secs, g_reconnect_max_secs, g_backoff_factor, g_min_uptime_secs);
    }

    /* Create PPP over L2TP session.
     * - pppif: PPP netif holder. We keep it static/global for lifetime reasons.
     * - netif: the 'underlay' interface (ZeroTier lwIP netif)
     * - ipaddr/port: L2TP tunnel peer (ZT_IP:forward_port)
     * - secret: L2TP control secret (optional; may be NULL/0) */
    const u8_t* secret_ptr = (const u8_t*)l2tp_secret;
    u8_t secret_len = (u8_t)((l2tp_secret && *l2tp_secret) ? (u8_t)strlen(l2tp_secret) : 0);
    if (secret_len == 0) {
        secret_ptr = nullptr;
    }

    g_ppp_pcb = pppapi_pppol2tp_create(&g_ppp_netif,
                                       zt_netif,
                                       &remote_ip,
                                       remote_port,
                                       secret_ptr,
                                       secret_len,
                                       ppp_link_status_cb,
                                       nullptr);
    if (!g_ppp_pcb) {
        return ZTS_ERR_SERVICE;
    }
    {
        char n0 = g_ppp_netif.name[0], n1 = g_ppp_netif.name[1];
        char u0 = zt_netif->name[0], u1 = zt_netif->name[1];
        printf("PPPoL2TP: created pcb=%p ppp_netif=%c%c%u underlay=%c%c%u\n",
               (void*)g_ppp_pcb, n0, n1, g_ppp_netif.num, u0, u1, zt_netif->num);
        printf("PPPoL2TP: underlay if=%c%c%u flags=0x%02x mtu=%u\n",
               u0, u1, zt_netif->num, (unsigned)zt_netif->flags, (unsigned)zt_netif->mtu);
        printf("PPPoL2TP: ppp_netif if=%c%c%u flags=0x%02x mtu=%u\n",
               n0, n1, g_ppp_netif.num, (unsigned)g_ppp_netif.flags, (unsigned)g_ppp_netif.mtu);
    }

/* Apply LCP echo settings (runtime), if supported by build */
    {
        /* pcb->settings fields exist per lwIP ppp.h; set them directly */
        if (g_lcp_echo_secs < 0) g_lcp_echo_secs = 0;
        if (g_lcp_echo_secs > 255) g_lcp_echo_secs = 255;
        if (g_lcp_echo_fails < 0) g_lcp_echo_fails = 0;
        if (g_lcp_echo_fails > 255) g_lcp_echo_fails = 255;
        g_ppp_pcb->settings.lcp_echo_interval = (u8_t)g_lcp_echo_secs;
        g_ppp_pcb->settings.lcp_echo_fails = (u8_t)g_lcp_echo_fails;
        printf("PPPoL2TP: applied LCP echo settings (interval=%u, fails=%u)\n",
               (unsigned)g_ppp_pcb->settings.lcp_echo_interval,
               (unsigned)g_ppp_pcb->settings.lcp_echo_fails);
    }

/* Enable PPP phase notifications for visibility into the handshake */
    ppp_set_notify_phase_callback(g_ppp_pcb, ppp_phase_cb);
    /* Observe PPP netif status changes (IPCP up/down) */
#if defined(LWIP_NETIF_STATUS_CALLBACK) && (LWIP_NETIF_STATUS_CALLBACK)
    netif_set_status_callback(&g_ppp_netif, ppp_netif_status_cb);
#else
    /* LWIP_NETIF_STATUS_CALLBACK disabled in this build; skipping netif status callback */
#endif

    /* Configure PPP auth: allow PAP/CHAP/MSCHAPv2 (will negotiate to peer's choice) or honor L2TP_AUTH env. */
    if (ppp_user && ppp_pass) {
        u8_t auth_types = PPPAUTHTYPE_PAP | PPPAUTHTYPE_CHAP | PPPAUTHTYPE_MSCHAP_V2;
        const char* auth_env = std::getenv("L2TP_AUTH");
        if (auth_env && *auth_env) {
            if (strcasecmp(auth_env, "pap") == 0) {
                auth_types = PPPAUTHTYPE_PAP;
                printf("PPPoL2TP: L2TP_AUTH=pap (forcing PAP)\n");
            } else if (strcasecmp(auth_env, "chap") == 0) {
                auth_types = PPPAUTHTYPE_CHAP;
                printf("PPPoL2TP: L2TP_AUTH=chap (forcing CHAP-MD5)\n");
            } else if (strcasecmp(auth_env, "mschapv2") == 0 || strcasecmp(auth_env, "mschap2") == 0) {
                auth_types = PPPAUTHTYPE_MSCHAP_V2;
                printf("PPPoL2TP: L2TP_AUTH=mschapv2 (forcing CHAP-MSCHAPv2)\n");
            } else if (strcasecmp(auth_env, "any") == 0) {
                auth_types = PPPAUTHTYPE_PAP | PPPAUTHTYPE_CHAP | PPPAUTHTYPE_MSCHAP_V2;
                printf("PPPoL2TP: L2TP_AUTH=any (PAP|CHAP|MSCHAPv2)\n");
            } else {
                printf("PPPoL2TP: L2TP_AUTH unrecognized (%s), using default (PAP|CHAP|MSCHAPv2)\n", auth_env);
            }
        }
        /* Make stable copies to ensure lifetime and avoid accidental corruption */
        g_auth_user = ppp_user;
        g_auth_pass = ppp_pass;
        /* lwIP stores pointers; pass our stable buffers */
        ppp_set_auth(g_ppp_pcb, auth_types, g_auth_user.c_str(), g_auth_pass.c_str());
        printf("PPPoL2TP: auth set for user=%s types=0x%02x\n", g_auth_user.empty() ? "<null>" : g_auth_user.c_str(), (unsigned)auth_types);
    }

    /* Conservative LCP options to reduce negotiation mismatches */
    ppp_set_neg_pcomp(g_ppp_pcb, 0);      /* Disable Protocol Field Compression */
    ppp_set_neg_accomp(g_ppp_pcb, 0);     /* Disable Address/Control Compression */
    ppp_set_neg_asyncmap(g_ppp_pcb, 1);   /* Negotiate ACCM */
    ppp_set_asyncmap(g_ppp_pcb, 0);       /* Request ACCM = 0 for L2TP */

    /* Actively initiate LCP (peer may also speak first) */
    ppp_set_listen_time(g_ppp_pcb, 0);
    ppp_set_passive(g_ppp_pcb, 0);
    ppp_set_silent(g_ppp_pcb, 0);

    /* Initiate the PPP session. */
    err_t e = pppapi_connect(g_ppp_pcb, 0);
    if (e != ERR_OK) {
        printf("PPPoL2TP: pppapi_connect failed err=%d\n", (int)e);
        return ZTS_ERR_SERVICE;
    }
    printf("PPPoL2TP: pppapi_connect initiated\n");
    return ZTS_ERR_OK;
#endif
}

/* Public C API: nudge close + reconnect */
extern "C" ZTS_API int ZTCALL zts_pppol2tp_nudge_close_reconnect(void)
{
#if !LWIP_IPV4 || !PPP_SUPPORT || !PPPOL2TP_SUPPORT
    return ZTS_ERR_SERVICE;
#else
    if (!g_ppp_pcb) {
        return ZTS_ERR_SERVICE;
    }
    g_force_reconnect_on_user.store(1);
    err_t e = pppapi_close(g_ppp_pcb, 1 /* nocarrier */);
    if (e != ERR_OK) {
        g_force_reconnect_on_user.store(0);
        printf("PPPoL2TP: pppapi_close failed err=%d\n", (int)e);
        return ZTS_ERR_SERVICE;
    }
    printf("PPPoL2TP: nudge close requested (nocarrier); will reconnect in %d sec\n", g_reconnect_secs);
    return ZTS_ERR_OK;
#endif
}
