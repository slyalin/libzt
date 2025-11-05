/*
 * libzt IPv4 input hook and public filter setter
 *
 * This file wires lwIP's LWIP_HOOK_IP4_INPUT to a user-provided callback
 * set via zts_set_ip4_input_filter(). If the callback returns nonzero,
 * the pbuf is consumed and not passed to lwIP.
 */

#include "ZeroTierSockets.h"

extern "C" {
#include "lwip/pbuf.h"
#include "lwip/netif.h"
}

static zts_ip4_filter_cb g_ip4_filter_cb = nullptr;

extern "C" ZTS_API int ZTCALL zts_set_ip4_input_filter(zts_ip4_filter_cb cb)
{
    g_ip4_filter_cb = cb;
    return ZTS_ERR_OK;
}

extern "C" int zts_lwip_hook_ip4_input(struct pbuf* p, struct netif* input_netif)
{
    (void)input_netif;
    if (!p || !g_ip4_filter_cb) {
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
