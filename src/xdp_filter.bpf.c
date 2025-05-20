/*
    TCP Filter XDP program

    Drops IPv4 TDP packets sent to port 9211 that are greater than 1kb and less than 16 bytes.
    Has Syn Spam protection
    Ack/Fin/Rst protection for in active connections

    Blocks ip addresses in blocked_ips map that can be updated from cilium (xdp_setup.go)

    USAGE:

        cd ./src
        make
        ./main IP:PORT
        sudo cat /sys/kernel/debug/tracing/trace_pipe

    Note: This pins blocked_ips map could use some kernel memory so after usage should clear it
    `sudo rm /sys/fs/bpf/blocked_ips`
*/

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PORT_TO_FILTER 9211
#define IP_OFFMASK 0x1FFF
#define IP_MF 0x2000

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#else
#error "Endianness detection needs to be set up for your compiler?!"
#endif

#define DEBUG 1

#if DEBUG
#define debug_printf bpf_printk
#else // #if DEBUG
#define debug_printf(...) \
    do                    \
    {                     \
    } while (0)
#endif // #if DEBUG

#define MAX_CPS 100   // Max connections per second (per IP)
#define BLOCK_TIME 10 // Block IP for 10 sec if exceeding rate

const __u8 OPEN = 1 << 0;
const __u8 PRE_HANDSHAKE = 1 << 1;
const __u8 POST_HANDSHAKE = 1 << 2;
const __u8 ACCEPT_ACK_ONLY = 1 << 3;

// BPF map to track SYN rates (per IP)
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);   // Source IP
    __type(value, __u64); // Timestamp of last SYN
} syn_rate SEC(".maps");

// BPF map to track active flows (simplified)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key); // 2-tuple (saddr, sport)
    __type(value, __u8);          // 1 = active flow
} active_flows SEC(".maps");

struct flow_key
{
    __u32 saddr;
    __u16 sport;
};

// BPF map to blocked ips will populate these from go
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);  // saddr
    __type(value, __u8); // 1 = active flow
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;

    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(struct ethhdr) < data_end)
    {
        if (eth->h_proto == __constant_htons(ETH_P_IP)) // IPV4
        {
            struct iphdr *ip = data + sizeof(struct ethhdr);

            if ((void *)ip + sizeof(struct iphdr) < data_end)
            {
                if (ip->protocol == IPPROTO_TCP) // TCP
                {
                    // int data = 1337;
                    // int *ring_buffer = bpf_ringbuf_reserve(&events, sizeof(int), ringbuffer_flags);
                    // if (!ring_buffer)
                    // {
                    //     return XDP_PASS;
                    // }
                    // *ring_buffer = data;
                    // bpf_ringbuf_submit(ring_buffer, ringbuffer_flags);

                    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);

                    if ((void *)tcp + sizeof(struct tcphdr) <= data_end)
                    {

                        // debug_printf("scanning packet id=%u", bpf_ntohs(ip->id));
                        if (tcp->dest == __constant_htons(PORT_TO_FILTER))
                        {
                            // Drop packets from blocked ips

                            __u32 src_ip = ip->saddr;
                            if (bpf_map_lookup_elem(&blocked_ips, &src_ip))
                            {
                                bpf_printk("[%s] Blocked packet_id=%u from %pI4\n", __func__, bpf_ntohs(ip->id), &src_ip);
                                return XDP_DROP;
                            }
                            bpf_printk("[%s] has tcphdr id=%u from %pI4 non-ref:0x%x\n", __func__, bpf_ntohs(ip->id), &src_ip, src_ip);

                            struct flow_key _flow_key = {
                                .saddr = src_ip,
                                .sport = tcp->source,
                            };
                            // --- TCP Flag Handling ---
                            // (1) SYN (new connection)
                            if (tcp->syn && !tcp->ack)
                            {
                                __u64 *last_syn = bpf_map_lookup_elem(&syn_rate, &src_ip);
                                __u64 now = bpf_ktime_get_ns();

                                // Rate limit SYNs
                                if (last_syn)
                                {
                                    __u64 delta = now - *last_syn;
                                    if (delta < (1e9 / MAX_CPS))
                                    { // Too fast? Drop.
                                        bpf_printk("[%s] Rate-limited SYN from %pI4", __func__, &src_ip);
                                        return XDP_DROP;
                                    }
                                }
                                bpf_map_update_elem(&syn_rate, &src_ip, &now, BPF_ANY);
                                // Update flow address 0
                                bpf_map_update_elem(&active_flows, &_flow_key, &PRE_HANDSHAKE, BPF_ANY);
                                // Ignore handshake packet
                                return XDP_PASS;
                            }

                            // (2) Non-SYN (ACK/FIN/RST): Must match an existing flow
                            __u8 *flow_state = bpf_map_lookup_elem(&active_flows, &_flow_key);
                            // Drop if no active flow exists
                            if (!flow_state)
                            {
                                bpf_printk("[%s] Invalid TCP flag (no flow): %pI4:%d -> %pI4:%d", __func__,
                                           &src_ip, bpf_ntohs(tcp->source),
                                           &ip->daddr, bpf_ntohs(tcp->dest));
                                return XDP_DROP;
                            }
                            // For fin graceful closing
                            if (*flow_state == ACCEPT_ACK_ONLY && !tcp->ack)
                            {
                                bpf_map_delete_elem(&active_flows, &_flow_key);
                                return XDP_PASS;
                            }
                            // Skip handshake packets (SYN/SYN-ACK/ACK-only/FIN)
                            if (*flow_state == PRE_HANDSHAKE)
                            {
                                if (tcp->ack && tcp->psh == 0 && tcp->fin == 0 && tcp->rst == 0)
                                {
                                    bpf_map_update_elem(&active_flows, &_flow_key, &POST_HANDSHAKE, BPF_EXIST);
                                    return XDP_PASS;
                                }
                                return XDP_DROP;
                            }

                            // Drop packets that are too large to be valid

                            short frag_off_val = bpf_ntohs(ip->frag_off);
                            short earlier_packet_size = (frag_off_val & IP_OFFMASK) * 8;
                            short is_fragment = (frag_off_val & IP_MF) || earlier_packet_size;

                            int fragment_bytes = data_end - (void *)tcp;                                    // if is_fragment has no tcphr
                            int packet_size = earlier_packet_size + fragment_bytes - sizeof(struct tcphdr); // the first fragment has tcphr
                                                                                                            // debugging
                            debug_printf("[%s] data=%lx, data_end=%lx, tcp=%lx", __func__, (unsigned long)data, (unsigned long)data_end, (unsigned long)tcp);
                            // debugging
                            debug_printf("[%s] id=%u, earlier_packet_size=%u, packet_size=%u", __func__,
                                         bpf_ntohs(ip->id), (unsigned int)earlier_packet_size, packet_size);

                            //  Remove fragments but this will miss tcp segments
                            if (is_fragment)
                            {
                                debug_printf("[%s] got a fragment packet id=%u", __func__, ip->id);
                                return XDP_DROP;
                            }

                            // Max packet payload size 1kb (drop rest)
                            // This is not that much better around small packets in between
                            if (packet_size > 1100)
                            {
                                debug_printf("[%s] packet is too large %u", __func__, packet_size);
                                return XDP_DROP;
                            }

                            // End Conn Packets sent by client
                            // Track dropped connections and just remove them from active flows
                            if (tcp->fin || tcp->rst)
                            {
                                bpf_printk("[%s] Connection dropped for : %pI4:%d", __func__, &ip->daddr, bpf_ntohs(tcp->dest));
                                if (tcp->rst)
                                    bpf_map_delete_elem(&active_flows, &_flow_key);
                                else
                                    bpf_map_update_elem(&active_flows, &_flow_key, &ACCEPT_ACK_ONLY, BPF_EXIST);
                                return XDP_PASS;
                            }

                            // Drop Non-Ack packets that are too small to be valid
                            if (!tcp->ack)
                            {
                                __u8 *packet_data = (void *)tcp + sizeof(struct tcphdr);
                                if ((void *)packet_data + 16 > data_end)
                                {
                                    debug_printf("[%s] packet is too small id=%u", __func__, ip->id);
                                    return XDP_DROP;
                                }
                            }
                            debug_printf("[%s] basic packet filter passed", __func__);

                            return XDP_PASS;
                        }
                    }
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";