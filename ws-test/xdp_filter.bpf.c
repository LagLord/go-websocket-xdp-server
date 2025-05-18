/*
    UDP drop XDP program

    Drops IPv4 UDP packets sent to port 40000 that don't match a simple pattern.

    USAGE:

        clang -Ilibbpf/src -g -O2 -target bpf -c xdp_filter.c -o xdp_filter.o
        sudo cat /sys/kernel/debug/tracing/trace_pipe
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

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
long ringbuffer_flags = 0;

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

                    debug_printf("scanning packet id=%u", bpf_ntohs(ip->id));
                    if ((void *)tcp + sizeof(struct tcphdr) <= data_end)
                    {

                        if (tcp->dest == __constant_htons(PORT_TO_FILTER))
                        {
                            debug_printf("has tcphdr id=%u", bpf_ntohs(ip->id));
                            // Skip handshake packets (SYN/SYN-ACK/ACK-only)
                            if (tcp->syn || (tcp->ack && tcp->psh == 0 && tcp->fin == 0 && tcp->rst == 0))
                            {
                                return XDP_PASS; // Ignore handshake packets
                            }

                            // Drop packets that are too large to be valid

                            short frag_off_val = bpf_ntohs(ip->frag_off);
                            short earlier_packet_size = (frag_off_val & IP_OFFMASK) * 8;
                            short is_fragment = (frag_off_val & IP_MF) || earlier_packet_size;

                            int fragment_bytes = data_end - (void *)tcp;                                    // if is_fragment has no tcphr
                            int packet_size = earlier_packet_size + fragment_bytes - sizeof(struct tcphdr); // the first fragment has tcphr
                                                                                                            // debugging
                            debug_printf("data=%lx, data_end=%lx, tcp=%lx", (unsigned long)data, (unsigned long)data_end, (unsigned long)tcp);
                            // debugging
                            debug_printf("id=%u, earlier_packet_size=%u, packet_size=%u",
                                         bpf_ntohs(ip->id), (unsigned int)earlier_packet_size, packet_size);

                            if (is_fragment)
                            {
                                debug_printf("got a fragment packet id=%u", ip->id);
                            }

                            // Drop packets that are too small to be valid

                            __u8 *packet_data = (void *)tcp + sizeof(struct tcphdr);
                            if ((void *)packet_data + 16 > data_end)
                            {
                                debug_printf("packet is too small id=%u", ip->id);
                                return XDP_DROP;
                            }
                            // Max packet payload size 8kb (drop rest fragments)
                            // This is not that much better around <8kb of fragments could fill up the fragment queue before timing out
                            if (packet_size > __constant_htons(1 << 13))
                            {
                                debug_printf("packet is too large %u", packet_size);
                                return XDP_DROP;
                            }
                            debug_printf("basic packet filter passed");

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