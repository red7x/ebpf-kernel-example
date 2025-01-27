#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct
{
    // __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    // __uint(key_size, sizeof(__u32));
    // __uint(value_size, sizeof(__u32));
    // __uint(max_entries, 4); // number of CPUs
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} packet_info_map SEC(".maps");

struct packet_info
{
    __u32 src_ip;
    __u32 dst_ip;
    __u8 protocol;
};

struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#define LLC_SAP_SNAP 0xAA

struct llc_snap_hdr
{
    /* RFC 1483 LLC/SNAP encapsulation for routed IP PDUs */
    __u8 dsap;        /* Destination Service Access Point (0xAA)     */
    __u8 ssap;        /* Source Service Access Point      (0xAA)     */
    __u8 ctrl;        /* Unnumbered Information           (0x03)     */
    __u8 org[3];      /* Organizational identification    (0x000000) */
    __be16 ethertype; /* Ether type (for IP)              (0x0800)   */
};

SEC("xdp")
int xdp_ipv4_packets(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }
    data += sizeof(*eth);

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    // VLAN
    if (h_proto == ETH_P_8021Q)
    {
        struct vlan_hdr *vlan = data;
        if (data + sizeof(*vlan) > data_end)
        {
            return XDP_PASS;
        }
        data += sizeof(*vlan);
        h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    }

    if (h_proto <= 0x05DC) // IEEE802.3
    {
        struct llc_snap_hdr *llc = data;
        if (data + sizeof(*llc) > data_end)
        {
            return XDP_PASS;
        }
        data += sizeof(*llc);
        if (
            llc->dsap != LLC_SAP_SNAP ||
            llc->ssap != LLC_SAP_SNAP ||
            (llc->org[0] | llc->org[1] | llc->org[2] != 0))
        {
            return XDP_PASS;
        }
        h_proto = bpf_ntohs(llc->ethertype);
    }

    if (h_proto != ETH_P_IP)
    {
        return XDP_PASS;
    }

    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end)
    {
        return XDP_PASS;
    }

    struct packet_info info =
        {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .protocol = ip->protocol,
        };

    bpf_ringbuf_output(&packet_info_map, &info, sizeof(info), 0);
    // bpf_perf_event_output(ctx, &packet_info_map, BPF_F_CURRENT_CPU, &info, sizeof(info));

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";