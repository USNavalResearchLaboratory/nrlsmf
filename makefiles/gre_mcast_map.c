/* clang -O2 -g -target bpf -c gre_mcast_map.c -o gre_mcast_map.o */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
/*#include <linux/if_ether.h>*/
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("classifier")
int gre_mcast_map(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    bpf_printk("gre_mcast_map hit 1\n");
    
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

     bpf_printk("gre_mcast_map hit 2\n");
     
    if (ip->version != 4)
        return TC_ACT_OK;
    
     bpf_printk("gre_mcast_map hit 3\n");

    // 224/4 multicast
    if ((ip->daddr & __builtin_bswap32(0xF0000000)) != __builtin_bswap32(0xE0000000))
        return TC_ACT_OK;
    
     bpf_printk("gre_mcast_map hit 4\n");

    struct bpf_tunnel_key key = {};
    int len = sizeof(key);

    // If a key already exists, preserve it (best-effort)
    int g = bpf_skb_get_tunnel_key(skb, &key, len, 0);
    bpf_printk("get_tunnel_key rc=%d remote=%x ttl=%d\n", g, key.remote_ipv4, key.tunnel_ttl);

    //bpf_printk("gre_mcast_map hit 5\n");
    //key.tunnel_ttl  = 64;
    //key.remote_ipv4 = ip->daddr; // dynamic outer dst = inner multicast group

    int flags = BPF_F_ZERO_CSUM_TX;;
    int s = bpf_skb_set_tunnel_key(skb, &key, len, flags);
    bpf_printk("set_tunnel_key rc=%d new_remote=%x\n", s, key.remote_ipv4);
    
    struct bpf_tunnel_key key2 = {};
    int g2 = bpf_skb_get_tunnel_key(skb, &key2, len, 0);
    bpf_printk("get2 rc=%d remote2=%x ttl2=%d\n", g2, key2.remote_ipv4, key2.tunnel_ttl);
    bpf_printk("gre_mcast_map hit 9\n");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
