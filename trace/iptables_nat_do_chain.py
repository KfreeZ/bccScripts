#!/usr/bin/env python 
# coding: utf-8 
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse
import ipaddress

# Hello BPF Program
bpf_text = '''
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <linux/trace_events.h>

// define output data structure in C
struct event_t {
    char func[16];
    u32 pid;
    u64 ts;
    u64 netns;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u8 ip_version;
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
    u8  len;
    u16 flag;
};
BPF_PERF_OUTPUT(events);

// Arg stash structure
struct ipt_do_table_args
{
    void *priv;
    struct sk_buff *skb;
    const struct nf_hook_state *state;
};
BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);

#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)            \
    ({                                                          \
        void* __ret;                                            \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                  \
        })
#define member_read(destination, source_struct, source_member)                 \
  do{                                                                          \
    bpf_probe_read(                                                            \
      destination,                                                             \
      sizeof(source_struct->source_member),                                    \
      ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
  } while(0)

static inline int do_trace_skb(struct event_t *evt, void *ctx, struct sk_buff *skb)
{
    // read sIP dIP port
    char* head;
    u16 mac_header;
    u16 network_header;
    member_read(&head,       skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);
    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    // Compute IP Header address
    char *ip_header_address = head + network_header;
    u8 l4proto;
    u8 l4_offset_from_ip_header;

    // Load IP protocol version
    bpf_probe_read(&evt->ip_version, sizeof(u8), ip_header_address);
    evt->ip_version = evt->ip_version >> 4 & 0xf;
    if (evt->ip_version == 4) {
        // Load IP Header
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);
        l4_offset_from_ip_header = iphdr.ihl * 4;
        // Load protocol and address
        l4proto      = iphdr.protocol;
        evt->saddr[0] = iphdr.saddr;
        evt->daddr[0] = iphdr.daddr;
        //bpf_trace_printk("saddr 0x%x daddr 0x%x\\n", be32_to_cpu(iphdr.saddr), be32_to_cpu(iphdr.daddr));
        FILTER_IP_4
    } else if (evt->ip_version == 6) {
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;
        l4_offset_from_ip_header = sizeof(*ipv6hdr);
        bpf_probe_read(&l4proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(evt->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(evt->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));
        return 0;
    } else {
        //bpf_trace_printk("ipt_do_table err\\n");
        return 0;
    }

    if (l4proto != IPPROTO_TCP) {
        bpf_trace_printk("not TCP \\n");
        return 0;
    }

    char* tcp_header_address = ip_header_address + l4_offset_from_ip_header;
    struct tcphdr thdr;
    bpf_probe_read(&thdr, sizeof(thdr), tcp_header_address);
    evt->sport = ntohs(thdr.source);
    evt->dport = ntohs(thdr.dest);
    evt->seq = be32_to_cpu(thdr.seq);
    evt->ack = be32_to_cpu(thdr.ack_seq);

    // read command
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    // read dev
    struct net_device *dev;
    member_read(&dev, skb, dev);
    bpf_probe_read(&evt->ifname, IFNAMSIZ, dev->name);

    // read namespace
    struct net* net;
    // Get netns id. The code below is equivalent to: evt->netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common* ns = member_address(net, ns);
    member_read(&evt->netns, ns, inum);

    return 1;
}

int trace_ipt(struct pt_regs *ctx, void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct event_t event = {};
    //strncpy(&event.func[0], "iptdoChIn", 16);
    event.func[0] = 'i';
    event.func[1] = 'p';
    event.func[2] = 't';
    event.func[3] = 'D';
    event.func[4] = 'o';
    event.func[5] = 'C';
    event.func[6] = 'h';
    event.func[7] = 'I';
    event.func[8] = 'n';
    event.func[9] = 0;


    u32 pid = bpf_get_current_pid_tgid();
    event.pid = bpf_get_current_pid_tgid();
    event.ts = bpf_ktime_get_ns();
    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .priv = priv,
    };
    cur_ipt_do_table_args.update(&pid, &args);
    if (1 == do_trace_skb(&event, ctx, skb)) {
       //shoot to userspace
       events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}




struct netifRcvSkb_args {
    // from /sys/kernel/debug/tracing/events/net/netif_receive_skb/format
    u64 __unused__;
    u64 skbaddr;
    u32 len;
    u32 name;
};
int traceTp_netifRcvSkb(struct netifRcvSkb_args *args) {
    struct event_t event = {};
    event.func[0] = 'n';
    event.func[1] = 'e';
    event.func[2] = 't';
    event.func[3] = 'i';
    event.func[4] = 'f';
    event.func[5] = 'R';
    event.func[6] = 'c';
    event.func[7] = 'v';
    event.func[8] = 'S';
    event.func[9] = 'k';
    event.func[10] = 'b';
    event.func[11] = 0;

    u32 pid = bpf_get_current_pid_tgid();
    struct sk_buff *skb;
    member_read(&skb, args, skbaddr);
    event.pid = pid;
    event.ts = bpf_ktime_get_ns();

    if (1 == do_trace_skb(&event, args, skb)) {

        //shoot to userspace
        events.perf_submit(args, &event, sizeof(event));
        //bpf_trace_printk("traceTp_netifRcvSkb_2\\n");
    }

    return 0;
}


int trace_ipt_out(struct pt_regs *ctx) {
    struct event_t event = {};
    event.func[0] = 'i';
    event.func[1] = 'p';
    event.func[2] = 't';
    event.func[3] = 'D';
    event.func[4] = 'o';
    event.func[5] = 'C';
    event.func[6] = 'h';
    event.func[7] = 'O';
    event.func[8] = 'u';
    event.func[9] = 't';    
    event.func[10] = 0;

    // Load arguments
    u32 pid = bpf_get_current_pid_tgid();
    event.pid = bpf_get_current_pid_tgid();
    event.ts = bpf_ktime_get_ns();
    struct ipt_do_table_args *args;
    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_table_args.delete(&pid);

    struct sk_buff *skb = args->skb;
    if (1 == do_trace_skb(&event, ctx, skb)) {
       events.perf_submit(ctx, &event, sizeof(event));
    }

    return PT_REGS_RC(ctx);
}
'''
examples = """examples:
    ./iptables_nat_do_chain.py -a 1.1.1.1 -b 2.2.2.2
"""
parser = argparse.ArgumentParser(
    description="Trace the lifespan of TCP connection",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-a", "--peerA", 
    help="IP address of TCP connection peer A")
parser.add_argument("-b", "--peerB", 
    help="IP address of TCP connection peer B")
args = parser.parse_args()


if args.peerA and args.peerB:
    pa = ipaddress.ip_address(args.peerA)
    pb = ipaddress.ip_address(args.peerB)
    bpf_text = bpf_text.replace('FILTER_IP_4', 
       'if (!(%d == be32_to_cpu(iphdr.saddr) && %d == be32_to_cpu(iphdr.daddr)) && !(%d == be32_to_cpu(iphdr.daddr) && %d == be32_to_cpu(iphdr.saddr))) { return 0; }' % (int(pa), int(pb), int(pa), int(pb)))
bpf_text = bpf_text.replace('FILTER_IP_4', '')

# 2. Build and Inject program
b = BPF(text=bpf_text)
b.attach_kprobe(event="iptable_nat_do_chain", fn_name="trace_ipt")
b.attach_kretprobe(event="iptable_nat_do_chain", fn_name="trace_ipt_out")

# some TIPs
# 1. cannot attach_kprobe to the trace points for some reason, attach_tracepoint is workable
# 2. attach_tracepoint is using args as the ctx in the kprobe, if args/ctx is missing, perf_submit() cannot work
# 3. args can be fount under /sys/kernel/debug/tracing/events/
# 4. if ctx is used as args in attach_tracepoint, bpf_read cannot work, complains permission denied
b.attach_tracepoint(tp="net:netif_receive_skb", fn_name="traceTp_netifRcvSkb")

#b.attach_uprobe(name="/bin/bash", sym="readline", fn_name="trace_recvfrom")


print("%-18s %-16s %-20s %-20s %-10s %-7s %-60s" % ("TIME(s)","FUNC", "COMM", "DEV", "NS", "PID", "FLOW"))

# 3. Print debug output
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    #event.ts is like 492233905473348.000000000, beautify it
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        saddr = 'NA'
        daddr = 'NA'

    flow = "%s:%s->%s:%s SEQ:%d ACK:%d " % (saddr, event.sport, daddr, event.dport, event.seq, event.ack)
    print("%-18.9f %-16s %-20s %-20s %-10s %-7d %-60s" % (time_s, event.func, event.comm, event.ifname, event.netns, event.pid, flow))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    # blocking waiting for events
    b.perf_buffer_poll()
    # line = b.trace_readline()
    # print(line)
