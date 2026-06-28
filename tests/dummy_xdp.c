/* Minimal XDP pass-through program used by integration tests.
 *
 * veth native XDP_TX requires the peer interface to have an XDP program
 * attached. Loading this dummy program on the client veth allows the server
 * side to send TCP RST packets back via XDP_TX during test 1.5.
 */
#define SEC(name) __attribute__((section(name), used))
#define XDP_PASS 2

struct xdp_md {
    unsigned int data;
    unsigned int data_end;
    unsigned int data_meta;
    unsigned int ingress_ifindex;
    unsigned int rx_queue_index;
    unsigned int egress_ifindex;
};

SEC("xdp") int dummy(struct xdp_md *ctx) { return XDP_PASS; }

char _license[] SEC("license") = "GPL";
