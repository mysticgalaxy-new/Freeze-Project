#include "net.h"
#include "vga.h"
#include <stdint.h>

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0,%1" :: "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
    uint8_t v;
    __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile("outw %0,%1" :: "a"(val), "Nd"(port));
}
static inline uint16_t inw(uint16_t port) {
    uint16_t v;
    __asm__ volatile("inw %1,%0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void outl(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0,%1" :: "a"(val), "Nd"(port));
}
static inline uint32_t inl(uint16_t port) {
    uint32_t v;
    __asm__ volatile("inl %1,%0" : "=a"(v) : "Nd"(port));
    return v;
}

static uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off) {
    uint32_t addr = 0x80000000u
                  | ((uint32_t)bus  << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | (off & 0xFC);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

static void pci_write(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint32_t val) {
    uint32_t addr = 0x80000000u
                  | ((uint32_t)bus  << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | (off & 0xFC);
    outl(0xCF8, addr);
    outl(0xCFC, val);
}

static void pci_enable_bus_master(uint8_t bus, uint8_t slot) {
    uint32_t cmd = pci_read(bus, slot, 0, 0x04);
    cmd |= (1 << 2) | (1 << 1);
    pci_write(bus, slot, 0, 0x04, cmd);
}

static void mem_copy(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

static void mem_set(void *dst, uint8_t v, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = v;
}

static int mem_eq(const void *a, const void *b, uint32_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    for (uint32_t i = 0; i < n; i++) if (x[i] != y[i]) return 0;
    return 1;
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}
static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static uint16_t ip_checksum(const uint8_t *data, uint32_t len) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1) sum += ((uint32_t)data[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                             const uint8_t *tcp, uint16_t tcp_len) {
    uint32_t sum = 0;
    for (int i = 0; i < 4; i += 2) sum += ((uint16_t)src_ip[i] << 8) | src_ip[i + 1];
    for (int i = 0; i < 4; i += 2) sum += ((uint16_t)dst_ip[i] << 8) | dst_ip[i + 1];
    sum += 0x0006;
    sum += tcp_len;
    for (uint32_t i = 0; i + 1 < tcp_len; i += 2) sum += ((uint16_t)tcp[i] << 8) | tcp[i + 1];
    if (tcp_len & 1) sum += ((uint16_t)tcp[tcp_len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

struct net_device *active_net = 0;

static uint8_t local_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
static const uint8_t local_ip[4] = {10, 0, 2, 15};
static const uint8_t gateway_ip[4] = {10, 0, 2, 2};
static const uint8_t dns_ip[4] = {10, 0, 2, 3};

static int tx_rx_ready = 0;

static struct {
    int valid;
    uint8_t ip[4];
    uint8_t mac[6];
} arp_cache;

#define E1000_REG_CTRL    0x0000
#define E1000_REG_STATUS  0x0008
#define E1000_REG_RCTL    0x0100
#define E1000_REG_TCTL    0x0400
#define E1000_REG_TIPG    0x0410
#define E1000_REG_RDBAL   0x2800
#define E1000_REG_RDBAH   0x2804
#define E1000_REG_RDLEN   0x2808
#define E1000_REG_RDH     0x2810
#define E1000_REG_RDT     0x2818
#define E1000_REG_TDBAL   0x3800
#define E1000_REG_TDBAH   0x3804
#define E1000_REG_TDLEN   0x3808
#define E1000_REG_TDH     0x3810
#define E1000_REG_TDT     0x3818
#define E1000_REG_RAL     0x5400
#define E1000_REG_RAH     0x5404

#define E1000_NUM_RX_DESC 32
#define E1000_NUM_TX_DESC 8
#define E1000_RX_BUF_SIZE 2048
#define E1000_TX_BUF_SIZE 2048

struct e1000_rx_desc {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} __attribute__((packed));

struct e1000_tx_desc {
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} __attribute__((packed));

static uint8_t e1000_bus = 0xFF;
static uint8_t e1000_slot = 0xFF;
static volatile uint32_t *e1000_mmio = 0;

static struct e1000_rx_desc e1000_rx_descs[E1000_NUM_RX_DESC];
static struct e1000_tx_desc e1000_tx_descs[E1000_NUM_TX_DESC];
static uint8_t e1000_rx_bufs[E1000_NUM_RX_DESC][E1000_RX_BUF_SIZE];
static uint8_t e1000_tx_bufs[E1000_NUM_TX_DESC][E1000_TX_BUF_SIZE];
static int e1000_rx_idx = 0;
static int e1000_tx_tail = 0;

static void e1000_wr(uint32_t reg, uint32_t val) { e1000_mmio[reg / 4] = val; }
static uint32_t e1000_rd(uint32_t reg) { return e1000_mmio[reg / 4]; }

static int e1000_link_up(void) {
    return (e1000_rd(E1000_REG_STATUS) & (1 << 1)) != 0;
}

static int e1000_send_frame(const uint8_t *frame, uint16_t len) {
    if (!tx_rx_ready || len > E1000_TX_BUF_SIZE) return -1;
    struct e1000_tx_desc *d = &e1000_tx_descs[e1000_tx_tail];
    if (!(d->status & 0x1)) return -1;

    mem_copy(e1000_tx_bufs[e1000_tx_tail], frame, len);
    d->length = len;
    d->cmd = 0x0B;
    d->status = 0;

    e1000_tx_tail = (e1000_tx_tail + 1) % E1000_NUM_TX_DESC;
    e1000_wr(E1000_REG_TDT, (uint32_t)e1000_tx_tail);
    return 0;
}

static void handle_frame(const uint8_t *frame, uint16_t len);

void net_poll(void) {
    if (active_net && active_net->poll) active_net->poll();
}

static void e1000_poll(void) {
    for (;;) {
        struct e1000_rx_desc *d = &e1000_rx_descs[e1000_rx_idx];
        if (!(d->status & 0x1)) break;
        if (d->length >= 14 && d->length <= E1000_RX_BUF_SIZE) {
            handle_frame(e1000_rx_bufs[e1000_rx_idx], d->length);
        }
        d->status = 0;
        e1000_wr(E1000_REG_RDT, (uint32_t)e1000_rx_idx);
        e1000_rx_idx = (e1000_rx_idx + 1) % E1000_NUM_RX_DESC;
    }
}

static void e1000_init(void) {
    print("[e1000] init...\n");
    pci_enable_bus_master(e1000_bus, e1000_slot);

    uint32_t bar0 = pci_read(e1000_bus, e1000_slot, 0, 0x10);
    e1000_mmio = (volatile uint32_t *)(bar0 & ~0xFu);

    e1000_wr(E1000_REG_CTRL, 1u << 26);
    for (volatile int i = 0; i < 100000; i++);

    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        e1000_rx_descs[i].addr = (uint64_t)(uint32_t)e1000_rx_bufs[i];
        e1000_rx_descs[i].status = 0;
    }
    e1000_wr(E1000_REG_RDBAL, (uint32_t)e1000_rx_descs);
    e1000_wr(E1000_REG_RDBAH, 0);
    e1000_wr(E1000_REG_RDLEN, E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc));
    e1000_wr(E1000_REG_RDH, 0);
    e1000_wr(E1000_REG_RDT, E1000_NUM_RX_DESC - 1);
    e1000_wr(E1000_REG_RCTL, (1 << 1) | (1 << 15));

    for (int i = 0; i < E1000_NUM_TX_DESC; i++) {
        e1000_tx_descs[i].addr = (uint64_t)(uint32_t)e1000_tx_bufs[i];
        e1000_tx_descs[i].status = 0x1;
    }
    e1000_wr(E1000_REG_TDBAL, (uint32_t)e1000_tx_descs);
    e1000_wr(E1000_REG_TDBAH, 0);
    e1000_wr(E1000_REG_TDLEN, E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));
    e1000_wr(E1000_REG_TDH, 0);
    e1000_wr(E1000_REG_TDT, 0);
    e1000_wr(E1000_REG_TCTL, 0x00000C02);
    e1000_wr(E1000_REG_TIPG, 0x0060200A);
    e1000_tx_tail = 0;

    uint32_t ral = e1000_rd(E1000_REG_RAL);
    uint32_t rah = e1000_rd(E1000_REG_RAH);
    local_mac[0] = (uint8_t)(ral & 0xFF);
    local_mac[1] = (uint8_t)((ral >> 8) & 0xFF);
    local_mac[2] = (uint8_t)((ral >> 16) & 0xFF);
    local_mac[3] = (uint8_t)((ral >> 24) & 0xFF);
    local_mac[4] = (uint8_t)(rah & 0xFF);
    local_mac[5] = (uint8_t)((rah >> 8) & 0xFF);

    tx_rx_ready = 1;
    print("[e1000] link: ");
    print(e1000_link_up() ? "up\n" : "down\n");
}

static uint16_t rtl_iobase = 0;
static int rtl8139_link_up(void) { return !(inb(rtl_iobase + 0x58) & 0x04); }
static void rtl8139_poll(void) { (void)0; }
static void rtl8139_init(void) {
    print("[rtl8139] init...\n");
    print("[rtl8139] link: ");
    print(rtl8139_link_up() ? "up\n" : "down\n");
    tx_rx_ready = 0;
}

static uint16_t virtio_iobase = 0;
static int virtio_link_up(void) { (void)virtio_iobase; return 1; }
static void virtio_poll(void) { (void)0; }
static void virtio_init(void) {
    print("[virtio-net] init...\n");
    tx_rx_ready = 0;
}

static uint16_t pcnet_iobase = 0;
static int pcnet_link_up(void) { (void)pcnet_iobase; return 1; }
static void pcnet_poll(void) { (void)0; }
static void pcnet_init(void) {
    print("[pcnet] init...\n");
    tx_rx_ready = 0;
}

#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV4 0x0800

static void route_next_hop(const uint8_t dst_ip[4], uint8_t out_hop[4]) {
    if (mem_eq(dst_ip, local_ip, 4)) mem_copy(out_hop, dst_ip, 4);
    else mem_copy(out_hop, gateway_ip, 4);
}

static int send_eth(uint16_t eth_type, const uint8_t dst_mac[6], const uint8_t *payload, uint16_t plen) {
    uint8_t frame[1518];
    if (((uint32_t)plen + 14u) > (uint32_t)sizeof(frame)) return -1;
    mem_copy(frame, dst_mac, 6);
    mem_copy(frame + 6, local_mac, 6);
    wr_be16(frame + 12, eth_type);
    mem_copy(frame + 14, payload, plen);
    return e1000_send_frame(frame, (uint16_t)(14 + plen));
}

static int arp_waiting = 0;
static uint8_t arp_wait_ip[4];

static int arp_send_request(const uint8_t target_ip[4]) {
    uint8_t arp[28];
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    wr_be16(arp + 0, 1);
    wr_be16(arp + 2, 0x0800);
    arp[4] = 6;
    arp[5] = 4;
    wr_be16(arp + 6, 1);
    mem_copy(arp + 8, local_mac, 6);
    mem_copy(arp + 14, local_ip, 4);
    mem_set(arp + 18, 0, 6);
    mem_copy(arp + 24, target_ip, 4);
    return send_eth(ETH_TYPE_ARP, bcast, arp, sizeof(arp));
}

static int arp_resolve(const uint8_t ip[4], uint8_t out_mac[6]) {
    if (arp_cache.valid && mem_eq(arp_cache.ip, ip, 4)) {
        mem_copy(out_mac, arp_cache.mac, 6);
        return 0;
    }

    arp_waiting = 1;
    mem_copy(arp_wait_ip, ip, 4);
    for (int t = 0; t < 3; t++) {
        arp_send_request(ip);
        for (int i = 0; i < 200000; i++) {
            net_poll();
            if (arp_cache.valid && mem_eq(arp_cache.ip, ip, 4)) {
                mem_copy(out_mac, arp_cache.mac, 6);
                arp_waiting = 0;
                return 0;
            }
        }
    }
    arp_waiting = 0;
    return -1;
}

static int send_ipv4(uint8_t proto, const uint8_t dst_ip[4], const uint8_t *payload, uint16_t plen) {
    uint8_t hop_ip[4];
    uint8_t dst_mac[6];
    route_next_hop(dst_ip, hop_ip);
    if (arp_resolve(hop_ip, dst_mac) != 0) return -1;

    uint8_t ip[20 + 1500];
    if (((uint32_t)plen + 20u) > (uint32_t)sizeof(ip)) return -1;
    ip[0] = 0x45;
    ip[1] = 0;
    wr_be16(ip + 2, (uint16_t)(20 + plen));
    wr_be16(ip + 4, 0x1234);
    wr_be16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = proto;
    wr_be16(ip + 10, 0);
    mem_copy(ip + 12, local_ip, 4);
    mem_copy(ip + 16, dst_ip, 4);
    wr_be16(ip + 10, ip_checksum(ip, 20));
    mem_copy(ip + 20, payload, plen);
    return send_eth(ETH_TYPE_IPV4, dst_mac, ip, (uint16_t)(20 + plen));
}

static int dns_waiting = 0;
static uint16_t dns_txid = 0;
static uint16_t dns_src_port = 53000;
static int dns_done = 0;
static int dns_ok = 0;
static uint8_t dns_answer_ip[4];

static struct {
    int active;
    int done;
    int ok;
    uint8_t server_ip[4];
    uint16_t client_port;
    uint16_t server_port;
    uint16_t expect_block;
    uint8_t *out;
    uint32_t out_cap;
    uint32_t out_len;
} tftp_state;

static int udp_send(const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port,
                    const uint8_t *payload, uint16_t payload_len) {
    uint8_t udp[8 + 1024];
    uint16_t ulen = (uint16_t)(8 + payload_len);
    if (ulen > sizeof(udp)) return -1;
    wr_be16(udp + 0, src_port);
    wr_be16(udp + 2, dst_port);
    wr_be16(udp + 4, ulen);
    wr_be16(udp + 6, 0);
    if (payload_len) mem_copy(udp + 8, payload, payload_len);
    return send_ipv4(17, dst_ip, udp, ulen);
}

static int dns_encode_name(const char *host, uint8_t *out, uint32_t max) {
    uint32_t pos = 0;
    uint32_t start = 0;
    uint32_t i = 0;
    while (1) {
        char c = host[i];
        if (c == '.' || c == 0) {
            uint32_t lab_len = i - start;
            if (lab_len > 63 || pos + 1 + lab_len >= max) return -1;
            out[pos++] = (uint8_t)lab_len;
            for (uint32_t j = 0; j < lab_len; j++) out[pos++] = (uint8_t)host[start + j];
            start = i + 1;
            if (c == 0) break;
        }
        i++;
    }
    if (pos >= max) return -1;
    out[pos++] = 0;
    return (int)pos;
}

static int dns_resolve(const char *host, uint8_t out_ip[4]) {
    uint8_t qname[256];
    int qn = dns_encode_name(host, qname, sizeof(qname));
    if (qn < 0) return -1;

    uint8_t payload[512];
    uint16_t pdlen = (uint16_t)(12 + qn + 4);
    if (pdlen > sizeof(payload)) return -1;
    mem_set(payload, 0, pdlen);

    uint8_t *d = payload;
    dns_txid++;
    wr_be16(d + 0, dns_txid);
    wr_be16(d + 2, 0x0100);
    wr_be16(d + 4, 1);
    wr_be16(d + 6, 0);
    wr_be16(d + 8, 0);
    wr_be16(d + 10, 0);
    mem_copy(d + 12, qname, (uint32_t)qn);
    wr_be16(d + 12 + qn, 1);
    wr_be16(d + 14 + qn, 1);

    dns_waiting = 1;
    dns_done = 0;
    dns_ok = 0;
    if (udp_send(dns_ip, dns_src_port, 53, payload, pdlen) != 0) {
        dns_waiting = 0;
        return -1;
    }

    for (int i = 0; i < 800000; i++) {
        net_poll();
        if (dns_done) break;
    }

    dns_waiting = 0;
    if (!dns_done || !dns_ok) return -1;
    mem_copy(out_ip, dns_answer_ip, 4);
    return 0;
}

struct tcp_conn_state {
    int used;
    int established;
    int closed;
    uint8_t remote_ip[4];
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t seq;
    uint32_t ack;
};

static struct tcp_conn_state tcp_conn;

static uint8_t *http_out = 0;
static uint32_t http_out_cap = 0;
static uint32_t http_out_len = 0;
static int http_header_done = 0;
static uint8_t http_hdr[1024];
static uint32_t http_hdr_len = 0;

static void http_feed(const uint8_t *data, uint16_t len) {
    if (len == 0) return;
    if (!http_header_done) {
        for (uint16_t i = 0; i < len; i++) {
            if (http_hdr_len < sizeof(http_hdr)) http_hdr[http_hdr_len++] = data[i];
            if (http_hdr_len >= 4 &&
                http_hdr[http_hdr_len - 4] == '\r' &&
                http_hdr[http_hdr_len - 3] == '\n' &&
                http_hdr[http_hdr_len - 2] == '\r' &&
                http_hdr[http_hdr_len - 1] == '\n') {
                http_header_done = 1;
                uint16_t rem = (uint16_t)(len - i - 1);
                if (rem > 0 && http_out_len < http_out_cap) {
                    uint32_t can = http_out_cap - http_out_len;
                    if (rem > can) rem = (uint16_t)can;
                    mem_copy(http_out + http_out_len, data + i + 1, rem);
                    http_out_len += rem;
                }
                return;
            }
        }
    } else if (http_out_len < http_out_cap) {
        uint32_t can = http_out_cap - http_out_len;
        uint16_t cp = len > can ? (uint16_t)can : len;
        mem_copy(http_out + http_out_len, data, cp);
        http_out_len += cp;
    }
}

static int tcp_send_segment(const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port,
                            uint32_t seq, uint32_t ack, uint8_t flags,
                            const uint8_t *payload, uint16_t plen) {
    uint8_t tcp[20 + 1024];
    if (((uint32_t)plen + 20u) > (uint32_t)sizeof(tcp)) return -1;
    wr_be16(tcp + 0, src_port);
    wr_be16(tcp + 2, dst_port);
    wr_be32(tcp + 4, seq);
    wr_be32(tcp + 8, ack);
    tcp[12] = 0x50;
    tcp[13] = flags;
    wr_be16(tcp + 14, 4096);
    wr_be16(tcp + 16, 0);
    wr_be16(tcp + 18, 0);
    if (plen) mem_copy(tcp + 20, payload, plen);
    wr_be16(tcp + 16, tcp_checksum(local_ip, dst_ip, tcp, (uint16_t)(20 + plen)));
    return send_ipv4(6, dst_ip, tcp, (uint16_t)(20 + plen));
}

static int tcp_connect(const uint8_t dst_ip[4], uint16_t dst_port) {
    mem_set(&tcp_conn, 0, sizeof(tcp_conn));
    tcp_conn.used = 1;
    mem_copy(tcp_conn.remote_ip, dst_ip, 4);
    tcp_conn.local_port = 49152;
    tcp_conn.remote_port = dst_port;
    tcp_conn.seq = 0x10203040;
    tcp_conn.ack = 0;

    if (tcp_send_segment(dst_ip, tcp_conn.local_port, dst_port, tcp_conn.seq, 0, 0x02, 0, 0) != 0)
        return -1;
    tcp_conn.seq += 1;

    for (int i = 0; i < 800000; i++) {
        net_poll();
        if (tcp_conn.established) return 0;
    }
    return -1;
}

static void handle_arp(const uint8_t *pkt, uint16_t len) {
    if (len < 28) return;
    uint16_t op = be16(pkt + 6);
    const uint8_t *sha = pkt + 8;
    const uint8_t *spa = pkt + 14;
    const uint8_t *tpa = pkt + 24;

    if (op == 2) {
        arp_cache.valid = 1;
        mem_copy(arp_cache.ip, spa, 4);
        mem_copy(arp_cache.mac, sha, 6);
    }

    if (op == 1 && mem_eq(tpa, local_ip, 4)) {
        uint8_t rep[28];
        wr_be16(rep + 0, 1);
        wr_be16(rep + 2, 0x0800);
        rep[4] = 6;
        rep[5] = 4;
        wr_be16(rep + 6, 2);
        mem_copy(rep + 8, local_mac, 6);
        mem_copy(rep + 14, local_ip, 4);
        mem_copy(rep + 18, sha, 6);
        mem_copy(rep + 24, spa, 4);
        send_eth(ETH_TYPE_ARP, sha, rep, sizeof(rep));
    }
}

static void handle_udp(const uint8_t src_ip[4], const uint8_t *udp, uint16_t len) {
    (void)src_ip;
    if (len < 8) return;
    uint16_t src_port = be16(udp + 0);
    uint16_t dst_port = be16(udp + 2);
    uint16_t ulen = be16(udp + 4);
    if (ulen > len || ulen < 8) return;
    const uint8_t *data = udp + 8;
    uint16_t dlen = (uint16_t)(ulen - 8);

    if (tftp_state.active && dst_port == tftp_state.client_port && mem_eq(src_ip, tftp_state.server_ip, 4) && dlen >= 2) {
        uint16_t op = be16(data + 0);
        if (op == 3 && dlen >= 4) {
            uint16_t block = be16(data + 2);
            if (tftp_state.server_port == 0) tftp_state.server_port = src_port;
            if (src_port != tftp_state.server_port) return;
            if (block == tftp_state.expect_block) {
                uint16_t pay = (uint16_t)(dlen - 4);
                if (tftp_state.out_len < tftp_state.out_cap) {
                    uint32_t can = tftp_state.out_cap - tftp_state.out_len;
                    if (pay > can) pay = (uint16_t)can;
                    mem_copy(tftp_state.out + tftp_state.out_len, data + 4, pay);
                    tftp_state.out_len += pay;
                }
                uint8_t ack[4];
                wr_be16(ack + 0, 4);
                wr_be16(ack + 2, block);
                udp_send(tftp_state.server_ip, tftp_state.client_port, tftp_state.server_port, ack, 4);
                tftp_state.expect_block++;
                if ((dlen - 4) < 512) {
                    tftp_state.done = 1;
                    tftp_state.ok = 1;
                }
            }
        } else if (op == 5) {
            tftp_state.done = 1;
            tftp_state.ok = 0;
        }
        return;
    }

    if (dns_waiting && src_port == 53 && dst_port == dns_src_port && dlen >= 12) {
        uint16_t id = be16(data + 0);
        uint16_t flags = be16(data + 2);
        uint16_t qd = be16(data + 4);
        uint16_t an = be16(data + 6);
        if (id != dns_txid || !(flags & 0x8000)) {
            dns_done = 1;
            dns_ok = 0;
            return;
        }

        uint32_t off = 12;
        for (uint16_t qi = 0; qi < qd; qi++) {
            while (off < dlen && data[off] != 0) off += (uint32_t)data[off] + 1;
            off++;
            off += 4;
            if (off > dlen) {
                dns_done = 1;
                dns_ok = 0;
                return;
            }
        }

        dns_ok = 0;
        for (uint16_t ai = 0; ai < an && off + 12 <= dlen; ai++) {
            if ((data[off] & 0xC0) == 0xC0) off += 2;
            else {
                while (off < dlen && data[off] != 0) off += (uint32_t)data[off] + 1;
                off++;
            }
            if (off + 10 > dlen) break;
            uint16_t typ = be16(data + off); off += 2;
            uint16_t cls = be16(data + off); off += 2;
            off += 4;
            uint16_t rdlen = be16(data + off); off += 2;
            if (off + rdlen > dlen) break;
            if (typ == 1 && cls == 1 && rdlen == 4) {
                mem_copy(dns_answer_ip, data + off, 4);
                dns_ok = 1;
                break;
            }
            off += rdlen;
        }
        dns_done = 1;
    }
}

static void handle_tcp(const uint8_t src_ip[4], const uint8_t *tcp, uint16_t len) {
    if (len < 20 || !tcp_conn.used) return;

    uint16_t src_port = be16(tcp + 0);
    uint16_t dst_port = be16(tcp + 2);
    uint32_t seq = be32(tcp + 4);
    uint32_t ack = be32(tcp + 8);
    uint8_t off = (uint8_t)((tcp[12] >> 4) * 4);
    uint8_t flags = tcp[13];
    if (off < 20 || off > len) return;
    uint16_t plen = (uint16_t)(len - off);
    const uint8_t *payload = tcp + off;

    if (!mem_eq(src_ip, tcp_conn.remote_ip, 4) ||
        src_port != tcp_conn.remote_port || dst_port != tcp_conn.local_port) {
        return;
    }

    if ((flags & 0x12) == 0x12 && !tcp_conn.established) {
        tcp_conn.ack = seq + 1;
        tcp_conn.established = 1;
        tcp_send_segment(tcp_conn.remote_ip, tcp_conn.local_port, tcp_conn.remote_port,
                         tcp_conn.seq, tcp_conn.ack, 0x10, 0, 0);
        return;
    }

    if (flags & 0x10) {
        (void)ack;
    }

    if (plen > 0) {
        if (seq == tcp_conn.ack) {
            http_feed(payload, plen);
            tcp_conn.ack += plen;
            tcp_send_segment(tcp_conn.remote_ip, tcp_conn.local_port, tcp_conn.remote_port,
                             tcp_conn.seq, tcp_conn.ack, 0x10, 0, 0);
        }
    }

    if (flags & 0x01) {
        tcp_conn.ack += 1;
        tcp_send_segment(tcp_conn.remote_ip, tcp_conn.local_port, tcp_conn.remote_port,
                         tcp_conn.seq, tcp_conn.ack, 0x10, 0, 0);
        tcp_conn.closed = 1;
    }
}

static void handle_ipv4(const uint8_t *pkt, uint16_t len) {
    if (len < 20) return;
    uint8_t ihl = (uint8_t)((pkt[0] & 0x0F) * 4);
    if (ihl < 20 || ihl > len) return;
    uint16_t total = be16(pkt + 2);
    if (total > len) total = len;
    if (!mem_eq(pkt + 16, local_ip, 4)) return;
    uint8_t proto = pkt[9];
    const uint8_t *src_ip = pkt + 12;
    const uint8_t *l4 = pkt + ihl;
    uint16_t l4_len = (uint16_t)(total - ihl);

    if (proto == 17) handle_udp(src_ip, l4, l4_len);
    else if (proto == 6) handle_tcp(src_ip, l4, l4_len);
}

static void handle_frame(const uint8_t *frame, uint16_t len) {
    if (len < 14) return;
    uint16_t eth = be16(frame + 12);
    const uint8_t *payload = frame + 14;
    uint16_t plen = (uint16_t)(len - 14);
    if (eth == ETH_TYPE_ARP) handle_arp(payload, plen);
    else if (eth == ETH_TYPE_IPV4) handle_ipv4(payload, plen);
}

static int is_digit(char c) { return c >= '0' && c <= '9'; }

static char to_lower_ascii(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return c;
}

static int http_status_code(const uint8_t *hdr, uint32_t len) {
    uint32_t i = 0;
    while (i < len && hdr[i] != ' ') i++;
    if (i + 3 >= len) return 0;
    if (!is_digit((char)hdr[i + 1]) || !is_digit((char)hdr[i + 2]) || !is_digit((char)hdr[i + 3])) return 0;
    return (hdr[i + 1] - '0') * 100 + (hdr[i + 2] - '0') * 10 + (hdr[i + 3] - '0');
}

static int http_get_header_value(const uint8_t *hdr, uint32_t len,
                                 const char *name, char *out, uint32_t out_cap) {
    uint32_t name_len = 0;
    while (name[name_len]) name_len++;
    if (out_cap == 0) return -1;

    uint32_t line_start = 0;
    while (line_start < len) {
        uint32_t line_end = line_start;
        while (line_end < len && hdr[line_end] != '\n') line_end++;

        if (line_end > line_start) {
            uint32_t content_end = line_end;
            if (content_end > line_start && hdr[content_end - 1] == '\r') content_end--;

            if (content_end >= line_start + name_len + 1) {
                int match = 1;
                for (uint32_t i = 0; i < name_len; i++) {
                    if (to_lower_ascii((char)hdr[line_start + i]) != to_lower_ascii(name[i])) {
                        match = 0;
                        break;
                    }
                }
                if (match && hdr[line_start + name_len] == ':') {
                    uint32_t v = line_start + name_len + 1;
                    while (v < content_end && (hdr[v] == ' ' || hdr[v] == '\t')) v++;

                    uint32_t o = 0;
                    while (v < content_end && o + 1 < out_cap) {
                        out[o++] = (char)hdr[v++];
                    }
                    out[o] = 0;
                    return 0;
                }
            }
        }

        line_start = line_end + 1;
    }

    out[0] = 0;
    return -1;
}

static int parse_ipv4_text(const char *s, uint8_t out[4]) {
    int part = 0;
    int val = 0;
    int have = 0;
    while (*s) {
        char c = *s++;
        if (c == '.') {
            if (!have || val > 255 || part >= 3) return -1;
            out[part++] = (uint8_t)val;
            val = 0;
            have = 0;
            continue;
        }
        if (!is_digit(c)) return -1;
        have = 1;
        val = val * 10 + (c - '0');
        if (val > 255) return -1;
    }
    if (!have || part != 3) return -1;
    out[3] = (uint8_t)val;
    return 0;
}

static int starts_with(const char *s, const char *p) {
    uint32_t i = 0;
    while (p[i]) {
        if (s[i] != p[i]) return 0;
        i++;
    }
    return 1;
}

static void sanitize_filename(const char *in, char *out, uint32_t cap) {
    uint32_t j = 0;
    if (cap == 0) return;
    for (uint32_t i = 0; in[i] && j + 1 < cap; i++) {
        char c = in[i];
        int ok = (c >= 'a' && c <= 'z') ||
                 (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '_' || c == '-';
        out[j++] = ok ? c : '_';
    }
    if (j == 0 && cap > 1) {
        out[0] = 'f'; out[1] = 0;
    } else {
        out[j] = 0;
    }
}

static int split_url(const char *url, char *host, uint32_t host_cap,
                     uint16_t *port, char *path, uint32_t path_cap,
                     char *name, uint32_t name_cap) {
    if (!starts_with(url, "http://")) return -1;
    const char *p = url + 7;

    uint32_t hi = 0;
    while (*p && *p != '/' && *p != ':' && hi + 1 < host_cap) host[hi++] = *p++;
    host[hi] = 0;
    if (hi == 0) return -1;

    *port = 80;
    if (*p == ':') {
        p++;
        uint32_t v = 0;
        while (*p && *p != '/') {
            if (!is_digit(*p)) return -1;
            v = v * 10 + (uint32_t)(*p - '0');
            if (v > 65535) return -1;
            p++;
        }
        *port = (uint16_t)v;
    }

    if (*p == 0) {
        if (path_cap < 2) return -1;
        path[0] = '/';
        path[1] = 0;
    } else {
        uint32_t pi = 0;
        while (*p && pi + 1 < path_cap) path[pi++] = *p++;
        path[pi] = 0;
    }

    const char *last = path;
    for (uint32_t i = 0; path[i]; i++) if (path[i] == '/') last = &path[i + 1];
    if (*last == 0) last = "index.html";
    sanitize_filename(last, name, name_cap);
    return 0;
}

int net_ready(void) {
    return tx_rx_ready && active_net && active_net->link_up && active_net->link_up();
}

int net_import_http(const char *url,
                    const char *forced_name,
                    char *out_name,
                    uint32_t out_name_cap,
                    char *out_data,
                    uint32_t out_cap,
                    uint32_t *out_len) {
    char host[128];
    char path[256];
    char auto_name[40];
    char location[192];
    uint16_t port;
    uint8_t dst_ip[4];

    if (!net_ready()) {
        print("[NET] NIC not ready or link down\n");
        return -1;
    }
    if (split_url(url, host, sizeof(host), &port, path, sizeof(path), auto_name, sizeof(auto_name)) != 0) {
        print("[NET] URL must be http://host/path\n");
        return -1;
    }

    if (forced_name && forced_name[0]) sanitize_filename(forced_name, out_name, out_name_cap);
    else sanitize_filename(auto_name, out_name, out_name_cap);

    if (parse_ipv4_text(host, dst_ip) != 0) {
        if (dns_resolve(host, dst_ip) != 0) {
            print("[NET] DNS resolve failed\n");
            return -1;
        }
    }

    if (tcp_connect(dst_ip, port) != 0) {
        print("[NET] TCP connect failed\n");
        return -1;
    }

    char req[512];
    uint32_t rn = 0;
#define APP(ch) do { if (rn + 1 < sizeof(req)) req[rn++] = (ch); } while (0)
#define APPSTR(s) do { const char *q = (s); while (*q && rn + 1 < sizeof(req)) req[rn++] = *q++; } while (0)
    APPSTR("GET ");
    APPSTR(path);
    APPSTR(" HTTP/1.0\r\nHost: ");
    APPSTR(host);
    APPSTR("\r\nUser-Agent: FreezeOS\r\nConnection: close\r\n\r\n");
    APP(0);
#undef APP
#undef APPSTR

    http_out = (uint8_t *)out_data;
    http_out_cap = out_cap;
    http_out_len = 0;
    http_header_done = 0;
    http_hdr_len = 0;
    tcp_conn.closed = 0;

    if (tcp_send_segment(dst_ip, tcp_conn.local_port, tcp_conn.remote_port,
                         tcp_conn.seq, tcp_conn.ack, 0x18,
                         (const uint8_t *)req, (uint16_t)(rn - 1)) != 0) {
        print("[NET] TCP send failed\n");
        return -1;
    }
    tcp_conn.seq += (rn - 1);

    for (int i = 0; i < 3000000; i++) {
        net_poll();
        if (tcp_conn.closed) break;
    }

    *out_len = http_out_len;
    if (!http_header_done) {
        print("[NET] HTTP response incomplete\n");
        return -1;
    }

    int status = http_status_code(http_hdr, http_hdr_len);

    if (http_out_len == 0) {
        if (status >= 300 && status < 400) {
            if (http_get_header_value(http_hdr, http_hdr_len, "Location", location, sizeof(location)) == 0) {
                print("[NET] HTTP redirect to ");
                print(location);
                print("\n");
                if (starts_with(location, "https://")) {
                    print("[NET] HTTPS redirects are not supported yet\n");
                }
            } else {
                print("[NET] HTTP redirect with no Location header\n");
            }
        } else if (status >= 400) {
            print("[NET] HTTP error status ");
            print_int(status);
            print("\n");
        }
        print("[NET] HTTP response/body empty\n");
        return -1;
    }

    return 0;
}

int net_import_tftp(const char *url,
                    const char *forced_name,
                    char *out_name,
                    uint32_t out_name_cap,
                    char *out_data,
                    uint32_t out_cap,
                    uint32_t *out_len) {
    char host[128];
    char path[256];
    char auto_name[40];
    uint8_t dst_ip[4];
    uint8_t rrq[600];
    uint16_t rrq_len;
    uint32_t h = 0;
    uint32_t p = 0;

    if (!net_ready()) {
        print("[NET] NIC not ready or link down\n");
        return -1;
    }
    if (!starts_with(url, "tftp://")) {
        print("[NET] URL must be tftp://host/path\n");
        return -1;
    }

    {
        const char *s = url + 7;
        while (s[h] && s[h] != '/' && h + 1 < sizeof(host)) {
            host[h] = s[h];
            h++;
        }
        host[h] = 0;
        if (host[0] == 0) return -1;

        if (s[h] == 0) {
            path[0] = 'd'; path[1] = 'o'; path[2] = 'w'; path[3] = 'n';
            path[4] = 'l'; path[5] = 'o'; path[6] = 'a'; path[7] = 'd';
            path[8] = '.'; path[9] = 'b'; path[10] = 'i'; path[11] = 'n';
            path[12] = 0;
        } else {
            if (s[h] == '/') h++;
            while (s[h] && p + 1 < sizeof(path)) {
                path[p++] = s[h++];
            }
            path[p] = 0;
            if (path[0] == 0) {
                path[0] = 'd'; path[1] = 'o'; path[2] = 'w'; path[3] = 'n';
                path[4] = 'l'; path[5] = 'o'; path[6] = 'a'; path[7] = 'd';
                path[8] = '.'; path[9] = 'b'; path[10] = 'i'; path[11] = 'n';
                path[12] = 0;
            }
        }

        const char *last = path;
        for (uint32_t i = 0; path[i]; i++) {
            if (path[i] == '/') last = &path[i + 1];
        }
        if (*last == 0) last = "download.bin";
        sanitize_filename(last, auto_name, sizeof(auto_name));
    }

    if (forced_name && forced_name[0]) sanitize_filename(forced_name, out_name, out_name_cap);
    else sanitize_filename(auto_name, out_name, out_name_cap);

    if (parse_ipv4_text(host, dst_ip) != 0) {
        if (dns_resolve(host, dst_ip) != 0) {
            print("[NET] DNS resolve failed\n");
            return -1;
        }
    }

    mem_set(&tftp_state, 0, sizeof(tftp_state));
    tftp_state.active = 1;
    tftp_state.client_port = 40000;
    tftp_state.server_port = 0;
    tftp_state.expect_block = 1;
    tftp_state.out = (uint8_t *)out_data;
    tftp_state.out_cap = out_cap;
    tftp_state.out_len = 0;
    mem_copy(tftp_state.server_ip, dst_ip, 4);

    rrq_len = 0;
    wr_be16(rrq + rrq_len, 1);
    rrq_len += 2;
    for (uint32_t i = 0; path[i] && ((uint32_t)rrq_len + 1u) < (uint32_t)sizeof(rrq); i++) {
        rrq[rrq_len++] = (uint8_t)path[i];
    }
    rrq[rrq_len++] = 0;
    rrq[rrq_len++] = 'o';
    rrq[rrq_len++] = 'c';
    rrq[rrq_len++] = 't';
    rrq[rrq_len++] = 'e';
    rrq[rrq_len++] = 't';
    rrq[rrq_len++] = 0;

    if (udp_send(dst_ip, tftp_state.client_port, 69, rrq, rrq_len) != 0) {
        tftp_state.active = 0;
        return -1;
    }

    for (int i = 0; i < 4000000; i++) {
        net_poll();
        if (tftp_state.done) break;
    }

    tftp_state.active = 0;
    *out_len = tftp_state.out_len;
    if (!tftp_state.done || !tftp_state.ok) {
        print("[NET] TFTP transfer failed\n");
        return -1;
    }
    return 0;
}

static struct net_device e1000_dev  = { "e1000",      e1000_init,    e1000_link_up,    e1000_poll   };
static struct net_device rtl_dev    = { "rtl8139",    rtl8139_init,  rtl8139_link_up,  rtl8139_poll };
static struct net_device virtio_dev = { "virtio-net", virtio_init,   virtio_link_up,   virtio_poll  };
static struct net_device pcnet_dev  = { "pcnet",      pcnet_init,    pcnet_link_up,    pcnet_poll   };

void net_scan_pci(void) {
    print("[PCI] Scanning...\n");

    int found_e1000 = 0;
    int found_rtl = 0;
    int found_virtio = 0;
    int found_pcnet = 0;

    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t slot = 0; slot < 32; slot++) {
            uint32_t id = pci_read((uint8_t)bus, slot, 0, 0);
            uint16_t vendor = id & 0xFFFF;
            if (vendor == 0xFFFF || vendor == 0x0000) continue;

            uint16_t device = (uint16_t)(id >> 16);
            print("[PCI] ");
            print_hex(vendor);
            print(":");
            print_hex(device);
            print(" @ ");
            print_hex(bus);
            print(":");
            print_hex(slot);
            print("\n");

            uint32_t cls = pci_read((uint8_t)bus, slot, 0, 0x08);
            if ((cls >> 24) == 0x02) print("      ^ network controller\n");

            if (vendor == 0x8086) {
                switch (device) {
                case 0x100E:
                case 0x100F:
                case 0x1019:
                case 0x101A:
                case 0x10D3:
                case 0x1533:
                case 0x1F41:
                    print("[NET] Intel e1000 (");
                    print_hex(device);
                    print(")\n");
                    e1000_bus = (uint8_t)bus;
                    e1000_slot = slot;
                    found_e1000 = 1;
                    break;
                default:
                    break;
                }
            }

            if (vendor == 0x10EC && device == 0x8139) {
                print("[NET] Realtek RTL8139\n");
                uint32_t bar0 = pci_read((uint8_t)bus, slot, 0, 0x10);
                rtl_iobase = (uint16_t)(bar0 & ~1u);
                pci_enable_bus_master((uint8_t)bus, slot);
                found_rtl = 1;
            }

            if (vendor == 0x1AF4 && (device == 0x1000 || device == 0x1041)) {
                uint32_t sub = pci_read((uint8_t)bus, slot, 0, 0x2C);
                uint16_t subsys = (uint16_t)(sub >> 16);
                if (subsys == 1 || device == 0x1041) {
                    print("[NET] VirtIO-net\n");
                    uint32_t bar0 = pci_read((uint8_t)bus, slot, 0, 0x10);
                    virtio_iobase = (uint16_t)(bar0 & ~1u);
                    pci_enable_bus_master((uint8_t)bus, slot);
                    found_virtio = 1;
                }
            }

            if (vendor == 0x1022 && (device == 0x2000 || device == 0x2001)) {
                print("[NET] AMD PCnet\n");
                uint32_t bar0 = pci_read((uint8_t)bus, slot, 0, 0x10);
                pcnet_iobase = (uint16_t)(bar0 & ~1u);
                pci_enable_bus_master((uint8_t)bus, slot);
                found_pcnet = 1;
            }
        }
    }

    if (found_virtio) active_net = &virtio_dev;
    else if (found_e1000) active_net = &e1000_dev;
    else if (found_rtl) active_net = &rtl_dev;
    else if (found_pcnet) active_net = &pcnet_dev;

    if (active_net) {
        active_net->init();
        print("[NET] Active driver: ");
        print(active_net->name);
        print("\n");
    } else {
        print("[NET] No supported NIC found\n");
    }
}