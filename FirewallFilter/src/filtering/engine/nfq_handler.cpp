#include "nfq_handler.hpp"

#include <netinet/in.h>
#include <linux/netfilter.h> // For NF_ACCEPT, etc.
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iostream>
#include <cstring>
#include <atomic>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../filtering.hpp"
#include "../utils/logger.hpp"

using namespace std;

atomic<bool> stop_atomic;

// Callback for each packet
static int my_nfq_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                        struct nfq_data* nfa, void* data)
{
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return nfq_set_verdict(qh, 0, NF_DROP, 0, nullptr);

    uint32_t id = ntohl(ph->packet_id);
    unsigned char* packetData = nullptr;
    int len = nfq_get_payload(nfa, &packetData);

    if (len >= (int)sizeof(struct iphdr)) {
        struct iphdr* ip_header = (struct iphdr*)packetData;
        string srcIP = inet_ntoa(*(in_addr*)&ip_header->saddr);
        string dstIP = inet_ntoa(*(in_addr*)&ip_header->daddr);

        int srcPort = 0;
        int dstPort = 0;
        int ipHeaderLen = ip_header->ihl * 4;

        if (ip_header->protocol == IPPROTO_TCP && len >= ipHeaderLen + (int)sizeof(struct tcphdr)) {
            struct tcphdr* tcp = (struct tcphdr*)(packetData + ipHeaderLen);
            srcPort = ntohs(tcp->source);
            dstPort = ntohs(tcp->dest);
        } else if (ip_header->protocol == IPPROTO_UDP && len >= ipHeaderLen + (int)sizeof(struct udphdr)) {
            struct udphdr* udp = (struct udphdr*)(packetData + ipHeaderLen);
            srcPort = ntohs(udp->source);
            dstPort = ntohs(udp->dest);
        } else {
            Logger::warn("Unsupported transport protocol or packet too short.");
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        }

        string payload((char*)packetData + ipHeaderLen, len - ipHeaderLen);
        bool allow = filterPacket(srcIP, dstIP, srcPort, dstPort, payload);
        return nfq_set_verdict(qh, id, allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
    }
    return -1;
}

int loop(){
    Logger::setLogLevel(LogLevel::DEBUG);

    struct nfq_handle* h = nfq_open();
    if (!h) {
        cerr << "Error: nfq_open() failed.\n";
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET) < 0) {
        cerr << "Error binding to AF_INET.\n";
        nfq_close(h);
        return 1;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &my_nfq_callback, nullptr);
    if (!qh) {
        cerr << "Error creating queue.\n";
        nfq_close(h);
        return 1;
    }

    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    while (true) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
