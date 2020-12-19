#include "analysis.h"
#include "growingarray.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <pthread.h>

Array syn_counter;              // Array to store IP of packets with SYN bits
volatile int arp_counter;       // Global volatile (can be changed at any time) counter for ARP poisoning detection
volatile int blacklist_counter; // Global volatile counter for blacklist violations  

pthread_mutex_t counters_lock = PTHREAD_MUTEX_INITIALIZER; // Mutex to lock global counters before we update them to stop race conditions 

void analyse(const unsigned char *packet, int verbose) {

    // We can't just update on the fly because multithreading so update these booleans and do it when we get mutex
    int is_syn_attack = 0;  
    int is_arp_attack = 0;  
    int is_blacklist_attack = 0;

    // Lengths of the headers so we can find the next headers
    int eth_header_length = ETH_HLEN; 
    int ip_header_length; 
    int tcp_header_length;

    // Pointers to the start of the headers we're interested in
    const unsigned char *ip_header_ptr = packet + eth_header_length;
    const unsigned char *tcp_header_ptr;  
    const unsigned char *payload_ptr; // Giving this const throws some whacky errors later so just dont add it

    // Actual structs we're going to use
    struct tcphdr *tcp_header;
    struct iphdr *ip_header;
    struct ether_arp *eth_arp_header;

    // If the protocol isn't TCP, then we're not interested in this packet unless its ARP
    // We can get the protocol being used in the packet in the IP header at byte 9
    // ip_header->protocol is equal to *(ip_header_ptr + 9); i.e. byte 9 of IP header
    ip_header = (struct iphdr *) ip_header_ptr;
    ip_header_length = (ip_header->ihl) * 4;

    // ## ARP POISONING ## // 
    if (ip_header->protocol != IPPROTO_TCP) {
        // Can't be ARP if not TCP, so check TCP first
        eth_arp_header = (struct ether_arp *) ip_header_ptr;
        // ARPOP_REPLY and info can be found in the ether_arp.h header file and docs
        if (ntohs(eth_arp_header->ea_hdr.ar_op) == ARPOP_REPLY) {
            is_arp_attack = 1; 
        }
    }

    // ## SYN FLOODING ## // 
    if (ip_header->protocol == IPPROTO_TCP) {
        // TCP header is after ethernet header (14 bytes) and ip header (variable length)
        tcp_header_ptr = ip_header_ptr + ip_header_length; 
        tcp_header = (struct tcphdr *) tcp_header_ptr; 

        // The TCP header length is stored in the first half of the 12th byte so we could do a bitwise AND with 11110000 then shift the result 4 bits to the right
        // tcp_header_length = ((*(tcp_header_ptr + 12 )) & 0xF0) >> 4; // But tcphdr gives us doff, so we can just use that 
        tcp_header_length = tcp_header->doff * 4;

        const int total_headers_size = eth_header_length + ip_header_length + tcp_header_length;
        //printf("ipheader ptr = %d, tcp_header_ptr = %d, Total header length is: %d\n", ip_header_ptr, tcp_header_ptr, total_headers_size);
        payload_ptr = packet + total_headers_size;

        if (tcp_header->syn && !tcp_header->ack && !tcp_header->urg && !tcp_header->psh && !tcp_header->fin && !tcp_header->rst) {
            // If the TCP header has SYN=1 then store it in our dynamic array
            // On exit, we will iterate over and get unique IPs, but for now store all. 
            is_syn_attack = 1; 
        }
    }

    // ## BLACKLIST VIOLATIONS ## // 
    if (ip_header->protocol == IPPROTO_TCP && payload_ptr != NULL) {
        // We're only interested in packets at port 80
        if (ntohs(tcp_header->dest) == 80) {
            const char *line;
            // We want to check that the host line is the one containing www.google.co.uk
            line = strstr((const char *)payload_ptr, "Host:");
            if (line != NULL) {
                if (strstr(line, "www.google.co.uk") != NULL) {
                    is_blacklist_attack = 1;
                } 
            }
        }
    }

    // Lock off the global counters before we update them to stop race conditions
    pthread_mutex_lock(&counters_lock);
        if (is_blacklist_attack) { blacklist_counter++; }
        if (is_arp_attack)       { arp_counter++; } 
        if (is_syn_attack)       { array_add(&syn_counter, ntohl(ip_header->saddr)); }
    pthread_mutex_unlock(&counters_lock);
}

// Function that can be called in sniff to initialise our syn counter array
// Can't be called in analyse because it will overwrite every call
void initialise_syn_counter() {
    array_create(&syn_counter, 4);
}
