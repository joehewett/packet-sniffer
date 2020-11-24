#include "analysis.h"
#include "growingarray.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if_arp.h>

Array syn_counter; 
volatile int arp_counter;
volatile int blacklist_counter; 

void print_arp_header(struct ether_arp *header);

void initialiseSynCounter() {
    initArray(&syn_counter, 4);
}


void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {

    // Lengths of the headers so we can find the next headers
    int eth_header_length = ETH_HLEN; 
    int ip_header_length; 
    int tcp_header_length;
    int payload_length; 

    // Pointers to the start of the headers we're interested in
    const unsigned char *ip_header_ptr = packet + eth_header_length;
    const unsigned char *tcp_header_ptr;  
    unsigned char *payload_ptr;

    // Actual structs we're going to use
    struct tcphdr *tcp_header;
    struct iphdr *ip_header;
    struct ether_arp *eth_arp_header;

    // If the protocol isn't TCP, then we're not interested in this packet unless its ARP
    // We can get the protocol being used in the packet in the IP header at byte 9
    // ip_header->protocol is equal to *(ip_header_ptr + 9); i.e. byte 9 of IP header
    // Or we can just use 
    ip_header = (struct iphdr *) ip_header_ptr;
    ip_header_length = (ip_header->ihl) * 4;

    if (ip_header->protocol != IPPROTO_TCP) {
        eth_arp_header = (struct ether_arp *) ip_header_ptr;
        if (ntohs(eth_arp_header->ea_hdr.ar_op) == ARPOP_REPLY) {
            //insertArray(arp_responses, 1);
            arp_counter++;
        }
        return; // We're not going to get anything useful out of this packet if its not TCP
    }

    // Use the tcp header pointer to a instantiate a tcphdr struct
    if (ip_header->protocol == IPPROTO_TCP) {
        // TCP header is after ethernet header (14 bytes) and ip header
        tcp_header_ptr = ip_header_ptr + ip_header_length; 
        tcp_header = (struct tcphdr *) tcp_header_ptr; 

        // The TCP header length is stored in the first half of the 12th byte
        // Do a bitwise AND with 11110000 then shift the result 4 bits to the right
        // There is probably an easier way of doing this but this one makes me feel like a real programmer
        tcp_header_length = ((*(tcp_header_ptr + 12 )) & 0xF0) >> 4;
        // Same as IP - multiply by 4 to get byte count
        tcp_header_length = tcp_header_length * 4; 

        int total_headers_size = eth_header_length + ip_header_length + tcp_header_length;
        payload_ptr = packet + total_headers_size;

        // Get the syn bit using the tcphdr struct
        printf("SYN FLAG is %u\n", tcp_header->syn);
        if (tcp_header->syn) {
            // If the TCP header has SYN=1 then store it in our dynamic array
            // On exit, we will iterate over and get unique IPs, but for now store all. 
            insertArray(&syn_counter, ntohs(ip_header->saddr)); 
        }
    }

    payload_length = header->caplen - (eth_header_length + ip_header_length + tcp_header_length);
    printf("Payload length is %d\n",payload_length);

    // Check blacklist for google.co.uk 
    if (ip_header->protocol == IPPROTO_TCP && payload_length > 0) {
        printf(" # tcp_header->dest = %d\n", ntohs(tcp_header->dest));
        if (ntohs(tcp_header->dest) == 80) {
            printf(" # dest is port 80 \n");
            unsigned char *line;
            line = strstr(payload_ptr, "Host:");
            if (line != NULL) {
                printf(" # EEZ \n");
                if (strstr(line, "google.co.uk") != NULL) {
                    printf("MALICIOUS HTML FOUND");
                    blacklist_counter++;
                } else {
                    printf("MALCIOUS HTML NOT FOUND");
                }
            }
        }
    }
}

    
    //printf("Size of all headers combined: %d bytes\n", total_headers_size);
    //printf("Size of header caplen: %u\n", header->caplen);
    //printf("Payload size: %d bytes\n", payload_length);
    //printf("Memory address where payload begins: %p\n\n", payload_ptr);



void print_arp_header(struct ether_arp *header)
{
    printf("ARP Header:\n");
    printf("\t ARP OP %d\n", ntohs(header->ea_hdr.ar_op));
    printf("\tHardware Type: %d\n", ntohs(header->ea_hdr.ar_hrd));
    printf("\tProtocol Type: %d\n", ntohs(header->ea_hdr.ar_pro));
    printf("\tHardware Length: %d\n", ntohs(header->ea_hdr.ar_hln));
    printf("\tProtocol Length: %d\n", ntohs(header->ea_hdr.ar_pln));
    printf("\tOperation: %d\n", ntohs(header->ea_hdr.ar_op));
    int i;
    printf("\tSender Hardware Address: ");
    for (i = 0; i < ETH_ALEN; ++i)
    {
        printf("%d", header->arp_sha[i]);
        if (i < ETH_ALEN - 1)
        {
            printf(":");
        }
    }

    printf("\n\tSender Protocol Address: ");
    for (i = 0; i < 4; ++i)
    {
        printf("%d", header->arp_spa[i]);
        if (i < 3)
        {
            printf(":");
        }
    }

    printf("\n\tTarget Hardware Address: ");
    for (i = 0; i < ETH_ALEN; ++i)
    {
        printf("%02x", header->arp_tha[i]);
        if (i < ETH_ALEN - 1)
        {
            printf(":");
        }
    }

    printf("\n\tTarget Protocol Address: ");
    for (i = 0; i < 4; ++i)
    {
        printf("%d", header->arp_tpa[i]);
        if (i < 3)
        {
            printf(":");
        }
    }
    printf("\n");
}
