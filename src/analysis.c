#include "analysis.h"
#include "growingarray.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if_arp.h>

void print_arp_header(struct ether_arp *header);

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose, Array *syn_ips, Array *arp_responses) {
    // TODO:
    // When a packet has SYN=1, add it and the IP to the dynamically growing array

    // Lengths of the headers so we can find the next headers
    int eth_header_length = ETH_HLEN; 
    int ip_header_length; 
    int tcp_header_length;
    int payload_length; 

    // Pointers to the start of the headers we're interested in
    const unsigned char *eth_header_ptr = packet;
    const unsigned char *ip_header_ptr = packet + eth_header_length;
    const unsigned char *tcp_header_ptr;  
    const unsigned char *payload_ptr;

    // If the protocol isn't TCP, then we're not interested in this packet 
    // We can get the protocol being used in the packet in the IP header at byte 9
    u_char protocol = *(ip_header_ptr + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Protocol is not TCP... Checking if ARP...\n");
        struct ether_arp * eth_arp_header = (struct ether_arp *) ip_header_ptr;
        if (ntohs(eth_arp_header->ea_hdr.ar_op) == ARPOP_REPLY) {
            printf("This is an ARPOP_REPLY");
            insertArray(arp_responses, 1);
        }
        print_arp_header(eth_arp_header);
        //return;
    }

    // ip header length is contained in the second-half of the first byte of the ip_header
    // So bitwise logical AND with 00001111 to wipe any preceding bits in the byte
    ip_header_length = ((*ip_header_ptr) & 0x0F); 
    // IHL is stored in 32 bit segments so multiply by 4 to get the byte count
    ip_header_length = ip_header_length * 4;

    struct iphdr * ip_header = (struct iphdr *) ip_header_ptr;
    ip_header_length = (ip_header->ihl) * 4;
    // TCP header is after ethernet header (14 bytes) and ip header
    tcp_header_ptr = ip_header_ptr + ip_header_length; 
    // The TCP header length is stored in the first half of the 12th byte
    // Do a bitwise AND with 11110000 then shift the result 4 bits to the right
    
    tcp_header_length = ((*(tcp_header_ptr + 12 )) & 0xF0) >> 4;
    // Same as IP - multiply by 4 to get byte count
    tcp_header_length = tcp_header_length * 4; 
    
    // Use the tcp header pointer to a instantiate a tcphdr struct
    struct tcphdr * tcp_header = (struct tcphdr *) tcp_header_ptr; 

    // Get the syn bit using the tcphdr struct
    printf("SYN FLAG is %u\n", tcp_header->syn);

    // If the TCP header has SYN=1 then store it in our dynamic array
    // On exit, we will iterate over and get unique IPs, but for now store all. 
    if (tcp_header->syn) {
        insertArray(syn_ips, ntohs(ip_header->saddr)); 
    }
    
    int total_headers_size = eth_header_length + ip_header_length + tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    printf("Size of header caplen: %u\n", header->caplen);
    payload_length = header->caplen - (eth_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload_ptr = packet + total_headers_size;
    //printf("Memory address where payload begins: %p\n\n", payload_ptr);

}

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
