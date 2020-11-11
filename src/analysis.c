#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  // TODO your part 2 code here
  
  struct ether_header * eth_header = (struct ether_header *) packet;
  unsigned short ethernet_type = ntohs(eth_header->ether_type);
  unsigned short ethernet_desthost = ntohs(eth_header->ether_dhost);
  unsigned short ethernet_sourcehost = ntohs(eth_header->ether_shost);
  printf("Ethernet Type: %hu\n", ethernet_type);
  printf("Ethernet Dest Host 1: %u\n", (unsigned int)ethernet_desthost);
  printf("Ethernet Source Host: %u\n", (unsigned int)ethernet_sourcehost);

  printf("size of packet = %u\n", sizeof(packet));
  struct tcphdr * tcp_header = (struct tcphdr *) packet + sizeof(eth_header); 
  //unsigned short syn_bit = ntohs(tcp_header->syn);
  printf("SYN FLAG is %u\n", tcp_header->syn);
  printf("ACK FLAG is %u\n", tcp_header->ack);
  printf("RST FLAG is %u\n", tcp_header->rst);
  printf("FIN FLAG is %u\n", tcp_header->fin);
  
  printf("TCP Source %u\n", tcp_header->source);
  printf("TCP Dest %u\n", tcp_header->dest);
}
