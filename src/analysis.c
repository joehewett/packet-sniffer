#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  // TODO your part 2 code here
  
  struct ether_header * eth_header = (struct ether_header *) header;
  unsigned short ethernet_type = ntohs(eth_header->ether_type);
  printf("\nType: %hu\n", ethernet_type);

  struct tcphdr * tcp_header = (struct tcphdr *) header; 
  //unsigned short syn_bit = ntohs(tcp_header->syn);
  //printf("SYN FLAG is %u\n", syn_bit);

}
