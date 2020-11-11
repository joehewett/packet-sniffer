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
  unsigned short ethernet_desthost = ntohs((unsigned int)eth_header->ether_dhost);
  unsigned short ethernet_sourcehost = ntohs((unsigned int)eth_header->ether_shost);
  printf("Ethernet Type: %hu\n", ethernet_type);
  printf("Ethernet Dest Host 1: %u\n", (unsigned int)ethernet_desthost);
  printf("Ethernet Source Host: %u\n", (unsigned int)ethernet_sourcehost);

  printf("size of packet = %u\n", (unsigned int)packet);

  const unsigned char *payload = packet + ETH_HLEN;

  printf("tcp pointer = %u\n", (unsigned int)payload);

  struct tcphdr * tcp_header = (struct tcphdr *) payload; 
  //unsigned short syn_bit = ntohs(tcp_header->syn);
  printf("SYN FLAG is %u\n", tcp_header->syn);
  printf("ACK FLAG is %u\n", tcp_header->ack);
  printf("RST FLAG is %u\n", tcp_header->rst);
  printf("FIN FLAG is %u\n", tcp_header->fin);
  printf("RES1 FLAG is %u\n", tcp_header->res1);
  printf(
        "Sender:      %02X:%02X:%02X:%02X\n",
        payload[0],payload[1],payload[2],payload[3],
    );

  printf("TCP Source %u\n", ntohs(tcp_header->source));
  printf("TCP Dest %u\n", ntohs(tcp_header->dest));
}
