#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include "growingarray.h"
#include <pcap.h>

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose,
              Array *syn_ips,
              Array *arp_responses);

#endif
