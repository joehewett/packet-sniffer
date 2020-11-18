#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include "growingarray.h"
#include <pcap.h>

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose,
              Array *syn_ips,
              Array *arp_responses);

#endif
