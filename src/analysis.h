#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include "growingarray.h"
#include <pcap.h>

extern Array syn_counter;
extern volatile int arp_counter; 
extern volatile int blacklist_counter;

void initialiseSynCounter(); 

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
