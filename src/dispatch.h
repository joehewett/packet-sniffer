#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include "growingarray.h"
#include <pcap.h>

#define THREAD_COUNT 10 //Some default value

void create_threads(int thread_count);
void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);
void sig_handler(int signo); 

#endif
