#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include "growingarray.h"
#include <pcap.h>

#define THREAD_COUNT 10 //Some default value

extern volatile int thread_switch;

void create_threads(int thread_count);
void dispatch(u_char *args, struct pcap_pkthdr *header, 
              const unsigned char *packet);
void sig_handler(int signo); 

#endif
