#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

extern pcap_t *pcap_handle; 

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);
void print_statistics();
int get_unique_syn_ips();

#endif
