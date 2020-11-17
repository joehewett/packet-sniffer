#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <unistd.h>

#include "dispatch.h"
#include "growingarray.h"

Array syn_ips; 

int process_syn_packets() {
    int total = 0; 
    int i; 
    for (i = 0; i < syn_ips.used; i++) {
        printf("Unique IP: %d\n", syn_ips.array[i]); 
    }
    return total;  
}

void sig_handler(int signo) {
  printf("\nProcessing before exiting..\n");
  int unique_syn_count = process_syn_packets();
  printf("SYN Packets with unique IP: %u\n", unique_syn_count);
  freeArray(&syn_ips);
  exit(0); 
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  initArray(&syn_ips, 5); 

  // Create signal handler to catch Ctrl+C so we can process packets
  if (signal(SIGINT, sig_handler) == SIG_ERR) {
    printf("Error creating signal handler");
  }
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // Capture packets (very ugly code)
  struct pcap_pkthdr header;
  const unsigned char *packet;
  while (1) {
    // Capture a  packet
    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // Optional: dump raw data to terminal
      if (verbose) {
        dump(packet, header.len);
      }
      // Dispatch packet for processing
      dispatch(&header, packet, verbose, &syn_ips);
    }
  }
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
