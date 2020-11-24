#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <unistd.h>

#include "dispatch.h"
#include "growingarray.h"

// Global so that we can access it from the signal handler 
Array syn_ips;
Array arp_responses; 

int getUniqueSynIPs() {
    int i, k, is_unique, unique_count = 0; 
    
    // Create an array that we can store unique IPs in
    Array unique_syns; 
    initArray(&unique_syns, 1); 

    // Iterate over the array of IP addresses and find the uniques. Store unique IPs in unique_syns
    for (i = 0; i < syn_ips.used; i++) {
        is_unique = 1; 
        for (k = 0; k < unique_syns.array[k]; k++) {
            if (unique_syns.array[k] == syn_ips.array[i]) {
                is_unique = 0;
                printf("Found an IP k=%d, i=%d that is not unique: %d\n", k, i, syn_ips.array[i]);
                break; 
            }
        }
        if (is_unique) {
            insertArray(&unique_syns, syn_ips.array[i]); 
        }
    }

    // Free up the memory then return the count of unique IPs that sent SYN packets
    unique_count = unique_syns.used; 
    freeArray(&unique_syns);
    return unique_count;  
}

// Called in the sigHandler function - prints out SYN/ARP/Blacklist info before exiting
void printStatistics() {
    printf("%d SYN packets detected from %d different IPs\n", syn_ips.used, getUniqueSynIPs());
    printf("%d ARP responses\n", arp_responses.used);
}

// Catch system signals and do some processing prior to exiting 
void sigHandler(int signo) {
    printStatistics(); 
    freeArray(&syn_ips);
    freeArray(&arp_responses);
    exit(0); 
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
    // Initialise the syn_ips and arp arrays with a few slots so that we can add items to it later
    initArray(&syn_ips, 4); 
    initArray(&arp_responses, 4);


    //create the worker threads
    printf("Creating threads..\n");
    create_threads(10);



    // Create signal handler to catch Ctrl+C so we can process packets
    if (signal(SIGINT, sigHandler) == SIG_ERR) {
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
    
    //while (1) {
    //    printf("In while loop...\n");
    //    // Capture a  packet
    //    packet = pcap_next(pcap_handle, &header);
    //    if (packet == NULL) {
    //    // pcap_next can return null if no packet is seen within a timeout
    //        if (verbose) {
    //            printf("No packet received. %s\n", pcap_geterr(pcap_handle));
            }
    //    } else {
        // Optional: dump raw data to terminal
    //        if (verbose) {
    //            dump(packet, header.len);
    //        }
    //        // Dispatch packet for processing
    //        printf("Calling dispatch with packet #### %d ####\n", packet);
    //        dispatch(&header, packet, verbose, &syn_ips, &arp_responses);
    //    }
    //}
    pcap_loop(pcap_handle, -1, (pcap_handler) dispatch, (u_char*) &verbose);
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
