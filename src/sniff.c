
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <unistd.h>

#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"
#include "growingarray.h"


// Application main sniffing loop
void sniff(char *interface, int verbose) {

    // Create the syn_counter array that will be used to store information wrt syn attacks
    initialise_syn_counter(); 

    create_threads(10);

    // Create signal handler to catch Ctrl+C so we can process packets
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        printf("Error creating signal handler");
        exit(1); 
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

    struct pcap_pkthdr header;
    const unsigned char *packet;
    
    while (1) {
        // Capture a  packet
        packet = pcap_next(pcap_handle, &header);
        unsigned char * new_packet = malloc(header.caplen);
        memcpy(new_packet, packet, header.caplen);

        if (packet == NULL) {
            // pcap_next can return null if no packet is seen within a timeout
            if (verbose) {
                printf("No packet received. %s\n", pcap_geterr(pcap_handle));
            }
        } else {
            // Optional: dump raw data to terminal
            if (verbose) {
                dump(new_packet, header.len);
            }
            // Dispatch packet for processing
            dispatch(&header, new_packet, verbose);
        }
        //free(new_packet);
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

int get_unique_syn_ips() {
    int i, k, is_unique, unique_count = 0; 
    
    // Create an array that we can store unique IPs in
    Array unique_syns; 
    array_create(&unique_syns, 1); 

    // Iterate over the array of IP addresses and find the uniques. Store unique IPs in unique_syns
    for (i = 0; i < syn_counter.used; i++) {
        is_unique = 1; 
        for (k = 0; k < unique_syns.used; k++) {
            if (unique_syns.array[k] == syn_counter.array[i]) {
                is_unique = 0;
                break; 
            }
        }
        if (is_unique) {
            array_add(&unique_syns, syn_counter.array[i]); 
        }
    }

    // Free up the memory then return the count of unique IPs that sent SYN packets
    unique_count = unique_syns.used; 
    array_delete(&unique_syns);
    return unique_count;  
}

// Called in the sigHandler function - prints out SYN/ARP/Blacklist info before exiting
void print_statistics() {
    int uniques = get_unique_syn_ips(); 
    printf("\n%d SYN packets detected from %d different IPs ", syn_counter.used, get_unique_syn_ips());
    if (uniques == 1) {
        printf("(unlikely to be a SYN attack) \n");
    } else {
        printf("(could be a SYN attack) \n");
    }
    printf("%d ARP responses\n", arp_counter);
    printf("%d Blacklist responses\n", blacklist_counter);
}

