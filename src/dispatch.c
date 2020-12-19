#include "dispatch.h"
#include "analysis.h"
#include "sniff.h"
#include "growingarray.h"
#include "threadqueue.h"

#include <stdlib.h>
#include <pcap.h>
#include <pthread.h> 

struct queue *packet_queue; // Main queue that threads are going to pick from
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for the queue
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER; // Condition lock that will have to be waited for by threads 

pthread_t tid[THREAD_COUNT]; // Num threads - Would be cool to make this dynamic based on load

volatile int thread_switch; 

// Thread function
void *analyse_packet(void *arg) {

    // Get a fresh packet pointer so we can load in the packet from the queue
    const unsigned char *packet_ptr = NULL; 

    // Loop until we get the signal to die 
    while (thread_switch == 1) {
        // Lock the queue 
        pthread_mutex_lock(&queue_mutex);
        if (!thread_switch) {
            return NULL;
        }
        // Wait while the queue is empty
        // Is the thread_switch is 0 but queue is not empty we'll still process the jobs in the queue
        while (isempty(packet_queue)) {  
            if (!thread_switch) {
                // Unlock our mutex before we leave and broadcast to the other threads to wakeup
                pthread_mutex_unlock(&queue_mutex);
                pthread_cond_broadcast(&queue_cond);
                return NULL; 
            }
            // Wait for the queue condition to be signalled - this happens when a packet is added the the queue
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        //printf("After while loop, processing packet..\n");
        // Get the packet from the queue that just got added
        packet_ptr = packet_queue->head->item;
        dequeue(packet_queue);
        // Once we have the item, release the queue mutex and set about processing it
        pthread_mutex_unlock(&queue_mutex);
        analyse(packet_ptr, 1);
    } 

    return NULL;
}

// Called at runtime to initially create the desired number of threads
void create_threads(int thread_count) {
    packet_queue = create_queue(); 

    thread_switch = 1; 

    int i;
    for (i = 0; i < thread_count; i++){
		pthread_create(&tid[i], NULL, analyse_packet, NULL);
	}
}

// Called from sniff when we get a packet from pcap 
void dispatch(u_char *verbose, struct pcap_pkthdr *header, const unsigned char *packet) {
    if (thread_switch == 1) {
        // Lock the queue before we add the packet
        pthread_mutex_lock(&queue_mutex);
        enqueue(packet_queue, packet);
        // Signal to any waiting threads that a new packet has been added so that they wake up
        // Need to be careful about Spurious Wakeup here. 
        pthread_cond_signal(&queue_cond);
        // Drop the queue mutex once we've queued and signaled
        pthread_mutex_unlock(&queue_mutex);
    }
}

// Catch system signals and do some processing prior to exiting 
void sig_handler(int signo) {
    thread_switch = 0; 

    // Broadcast to wake up all threads. They will exit their thread functions since thread_switch is 0. 
    int i = 0;
    pthread_cond_broadcast(&queue_cond);
    // Join all threads back to main
    for (i = 0; i < THREAD_COUNT; i++) {
        pthread_join(tid[i], NULL);
    }

    print_statistics(); 
    pcap_close(pcap_handle); 
    array_delete(&syn_counter);
    free(packet_queue);
    exit(0); 
}
