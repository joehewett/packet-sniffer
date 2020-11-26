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

int thread_switch; 

// Thread function
void *analyse_packet(void *arg) {

    // Get a fresh packet pointer so we can load in the packet from the queue
    unsigned char *packet_ptr = NULL; 

    // Loop indefinitely 
    while (1) {
        // Lock the queue 
        pthread_mutex_lock(&queue_mutex);
        // Wait while the queue is empty - when a job gets added we will send a queue cond and wake up the thread
        while (isempty(packet_queue)) {  
            if (thread_switch == 0) {
                break; 
            }
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        if (thread_switch == 0) {
            break; 
        }

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
void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

    // Lock the queue before we add the packet
    pthread_mutex_lock(&queue_mutex);
    enqueue(packet_queue, packet);
    // Signal to any waiting threads that a new packet has been added so that they wake up
    // Need to be careful about Spurious Wakeup here. 
    pthread_cond_signal(&queue_cond);

    // Drop the queue mutex once we've queued and signaled
    pthread_mutex_unlock(&queue_mutex);
}

// Catch system signals and do some processing prior to exiting 
void sig_handler(int signo) {
    thread_switch = 0; 

    pthread_cond_broadcast(&queue_cond);
    // This is where we would join the threads back to main if it was necessary
    //int i = 0;
    //for (i = 0; i < THREAD_COUNT; i++) {
    //    pthread_join(tid[i], NULL);
    //}

    print_statistics(); 
    array_delete(&syn_counter);
    exit(0); 
}
