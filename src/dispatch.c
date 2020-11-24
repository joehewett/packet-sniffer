#include "dispatch.h"
#include "analysis.h"
#include "growingarray.h"
#include "threadqueue.h"

#include <stdlib.h>
#include <pcap.h>
#include <pthread.h> 

struct queue *work_queue; 
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

const unsigned char* packet_ptr;
pthread_t tid[10]; 

void *analyse_packet(void *arg) {
    return NULL;

    printf("In thread function for thread %d, acquiring queue lock...\n", (int)pthread_self());
    pthread_mutex_lock(&queue_mutex);

    while (isempty(work_queue)) {  
        printf("Queue is empty, thread %d is waiting for queue cond/mutex...\n", (int)pthread_self());
        pthread_cond_wait(&queue_cond, &queue_mutex);
        printf("Queue has an item in it! thread %d has acquired queue mutex\n", (int)pthread_self());
        printqueue(work_queue);
    }

    packet_ptr = work_queue->head->item;
    dequeue(work_queue);
    printf("Thread %d has taken an item from the queue for processing, poggers\n", (int)pthread_self());
    pthread_mutex_unlock(&queue_mutex);
    printf("Thread %d has released the queue mutex\n", (int)pthread_self());

    printqueue(work_queue);
    printf("Thread %d would have called anaylse for packet: %d\n", (int)pthread_self(), packet_ptr);
    //analyse(header, packet, verbose, syn_ips, arp_responses);
    // Call to analyse with packet 
    // Returns array with 3 entries: SYN, ARP, Blacklist
    // Get a hold of official array and add to it
    return NULL; 
}

// Called at runtime to initially create the desired number of threads
void create_threads(int thread_count) {
    return NULL;
    work_queue = create_queue(); 
    printf("Creating %d initial threads...\n", thread_count);
    
    int i;
    for (i = 0; i < thread_count; i++){
        printf("Creating thread %d\n", i);
		pthread_create(&tid[1], NULL, analyse_packet, NULL);
	}
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose,
              Array *syn_ips,
              Array *arp_responses) {

    printf("Dispatch has been called\n");

    pthread_mutex_lock(&queue_mutex);
    printf("Got mutex lock on the queue\n");
    enqueue(work_queue, packet);
    printf("Queued the packet %d\n", packet);
    pthread_cond_signal(&queue_cond);
    printf("Sent queue condition signal\n");
    pthread_mutex_unlock(&queue_mutex);
    printf("Dropped mutex lock on queue");


    //analyse(header, packet, verbose, syn_ips, arp_responses);
}
