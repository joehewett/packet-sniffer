#include <stdio.h>
#include <stdlib.h>
#include "threadqueue.h"

// A modification of Arpan's threadpool model queue structure

// Create a new queue
struct queue *create_queue(void) { 
    struct queue *q = (struct queue *) malloc(sizeof(struct queue));
    q->head = NULL;
    q->tail = NULL;
    return(q);
}

int isempty(struct queue *q){ 
    return(q->head == NULL);
}

// Add an item to the tail node
void enqueue(struct queue *q, const unsigned char *item) {
    struct node *new_node = (struct node *) malloc(sizeof(struct node));
    new_node->item = item;
    new_node->next = NULL;
    if (isempty(q)) {
        q->head = new_node;
        q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }
}

// Remove the item at the head node
void dequeue(struct queue *q) { //dequeues a the head node
    struct node *head_node;
    if (isempty(q)) {
        printf("Error: attempt to dequeue from an empty queue");
    } else {
        head_node = q->head;
        q->head = q->head->next;
        if(q->head == NULL) {
            q->tail = NULL;
        }
        free(head_node);
    }
}