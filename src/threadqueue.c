#include <stdio.h>
#include <stdlib.h>
#include "threadqueue.h"

struct queue *create_queue(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

int isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, const unsigned char *item){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->item = item;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

void dequeue(struct queue *q){ //dequeues a the head node
  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
  }
}

void printqueue(struct queue *q){
    if(isempty(q)){
        printf("The queue is empty\n");
    }
    else{
        struct node *read_head;
        read_head=q->head;
        printf("The queue elements from head to tail are:\n");
        printf("%d",read_head->item);
        while(read_head->next!=NULL){
            read_head=read_head->next;
            printf("--> %d",read_head->item);
        }
        printf("\n");
    }
}

// int main(){
//     struct queue *work_queue;
//     work_queue=create_queue();
//     enqueue(work_queue,2);
//     enqueue(work_queue,3);
//     enqueue(work_queue,1);
//     enqueue(work_queue,1);
//     printqueue(work_queue);
//     dequeue(work_queue);
//     dequeue(work_queue);
//     printqueue(work_queue);
//     return 0;
// }