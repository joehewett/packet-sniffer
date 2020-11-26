struct node { // data structure for each node
  const unsigned char *item;
  struct node *next;
};

struct queue { // data structure for queue
  struct node *head;
  struct node *tail;
};

struct queue *create_queue(void);
int isempty(struct queue *q);
void enqueue(struct queue *q, const unsigned char *item);
void dequeue(struct queue *q);


