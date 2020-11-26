#ifndef CS241_GROWINGARRAY_H
#define CS241_GROWINGARRAY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Array Array; 

struct Array {
  int *array;
  size_t used;
  size_t size;
};

void array_create(Array *a, size_t initialSize);
void array_add(Array *a, int element);
void array_delete(Array *a);

#endif
