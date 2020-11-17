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

void initArray(Array *a, size_t initialSize);
void insertArray(Array *a, int element);
void freeArray(Array *a);

#endif
