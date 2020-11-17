#include "growingarray.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void initArray(Array *a, size_t initialSize) {
  a->array = malloc(initialSize * sizeof(int));
  a->used = 0;
  a->size = initialSize;
  printf("Initialising array\n");
}

void insertArray(Array *a, int element) {
  // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
  // Therefore a->used can go up to a->size 
  if (a->used == a->size) {
    a->size *= 2;
    a->array = realloc(a->array, a->size * sizeof(int));
  }
  a->array[a->used++] = element;
  printf("Inserting into array...\n");
}

void freeArray(Array *a) {
    free(a->array);
    a->array = NULL;
    a->used = a->size = 0;
}

//int main(int argc, char *argv[]) {
//    Array a;
//    int i;

//    initArray(&a, 5);  // initially 5 elements
//    for (i = 0; i < 100; i++) {
//        insertArray(&a, i);  // automatically resizes as necessary
//        printf("array %u is: %u\n", i, a.array[i]);   
//    }
        
//    printf("%d\n", a.array[9]);  // print 10th element
//    printf("%d\n", a.used);  // print number of elements
//    freeArray(&a);
//   return 0;
//}
