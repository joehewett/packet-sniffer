#include "growingarray.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

// An implementation of a growing array  

void array_create(Array *arr, size_t start_size) {
  arr->array = malloc(start_size * sizeof(int));
  arr->used = 0;
  arr->size = start_size;
}

// Add an item to the array
// Checks if used==size and then expands the array by *2 if true
void array_add(Array *arr, int element) {
  if (arr->used == arr->size) {
    arr->size *= 2;
    arr->array = realloc(arr->array, arr->size * sizeof(int));
  }
  arr->array[arr->used++] = element;
}

// Free up the array memory and reset
void array_delete(Array *arr) {
    free(arr->array);
    arr->array = NULL;
    arr->used = arr->size = 0;
}