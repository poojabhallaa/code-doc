#include <stdio.h>
#include <stdlib.h>

int main() {
    int n;
    printf("Enter number of elements: ");
    scanf("%d", &n);
    int size = n * sizeof(int);

    int *arr = (int *)malloc(size);

    if (arr == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    printf("Memory allocated for %d elements\n", n);

    free(arr);
    return 0;
}
