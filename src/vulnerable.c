#include <stdio.h>

int main() {
    char buffer[10];
    printf("Enter your name: ");
    gets(buffer);   // Vulnerable: no bounds checking
    printf("Hello %s\n", buffer);
    return 0;
}