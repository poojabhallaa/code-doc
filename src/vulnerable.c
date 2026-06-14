#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* CWE-476: NULL Pointer Dereference */
void print_value(int *ptr) {
    printf("%d\n", *ptr);
}

/* CWE-121: Stack-based Buffer Overflow via gets() */
void read_username() {
    char buf[64];
    gets(buf);   /* semgrep: c.lang.security.insecure-use-gets-fn */
    printf("Hello, %s\n", buf);
}

/* CWE-120: Buffer Overflow via strcpy() */
void copy_input(const char *input) {
    char dest[32];
    strcpy(dest, input);   /* semgrep: c.lang.security.insecure-use-string-copy-fn */
    printf("%s\n", dest);
}

/* CWE-134: Uncontrolled Format String */
void log_message(char *msg) {
    printf(msg);   /* semgrep: c.lang.security.insecure-use-printf-fn */
}

int main() {
    /* NULL pointer dereference */
    int *p = NULL;
    print_value(p);

    /* Stack overflow via gets */
    read_username();

    /* Buffer overflow via strcpy */
    copy_input("this string is definitely longer than thirty-two characters and will overflow");

    /* Format string vulnerability */
    char user_input[] = "%s%s%s%s%s";
    log_message(user_input);

    return 0;
}
