#include <stdio.h>
#include <string.h>

/* Intentionally vulnerable training sample. Never expose this service. */
static void greet(void) {
    char name[32];
    puts("Name?");
    gets(name);                 /* Deliberately unsafe for scanner demonstration. */
    printf("Hello, %s\n", name);
}

int main(void) {
    greet();
    return 0;
}
