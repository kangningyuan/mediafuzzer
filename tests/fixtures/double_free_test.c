/* CWE-415 test: double free */

#include <stdlib.h>

/* Vulnerable: frees memory twice */
int double_free(int trigger) {
    char* p = (char*)malloc(32);
    if (!p) return -1;

    p[0] = 'A';
    free(p);

    if (trigger) {
        free(p);  // Double free
    }
    return 0;
}
