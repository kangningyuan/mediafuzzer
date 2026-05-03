/* CWE-416 test: use-after-free */

#include <stdlib.h>

/* Vulnerable: accesses memory after free */
int use_after_free(int trigger) {
    int* p = (int*)malloc(sizeof(int) * 4);
    if (!p) return -1;

    p[0] = 42;
    free(p);

    /* Use after free: read from freed memory */
    if (trigger) {
        return p[0];  // UAF
    }
    return 0;
}
