/* CWE-122 test: heap buffer overflow */

#include <stdlib.h>
#include <string.h>

/* Vulnerable: copies input without checking buffer size */
int vulnerable_copy(const unsigned char* input, int len) {
    char* buf = (char*)malloc(16);
    if (!buf) return -1;

    /* Buffer overflow: len can exceed 16 */
    memcpy(buf, input, len);

    int result = buf[0];
    free(buf);
    return result;
}
