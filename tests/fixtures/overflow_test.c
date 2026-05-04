/* CWE-122 test: heap buffer overflow */

/* Declarations for standalone cross-compilation (resolved at runtime by Qiling/rootfs) */
void* malloc(unsigned long);
void free(void*);
void* memcpy(void*, const void*, unsigned long);

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
