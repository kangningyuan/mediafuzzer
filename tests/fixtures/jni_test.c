/* JNI test SO: uses JNI functions and memory allocation */

/* Declarations for standalone cross-compilation (resolved at runtime by Qiling/rootfs) */
void* malloc(unsigned long);
void free(void*);
void* memcpy(void*, const void*, unsigned long);

/* Simulated JNI types for standalone compilation */
typedef void* JNIEnv;
typedef void* jobject;
typedef unsigned char jbyte;
typedef int jint;
typedef void* jbyteArray;

/* Simulated JNI functions */
jint GetArrayLength(JNIEnv* env, jbyteArray array) {
    return 64;
}

jbyte* GetByteArrayElements(JNIEnv* env, jbyteArray array, jint* isCopy) {
    return (jbyte*)malloc(64);
}

void ReleaseByteArrayElements(JNIEnv* env, jbyteArray array, jbyte* elems, jint mode) {
    free(elems);
}

jbyteArray NewByteArray(JNIEnv* env, jint size) {
    return (jbyteArray)malloc(size);
}

/* JNI function that processes byte array */
jint Java_com_test_JniProcessor_processData(
    JNIEnv* env, jobject obj, jbyteArray data, jint len
) {
    jint array_len = GetArrayLength(env, data);
    jbyte* bytes = GetByteArrayElements(env, data, (jint*)0);

    jbyte* buf = (jbyte*)malloc(64);
    if (buf && bytes && len <= 64) {
        memcpy(buf, bytes, len);
    }

    if (buf) free(buf);
    ReleaseByteArrayElements(env, data, bytes, 0);

    return 0;
}
