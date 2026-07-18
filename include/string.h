#ifndef _STRING_H_
#define _STRING_H_

typedef unsigned long size_t;

#ifdef __cplusplus
extern "C" {
#endif

void* memcpy(void* dst, const void* src, size_t n);
void* memmove(void* dst, const void* src, size_t n);
void* memset(void* dst, int val, size_t n);

char* strrchr(const char* str, int c);
char* strchr(const char* str, int c);
int strncmp(const char* str1, const char* str2, size_t n);
int strcmp(const char* str1, const char* str2);
char* strncat(char* dst, const char* src, size_t n);
char* strncpy(char* dst, const char* src, size_t n);
char* strcpy(char* dst, const char* src);
size_t strlen(const char* str);
char* strtok(char* str, const char* delim);

#ifdef __cplusplus
}
#endif

char* strcat(char* dst, const char* src, size_t n);

#endif
