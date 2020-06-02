#include <stdio.h>

typedef struct {
    FILE* file;
    size_t line_length;
    char* static_line;
    char* buffer;
    size_t buffer_sz;
} VirtualFd;

void init_vfd(VirtualFd* vfd, FILE* file, size_t line_length);
void destroy_vfd(VirtualFd* vfd);
void vfd_printf_static(VirtualFd* vfd, const char* static_format, ...);
void vfd_printf(VirtualFd* vfd, const char* format, ...);
