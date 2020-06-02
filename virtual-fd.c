/*
 * Virtual stdout that enables normal stdout write capabilities
 * as well as a configurable static final terminal line
 *
 * Note that the nature of particular file streams like stdout
 * precludes the ability to wrap fflush().
 * Flushing will happen only on \n
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "virtual-fd.h"

#define LINEBUFFER_SIZE 4096

void init_vfd(VirtualFd* vfd, FILE* file, size_t line_length) {
    vfd->file = file;
    vfd->line_length = line_length;
    vfd->static_line = calloc(LINEBUFFER_SIZE, sizeof(char)); 
    vfd->buffer = malloc(LINEBUFFER_SIZE);
    vfd->buffer_sz = 0;
}


void destroy_vfd(VirtualFd* vfd) {
    free(vfd->static_line);
    free(vfd->buffer);
}


//Implement line buffer as circular buffer
//wrapping around truncates the buffer - data is lost!
//don't overflow the buffer :)
void buffer_append(VirtualFd* vfd, const char* data) {
    for (;(vfd->buffer[vfd->buffer_sz++] = *(data++));
        vfd->buffer_sz %= (LINEBUFFER_SIZE-1));
    vfd->buffer_sz += (LINEBUFFER_SIZE - 2);
    vfd->buffer_sz %= (LINEBUFFER_SIZE - 1);
}


/*
 * vfd printf equivalent for static field
 */
void vfd_printf_static(VirtualFd* vfd, const char* static_format, ...) {
    va_list args;
    va_start(args, static_format);

    vsnprintf(vfd->static_line, LINEBUFFER_SIZE, static_format, args);

    fprintf(vfd->file, "\r%s", vfd->static_line);
    fflush(vfd->file);

    va_end(args);
}


void purge_line(VirtualFd* vfd) {
    fprintf(vfd->file, "\r");
    for (int i = 0; i < vfd->line_length; i++) {
        fprintf(vfd->file, " ");
    }
}


/*
 * printf wrapper for vfds
 */
void vfd_printf(VirtualFd* vfd, const char* format, ...) {
    va_list args;
    va_start(args, format);

    char printf_buf[LINEBUFFER_SIZE];

    //append to buffer
    //custom handling for newlines - since we can't go backward in the buffer,
    //we can't write unterminated lines -- we need to buffer them.
    vsnprintf(printf_buf, LINEBUFFER_SIZE, format, args);
    buffer_append(vfd, printf_buf);

    //check for newline in format, print buffer if found
    for (char* p = vfd->buffer; p < &vfd->buffer[vfd->buffer_sz]; p++) {
        if (*p == '\n') {
            //purge current line based on width
            purge_line(vfd);

            //print line
            *p = '\0'; //separate line within buffer
            int line_length = strlen(vfd->buffer);
            fprintf(vfd->file, "\r%s\n", vfd->buffer);

            //write static line
            fprintf(vfd->file, "%s", vfd->static_line);


            //move the rest of the buffer up if necessary
            if (p == &vfd->buffer[LINEBUFFER_SIZE-1]) {
                vfd->buffer_sz = 0;
                fflush(vfd->file);
                va_end(args);
                return;
            }
            memmove(vfd->buffer, p+1, LINEBUFFER_SIZE-(vfd->buffer_sz));

            vfd->buffer_sz -= (line_length+1);
            p = vfd->buffer;
        }
    }
    fflush(vfd->file);

    va_end(args);
}
