/*
 * hash-service: a service for hashing FTP streams 
 *
 * PROTOCOL: Connect to command port (8556)
 * -> ASCII, line based protocol
 * Only supported commands:
 * HASH [port]\r\n
 * where [port] is a valid port number.
 *
 * QUIT
 * Disconnects.
 *
 * the hash service will connect to the port, listen,
 * and sha256 hash the incoming TCP stream.
 * The hash service does not support multiple hashing jobs within
 * the same TCP session.
 *
 * The final sha256 hash will be sent on a newline as an ascii hex string
 * (lowercase) after a 201 status response
 *
 * 201 Success\r\n
 * d390b8237b393875d968c7e5703685d37782d1b5c26b2d30839c3115ba1f3e73\r\n
 *
 * Status responses:
 * Format [STATUS CODE] String Description
 * 500 Bad Request
 * 400 Internal Error
 * 401 No Data
 * 201 Success
 *
 *
 * Known issues: 
 *
 * -> connect() takes far too long to time out by default,
 * so commanding the server to hash on a port that isn't open takes
 * over a minute to return an error code
 * https://stackoverflow.com/a/2597669
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "sha256.h"


char* hash_to_string(const unsigned char*);

void hash_file(const char *filename, unsigned char* hash) {
    SHA256_CTX ctx;
    sha256_init(&ctx);    

    FILE* file; 
    if ((file = fopen(filename, "r")) == NULL) {
        perror("hash-service: error opening file in hash_file:");
    }

    unsigned char read_buf[64];
    int read_size;
    while((read_size = fread(read_buf, 1, sizeof(read_buf), file)) != 0) {
        sha256_update(&ctx, read_buf, read_size);
    }

    sha256_final(&ctx, hash);
    
    if (fclose(file) != 0) {
        perror("hash-service: error closing file in hash_file");
    }
}

int hash_fd(int fd, unsigned char* hash) {
    SHA256_CTX ctx;
    sha256_init(&ctx);    

    unsigned char read_buf[64];
    int read_size;
    while((read_size = read(fd, read_buf, sizeof(read_buf))) > 0) {
        sha256_update(&ctx, read_buf, read_size);
    }

    if (read_size < 0) {
        return -1;
    }

    sha256_final(&ctx, hash);

    return 0;
}

char* hash_to_string(const unsigned char *hash) {
    static char str[65];
    bzero(str, sizeof(str));
    char* write_ptr = str;
    for(int i = 0; i < 32; i++) {
        sprintf(write_ptr, "%02x", (uint8_t)hash[i]); 
        write_ptr += 2;
    } 
    return str;
}

void populate_sockaddr(struct sockaddr_in * addr, int port, char* ip) {
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_aton(ip, &addr->sin_addr);
}

typedef struct {
    char line[1024];
    char* endptr;
} LineBuffer;

void init_line_buffer(LineBuffer* buf) {
    buf->endptr = buf->line;
}

//purge current line from buffer and shift in rest of buffer
void consume_line(LineBuffer* buf) {
    memcpy(buf->line, buf->endptr, 1024 - (buf->endptr - buf->line));
}

//buffer line from socket buffer
//returns 0 if no line found, 1 if line found
int get_sock_line(LineBuffer* buf, char* read_buf, size_t read_buf_size) {

    static char* i = NULL;
    if (i == NULL) {
        i = read_buf;
    }

    for (; i < read_buf + read_buf_size - 1; i++) {

        //reset ptr if it goes beyond the buffer
        if (buf->endptr - buf->line >= sizeof(buf->line)) {
            buf->endptr = buf->line;
        }

        //detect \r\n
        if (*i == '\r' && *(i+1) == '\n') {
            i++;
            *buf->endptr = '\0';
            buf->endptr = buf->line;

            return 1;
        } 

        *buf->endptr++ = *i;
    }

    i = NULL;
    return 0;
}

void* control_session(void* arg) {
    int sock = *(int*)arg;

    LineBuffer line_buffer;
    init_line_buffer(&line_buffer);

    char buf[1024];
    int read_sz;
    while ((read_sz = recv(sock, buf, sizeof(buf), 0)) > 0) {
        while(get_sock_line(&line_buffer, buf, read_sz)) {
            char* syntax_err = "500 Bad Request\r\n";
            char* internal_err = "400 Internal Error\r\n";
            char* nodata_err = "401 No Data\r\n";
            char* success = "200 Success\r\n";

            if (strcmp("QUIT", line_buffer.line) == 0) {
                read_sz = 0;
                goto end;
            }

            if (strcmp("HASH", strtok(line_buffer.line, " "))) {
                if (send(sock, syntax_err, strlen(syntax_err), 0) < 0) {
                    perror("hash-service: error sending 500 Bad Request");
                }
                continue;
            }

            char* arg;
            if ((arg = strtok(NULL, " ")) == NULL) {
                if (send(sock, syntax_err, strlen(syntax_err), 0) < 0) {
                    perror("hash-service: error sending 500 Bad Request");
                }
                continue;
            }
            char* endptr;
            int port = strtol(arg, &endptr, 10);
            if (*endptr != '\0') {
                if (send(sock, syntax_err, strlen(syntax_err), 0) < 0) {
                    perror("hash-service: error sending 500 Bad Request");
                }
                continue;
            }

            //connect to port and commence hashing!
            int ftp_socket = socket(AF_INET, SOCK_STREAM, 0);
            if (ftp_socket == -1) {
                perror("hash-service: ftp socket creation failed");
                if (send(sock, internal_err, strlen(internal_err), 0) < 0) {
                    perror("hash-service: error sending 400 Internal Error");
                }
                continue;
            }

            struct sockaddr_in addr;
            populate_sockaddr(&addr, port, "127.0.0.1");
            
            struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

            if (setsockopt (ftp_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0) {
                perror("hash-service: setsockopt failed");
            }

            /*
            if (setsockopt (ftp_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0) {
                perror("hash-service: setsockopt failed");
            }
            */

            if (connect(ftp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                perror("hash-service: ftp connection failed");
                if (send(sock, internal_err, strlen(internal_err), 0) < 0) {
                    perror("hash-service: error sending 400 Internal Error");
                }
                continue;
            }

            unsigned char hash[32];
            if (hash_fd(ftp_socket, hash)) {
                switch (errno) {
                    case EWOULDBLOCK:
                        fprintf(stderr, "ftp connection timed out\n");
                        break;
                    default:
                        perror("hash-service: ftp connection");
                }
                if (send(sock, nodata_err, strlen(nodata_err), 0) < 0) {
                    perror("hash-service: error sending 401 No Data");
                }
                if(close(ftp_socket)) {
                    perror("hash-service: error closing ftp socket");
                }
                continue;
            }
            char hashdump[70];
            sprintf(hashdump, "%s\r\n", hash_to_string(hash));

            if (send(sock, success, strlen(success), 0) < 0) {
                perror("hash-service: error sending 200 Success");
            }
            if (send(sock, hashdump, strlen(hashdump), 0) < 0) {
                perror("hash-service: error sending hexdump");
            }

            if(close(ftp_socket)) {
                perror("hash-service: error closing ftp socket");
            }
            
        }
    }

end:

    switch (read_sz) {
    case 0:
        printf("Client disconnected\n");
        break;
    default:
        switch (errno) {
        case EWOULDBLOCK:
            fprintf(stderr, "Client timed out\n");
            break;
        default:
            perror("hash-service: control socket receive failed");
        }
    }
    
    return NULL; 
}


void run_server(int ftp_server_port, int upload_port) {
    //wait for connection from client
    int client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        perror("hash-service: socket create failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    populate_sockaddr(&addr, upload_port, "0.0.0.0");

    if (bind(client_sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("hash-service: bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(client_sockfd, 5) < 0) {
        perror("hash-service: listen failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in in_addr;
    socklen_t in_len = sizeof(in_addr);
    int insocket;

    while ((insocket = 
        accept(client_sockfd, (struct sockaddr*)&in_addr, &in_len)) != -1) {
        
        //configure timeouts on new socket
        struct timeval timeout;
        timeout.tv_sec = 90;
        timeout.tv_usec = 0;

        if (setsockopt (insocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
            sizeof(timeout)) < 0) {
            perror("hash-service: setsockopt failed");
        }

        if (setsockopt (insocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
            sizeof(timeout)) < 0) {
            perror("hash-service: setsockopt failed");
        }

        pthread_t control_thread;

        printf("Creating control thread for client at %s:%d\n",
                inet_ntoa(in_addr.sin_addr), ntohs(in_addr.sin_port));

        if (pthread_create(&control_thread, NULL, control_session, &insocket)) {
            perror("hash-service: pthread_create failed");
        }
        else {
            void* retval;
            if (pthread_join(control_thread, &retval) < 0) { 
                perror("hash-service: pthread_join failed");
            }
            printf("Thread terminated\n");
        }

        if (close(insocket) < 0) {
            perror("hash-service: close failed");
        }

    }

    perror("hash-service: accept failed");
    
    
}

void upload(char* hostname, int port) {
     
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "ligma lmao\n");
        exit(EXIT_FAILURE);
    }
    /*
    unsigned char hash[32];
    hash_file(argv[1], hash);
    printf("%s\n", hash_to_string(hash));
    */
    run_server(21, 8009);
    return 0;
}
