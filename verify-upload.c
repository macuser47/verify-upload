/*
 * verify-upload: a verification layer for FTP transfers
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
#include "sha256.h"

typedef struct {
    int client_fd;
    int server_fd;
} ProxyPair;

char* hash_to_string(const unsigned char*);

void hash_file(const char *filename, unsigned char* hash) {
    SHA256_CTX ctx;
    sha256_init(&ctx);    

    FILE* file; 
    if ((file = fopen(filename, "r")) == NULL) {
        perror("verify-upload: error opening file in hash_file:");
    }

    unsigned char read_buf[64];
    int read_size;
    while((read_size = fread(read_buf, 1, sizeof(read_buf), file)) != 0) {
        sha256_update(&ctx, read_buf, read_size);
    }

    sha256_final(&ctx, hash);
    
    if (fclose(file) != 0) {
        perror("verify-upload: error closing file in hash_file");
    }
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

enum state_t {WAITING_FOR_HASH = 0, WAITING_FOR_PASV = 1, HASHING = 3};
enum state_t proxy_state = WAITING_FOR_HASH;
char file_to_hash[64];

void* proxy_thread(void* arg) {
    ProxyPair* p = (ProxyPair*)arg;

    LineBuffer line_buffer;
    init_line_buffer(&line_buffer);

    char buf[1024];
    int read_sz;
    while((read_sz = recv(p->client_fd, buf, sizeof(buf), 0)) > 0) {

        char* consume_ptr = buf; //offset to consume lines not for ftp server
        size_t consumed_sz = 0;

        //check if complete line buffered
        while (get_sock_line(&line_buffer, buf, read_sz)) {
            printf("Got \"%s\"\n", line_buffer.line);

            //decide if buffer should be purged
            size_t length = strlen(line_buffer.line);

            if (strncmp("HASH", strtok(line_buffer.line, " "), 4) == 0) {

                //hash command consumes line. 
                //respond to hash and
                //shift buffer over.
                consume_ptr += length + 1;
                consumed_sz += length + 1;
                
                char* hash_target;
                if ((hash_target = strtok(NULL, " ")) == NULL) {
                    //send error back to client
                    char* error = "500 Bad Request\r\n";
                    if (send(p->client_fd, error, strlen(error), 0) < 0) {
                        perror("verify-upload: error sending 500 to client");
                    }
                    continue;
                }
                strncpy(file_to_hash, hash_target, sizeof(file_to_hash));

                //issue PWD to server
                char* pwd_buf = "PWD\r\n";
                if (send(p->server_fd, pwd_buf, strlen(pwd_buf), 0) < 0) {
                    perror("verify-upload: error sending PWD\n");
                    continue;
                }
                proxy_state = WAITING_FOR_PASV;

            }
        }

        memmove(buf, consume_ptr, 1024 - consumed_sz); 

        send(p->server_fd, buf, read_sz - consumed_sz, 0);
    }

    switch (read_sz) {
    case 0:
        printf("Client closed connection\n");
        break;
    default:
        perror("verify-upload: reverse proxy error");
        return NULL;
    }

    return NULL; 
}

void* reverse_proxy_thread(void* arg) {
    ProxyPair* p = (ProxyPair*)arg;

    LineBuffer line_buffer;
    init_line_buffer(&line_buffer);

    char buf[1024];
    int read_sz;
    while((read_sz = recv(p->server_fd, buf, sizeof(buf), 0)) > 0) {
        //intercept PWD reads
        if (proxy_state == WAITING_FOR_PASV) {
            while (get_sock_line(&line_buffer, buf, read_sz)) {
                char* error = 
                    "451 Requested action aborted: local error in processing.\r\n";

                char* success = "200 Success\r\n";

                char* response_code_str = strtok(line_buffer.line, " ");
                char* endptr;

                int response_code = strtol(response_code_str, &endptr, 10); 
                if (*endptr != '\0') {
                    perror("verify-upload: bad response from ftp server");
                    send(p->client_fd, error, strlen(error), 0); 
                    continue;
                }

                if (response_code != 257) {
                    send(p->client_fd, error, strlen(error), 0); 
                    continue;
                }

                printf("%s\n", strtok(NULL, "\""));

                /*if (strcmp("", strtok(NULL, "\"")) != 0) {
                    send(p->client_fd, error, strlen(error), 0); 
                    continue;
                }*/
                
                send(p->client_fd, success, strlen(success), 0);
                proxy_state = WAITING_FOR_HASH; 
            }
        }
        else {
            send(p->client_fd, buf, read_sz, 0); 
        }
    }

    switch (read_sz) {
    case 0:
        printf("FTP server closed connection\n");
        break;
    default:
        perror("verify-upload: reverse proxy error");
        return NULL;
    }

    return NULL;
}

void run_server(int ftp_server_port, int upload_port) {
    //wait for connection from client
    int client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        perror("verify-upload: socket bind failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    populate_sockaddr(&addr, upload_port, "0.0.0.0");

    if (bind(client_sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("verify-upload: bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(client_sockfd, 5) < 0) {
        perror("verify-upload: listen failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in in_addr;
    socklen_t in_len = sizeof(in_addr);
    int insocket;

    while ((insocket = 
        accept(client_sockfd, (struct sockaddr*)&in_addr, &in_len)) != -1) {

        int server_sockfd;
        pid_t pid = fork();
        switch (pid){
        case -1:
            perror("verify-upload: fork failed");
            exit(EXIT_FAILURE);
        case 0:
            //make connection to server on connection init    
            server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

            struct sockaddr_in server_addr;
            populate_sockaddr(&server_addr, ftp_server_port, "68.187.67.135");
    
            if (connect(server_sockfd, 
                (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                perror("verify-upload: ftp connect failed");
                exit(EXIT_FAILURE);
            }

            ProxyPair p = {
                .client_fd = insocket,
                .server_fd = server_sockfd
            };

            pthread_t proxy_t, reverse_proxy_t;

            if(pthread_create(&reverse_proxy_t, NULL, 
                reverse_proxy_thread, &p)) {
                perror("verify-upload: reverse proxy thread creation failed");
                exit(EXIT_FAILURE);
            }
            if(pthread_create(&proxy_t, NULL, proxy_thread, &p)) {
                perror("verify-upload: proxy thread creation failed");
                exit(EXIT_FAILURE);
            }

            //wait for threads :)
            void* retval;
            if (pthread_join(proxy_t, &retval)) {
                perror("verify-upload: proxy thread join failed");
                exit(EXIT_FAILURE);
            }
            if (pthread_join(reverse_proxy_t, &retval)) {
                perror("verify-upload: reverse proxy thread join failed");
                exit(EXIT_FAILURE);
            }
            
            printf("Process closing (%d). Goodbye world!\n", getpid()); 
            exit(EXIT_SUCCESS);

            break;
        default:
            printf(
                "Created child process %d to handle connection from %s\n",
                pid,
                inet_ntoa(in_addr.sin_addr)
            );
            break;

        }

    }

    perror("verify-upload: accept failed");
    
    
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
