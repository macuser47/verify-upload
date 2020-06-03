/*
 * verify-upload: a verification layer for FTP transfers
 *
 * What follows is a loathsome piece of code that should not rightfully exist.
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
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <libgen.h>
#include "sha256.h"
#include "virtual-fd.h"

#define PROGRAM_NAME "verify-upload"
#define AUTHOR "Nic Hodlofski"
#define VERSION "1.0"
#define SITE "https://github.com/macuser47/verify-upload"

#define SERVICE_NAME 0
#define USER_REPLY 1
#define PASS_REPLY 2
#define MODE_REPLY 3
#define TYPE_REPLY 4
#define PASV_REPLY 5
#define STOR_REPLY 6
#define COMPLETE_REPLY 7
#define PASV2_REPLY 8
#define RETR_REPLY 9
#define RETR_REPLY2 10
    
enum {LOUD, QUIET, NORMAL} loudness = NORMAL;

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

void progress_bar(const int total, const int progress, const int length, 
        char** bar_string) {

    if (*bar_string == NULL) {
        *bar_string = malloc(length + 1);
    } 
    else {
        *bar_string = realloc(*bar_string, length + 1);
    }

    int fill_length = (int)(((double)progress / total) * length);
    int i;
    for (i = 0; i < fill_length - 1; (*bar_string)[i++]='=');
    (*bar_string)[i++] = '>';
    for (; i < length; (*bar_string)[i++]=' ');
    (*bar_string)[i] = '\0';
}


/*int get_sock_line(int fd) {
    //brrt
    int status;
    for (char c = 0, int i = 0; c != '\n ; i++) {
        status = recv(fd, &c, 1, MSG_PEEK);

        if (status < 0) {
            return status;
        }
    }

    return i;
}*/

typedef struct {
    char line[1024];
    char* endptr;
    char* readptr;
} LineBuffer;

void init_line_buffer(LineBuffer* buf) {
    buf->endptr = buf->line;
    buf->readptr = NULL;
}

//buffer line from socket buffer
//returns 0 if no line found, 1 if line found
int get_sock_line(LineBuffer* buf, char* read_buf, size_t read_buf_size) {
    if (buf->readptr == NULL) {
        buf->readptr = read_buf;
    }

    for (; buf->readptr < read_buf + read_buf_size - 1; buf->readptr++) {

        //reset ptr if it goes beyond the buffer
        if (buf->endptr - buf->line >= sizeof(buf->line)) {
            buf->endptr = buf->line;
        }

        //detect \r\n
        if (*buf->readptr == '\r' && *(buf->readptr+1) == '\n') {
            buf->readptr++;
            *buf->endptr = '\0';
            buf->endptr = buf->line;

            return 1;
        } 

        *buf->endptr++ = *buf->readptr;
    }

    buf->readptr = NULL;
    return 0;
}

//gets response code
//clobbers string
//returns -1 on error
int response_code(char* reply) {
    char* arg;
    if ((arg = strtok(reply, " ")) == NULL) {
        return -1;     
    }
    char* endptr;
    int code = strtol(arg, &endptr, 10);
    if (*endptr != '\0') {
        return -1;
    }
    return code;
}

enum ResponseType { FTP_CONTINUE, FTP_SUCCESS, FTP_NEED_MORE, 
    FTP_INTERNAL_ERROR, FTP_FAIL};

enum ResponseType response_type(int code) {
    int code_prefix = code / 100;
    switch (code_prefix) {
    case 1:
        return FTP_CONTINUE;
    case 2:
        return FTP_SUCCESS;
    case 3:
        return FTP_NEED_MORE;
    case 4:
        return FTP_INTERNAL_ERROR;
    case 5:
        return FTP_FAIL;
    }
    return -1;
}

struct FtpCredentials {
    char* uname;
    char* passwd;
};

struct FtpCredentials default_credentials = {"ftp", "ftp"};

int human_order(const long int bytes) {
    if (bytes >> 50) {
        return 50;
    }
    if (bytes >> 40) {
        return 40;
    }
    if (bytes >> 30) {
        return 30;
    }
    if (bytes >> 20) {
        return 20;
    }
    if (bytes >> 10) {
        return 10;
    }
    return 0;
}

void apply_human_order(const long int bytes, int order, char* buf, size_t size) {
    switch (order) {
    case 0:
        snprintf(buf, size, "%ldB", bytes);
        return;
    case 10:
        snprintf(buf, size,"%ldKB", bytes >> 10);    
        return;
    case 20:
        snprintf(buf, size, "%ldMB", bytes >> 20);
        return;
    case 30:
        snprintf(buf, size, "%ldGB", bytes >> 30);
        return;
    case 40:
        snprintf(buf, size, "%ldTB", bytes >> 40);
        return;
    case 50:
        snprintf(buf, size, "%ldPB", bytes >> 50);
        return;
    }
}

void apply_human_order_float(const long int bytes, int order, char* buf, size_t size) {
    switch (order) {
    case 0:
        snprintf(buf, size, "%0.2fB", (float)bytes);
        return;
    case 10:
        snprintf(buf, size,"%0.2fKB", (float)bytes / (1 << 10));    
        return;
    case 20:
        snprintf(buf, size, "%0.2fMB", (float)bytes / (1 << 20));
        return;
    case 30:
        snprintf(buf, size, "%0.2fGB", (float)bytes / (1 << 30));
        return;
    case 40:
        snprintf(buf, size, "%0.2fTB", (float)bytes / ((long int)1 << 40));
        return;
    case 50:
        snprintf(buf, size, "%0.2fPB", (float)bytes / ((long int)1 << 50));
        return;
    }
}

void bytes_to_human_f(const long int bytes, char* buf, size_t size) {
    apply_human_order_float(bytes, human_order(bytes), buf, size);
}

void bytes_to_human(const long int bytes, char* buf, size_t size) {
    apply_human_order(bytes, human_order(bytes), buf, size);
}

//write progress bar to the screen 
//returns time in seconds sice last call
double write_progress(VirtualFd* vstdout, long int accum_sent, 
        long int filesize, int width) {
    static struct timespec last_time;
    static long int last_accum = 0;
    
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);

    double elapsed_time = (time.tv_sec - last_time.tv_sec) + 
        ((time.tv_nsec - last_time.tv_nsec) / 1000000000.0);
    last_time = time;


    double marginal_bytes = (double)(accum_sent - last_accum);
    last_accum = accum_sent;

    double speed = marginal_bytes / elapsed_time;

    char speed_human[16];
    char accum_human[16];
    char size_human[16];

    char data_line[24];
    char* bar_string = NULL;

    int size_order = human_order(filesize);
    bytes_to_human_f(filesize, size_human, sizeof(size_human));

    int accum_order = human_order(accum_sent);
    bytes_to_human_f(accum_sent, accum_human, sizeof(accum_human));

    //truncate unit if order matches
    if (accum_order == size_order) {
        char* endptr;
        strtod(accum_human, &endptr);
        *endptr = '\0';
    }
    else { //truncate decimal otherwise
        char* endptr;
        strtol(accum_human, &endptr, 10);

        char* dec_endptr;
        strtod(accum_human, &dec_endptr);

        strcpy(endptr, dec_endptr);
    }

    bytes_to_human_f(speed, speed_human, sizeof(speed_human));

    snprintf(data_line, sizeof(data_line), "%s/%s %s/s", accum_human, size_human,
            speed_human);

    //create progress bar
    progress_bar(filesize, accum_sent, width - (strlen(data_line)+2), 
        &bar_string);

    if (loudness != QUIET) {
        vfd_printf_static(vstdout, "[%s]%s", bar_string, data_line);
    }
    free(bar_string);

    return elapsed_time;
}

//hash and upload files :)
//returns 0 on success, -1 on error
int ftp_stream_upload(int pasv_fd, char* path, int bufsize) {

    //open path
    FILE* file; 
    if ((file = fopen(path, "r")) == NULL) {
        perror("verify-upload: error opening file for upload");
        return -1;
    }

    //get file size for progress bar
    struct stat stats;
    if (fstat(fileno(file), &stats) < 0) {
        perror("verify-upload: error statting file for upload");
        return -1;
    }

    off_t filesize = stats.st_size;
    
    //set up vfd
    struct winsize win;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
    
    VirtualFd vstdout;
    if (loudness != QUIET) {
        init_vfd(&vstdout, stdout, win.ws_col);
    }


    //dynamic memory so we can support lil' ram computers and still
    //have sane speeds on normal pcs
    char* buf = malloc(bufsize);
    long long int accum_sent = 0;
    int read_size;

    int actual_size = 1 << 10; //start at 1k and double until write time is ~0.5s

    while((read_size = fread(buf, 1, actual_size, file)) != 0) {
        double q;
        if((q = write_progress(&vstdout, accum_sent, filesize, win.ws_col)) < 0.5) {
            if (actual_size * 1.2 < bufsize) {
                actual_size *= 1.2;
            }
            else {
                actual_size = bufsize;
            }
            /*
            char buf[24];
            bytes_to_human(actual_size, buf, sizeof(buf));
            vfd_printf(&vstdout, "Buffer size: %s\n", buf);
            */
        }

        if (send(pasv_fd, buf, read_size, 0) < 0) {
            perror("verify-upload: error sending file data");
            free(buf);
            return -1; 
        }
        accum_sent += read_size;
    }
    write_progress(&vstdout, accum_sent, filesize, win.ws_col);

    free(buf);

    fclose(file);
    close(pasv_fd);
    return 0;
}

//parse ftp pasv line to sockaddr_in
int parse_pasv_response(char* response, struct sockaddr_in* addr) {
    char* pasv_tuple_str;
    if ((pasv_tuple_str = strchr(response, '(') + 1) == NULL) {
        return -1;
    }
                
    uint8_t pasv_tuple[6];
    char* tuple_head = pasv_tuple_str;
    char* endptr;
    for (int i = 0; i < 6; i++) {
        pasv_tuple[i] = strtol(tuple_head, &endptr, 10);
        if (i < 5 && *endptr != ',') {
            return -1;
        }
        else if (i == 5 && *endptr != ')') {
            return -1;
        }
        tuple_head = endptr + 1;
    }

    char pasv_ip[24];
    snprintf(pasv_ip, sizeof(pasv_ip), "%d.%d.%d.%d", 
            pasv_tuple[0], pasv_tuple[1], pasv_tuple[2], pasv_tuple[3]);

    int port = pasv_tuple[4] << 8 | pasv_tuple[5];

    populate_sockaddr(addr, port, pasv_ip);
    return 0;
}

//connect to hashing service and hash file
int hashservice_hash(struct sockaddr_in* addr, int commandport, char** hash_string) {
    //use ftp error codes because they're the same for hashservice 
    int hash_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (hash_fd == -1) {
        perror("verify-upload: error creating hash service socket");
        return -1;
    }

    if (connect(hash_fd, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) < 0) { 
        perror("verify-upload: error connecting to hash service");
        return -1;
    }

    //send request
    char cmd[30];
    snprintf(cmd, sizeof(cmd), "HASH %d\r\n", commandport);

    if (loudness == LOUD) {
        printf("Sending \"%s\" to hash service\n", cmd);
    }

    if (send(hash_fd, cmd, strlen(cmd), 0) < 0) {
        perror("verify-upload: error sending hash request");
        return -1;
    }

    //wait for response
    LineBuffer line_buf;
    init_line_buffer(&line_buf);

    char buf[1024];
    int line = 0;
    int read_sz;
    while((read_sz = recv(hash_fd, buf, sizeof(buf), 0)) > 0) {
        while(get_sock_line(&line_buf, buf, read_sz) > 0) { 
            if (loudness == LOUD) {
                printf("Got line: %s\n", line_buf.line);
            }

            enum ResponseType hash_resp;

            switch(line++) {
            case 0:
                //get status code
                if ((hash_resp = response_type(response_code(line_buf.line))) < 0) {
                    fprintf(stderr, "Bad response from hash sever: %s\n", 
                        strtok(NULL, "\0"));
                    close(hash_fd);
                    return -1;
                }

                if (hash_resp != FTP_SUCCESS) {
                   fprintf(stderr, "Bad response code from hash sever: %s\n",
                        strtok(NULL, "\0"));
                    close(hash_fd);
                    return -1;
                }
                break;

            case 1:
                //get hash string :)
                *hash_string = malloc(strlen(line_buf.line));
                strcpy(*hash_string, line_buf.line);

                close(hash_fd);
                return 0;
            }
        }
    }

    switch (read_sz) {
    case 0:
        fprintf(stderr, "Hash server connection closed unexpectedly\n");
        break;
    default:
        perror("verify-upload: error negotiating with hash server");
    }


    return -1;
}

//uploads file to ftp server using PASV, mode S, type L 8
int upload(char* hostname, int port, struct FtpCredentials creds, 
        char* filename, char* path) {
    int returncode = 0;

    //connect to ftp server
    int ftp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ftp_fd < 0) {
        perror("verify-upload: error creating ftp connection");
        return -1;
    }

    //TODO: support DNS w/gethostbyname(3)
    struct sockaddr_in addr;
    populate_sockaddr(&addr, port, hostname);

    if (connect(ftp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("verify-upload: error connecting to ftp server");
        return -1;
    }
    
    int pasv_fd;
    struct sockaddr_in pasv2_addr;
    char* hash_response; 
 
    LineBuffer line_buf;
    init_line_buffer(&line_buf);

    char buf[1024];
    int line = 0;
    int read_sz;

    //round counter to indicate 
    //which ftp session is taking place
    //0 - upload session
    //1 - hash verification session
    int round = 0;
    while((read_sz = recv(ftp_fd, buf, sizeof(buf), 0)) > 0) {
        while(get_sock_line(&line_buf, buf, read_sz) > 0) { 
            if (loudness == LOUD) {
                printf("Got line: %s\n", line_buf.line);
            }
            
            enum ResponseType ftp_resp;
            if ((ftp_resp = response_type(response_code(line_buf.line))) < 0) {
                fprintf(stderr, "verify-upload: bad response from sever");
                returncode = -1;
                goto end;
            }

            char* errc = line_buf.line;
            char* rest_of_response = strtok(NULL, "\0");

            switch (line++) {
            case SERVICE_NAME:
                //read service name line
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "Bad response from server: %s %s\n",
                        errc, rest_of_response);
                    returncode = -1;
                    goto end;
                }
                else {
                    if (loudness == LOUD) {
                        printf("Connected to ftp server: %s\n", rest_of_response);
                    }
                }

                //reply with user login
                char user_cmd[64];
                snprintf(user_cmd, sizeof(user_cmd), "USER %s\r\n", creds.uname);
                if (send(ftp_fd, user_cmd, strlen(user_cmd), 0) < 0) {
                    perror("verify-upload: error sending user login");
                    returncode = -1;
                    goto end;
                }
                break;
            case USER_REPLY:
                //check response code
                if (ftp_resp != FTP_SUCCESS && ftp_resp != FTP_NEED_MORE) {
                    fprintf(stderr, "verify-upload: bad response code to login: %s\n",
                            errc);
                    returncode = -1;
                    goto end;
                }

                //send password
                char pwd_cmd[64];
                snprintf(pwd_cmd, sizeof(user_cmd), "PASS %s\r\n", creds.passwd);
                if (send(ftp_fd, pwd_cmd, strlen(pwd_cmd), 0) < 0) {
                    perror("verify-upload: error sending user login");
                    returncode = -1;
                    goto end;
                }
                break;

            case PASS_REPLY:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to password: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }
                if (loudness == LOUD) {
                    printf("Successfuly logged in as %s\n", creds.uname);
                }

                //send mode configuration
                char* mode_cmd = "MODE S\r\n";
                if (send(ftp_fd, mode_cmd, strlen(mode_cmd), 0) < 0) {
                    perror("verify-upload: error sending mode");
                    returncode = -1;
                    goto end;
                }
                break;

            case MODE_REPLY:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to mode change: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                //send data type configuration
                char* type_cmd = "TYPE L 8\r\n";
                if (send(ftp_fd, type_cmd, strlen(type_cmd), 0) < 0) {
                    perror("verify-upload: error sending type");
                    returncode = -1;
                    goto end;
                }
                
                if (round == 1) {
                    line = COMPLETE_REPLY;
                }

                break;

            case TYPE_REPLY:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to mode change: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                //send pasv 
                char* pasv_cmd = "PASV\r\n";
                if (send(ftp_fd, pasv_cmd, strlen(pasv_cmd), 0) < 0) {
                    perror("verify-upload: error sending pasv");
                    returncode = -1;
                    goto end;
                }
                break;

            case PASV_REPLY:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to mode change: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                //parse pasv reply
                struct sockaddr_in pasv_addr;
                parse_pasv_response(rest_of_response, &pasv_addr);
                
                if (loudness == LOUD) {
                    printf("Configuring to PASV server at %s:%d\n", 
                            inet_ntoa(pasv_addr.sin_addr), ntohs(pasv_addr.sin_port));
                }

                //request upload for file
                char stor_cmd[64];
                snprintf(stor_cmd, sizeof(stor_cmd), "STOR %s\r\n", filename);
                if (send(ftp_fd, stor_cmd, strlen(stor_cmd), 0) < 0) {
                    perror("verify-upload: error sending stor command");
                    returncode = -1;
                    goto end;
                }

                //sleep needed for processing time...
                sleep(1);

                //connect to pasv port!
                if (loudness == LOUD) {
                    printf("Connecting to PASV server and uploading '%s' as '%s'\n",
                            path, filename);
                }

                pasv_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (pasv_fd < 0) {
                    perror("verify-upload: error creating pasv socket");
                    returncode = -1;
                    goto end;
                }

                if (connect(pasv_fd, (struct sockaddr*)&pasv_addr, sizeof(pasv_addr)) 
                        < 0) {
                    perror("verify-upload: error connecting to ftp pasv socket");
                    returncode = -1;
                    goto end;
                }
                
                if (loudness == LOUD) {
                    printf("Connected!\n");
                }
                break;

            case STOR_REPLY:
                if (ftp_resp != FTP_CONTINUE) {
                    fprintf(stderr, "bad response code to stor: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                //upload file!
                //default to 4M blocksize
                if (loudness == LOUD) {
                    printf("Uploading...\n");
                }
                if (ftp_stream_upload(pasv_fd, path, 1 << 22) < 0) {
                    fprintf(stderr, "Upload failed.");
                    returncode = -1;
                    goto end;
                }
                if (loudness == LOUD) {
                    printf("done!\n");
                }


                //disconnect and prepare for verification sesson
                //why? -> we can't assume this session hasn't timed out
                //(it will for large uploads)
                close(ftp_fd);
                round = 1;
                
                ftp_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (ftp_fd == -1) {
                    perror("verify-upload: error creating ftp2 socket");
                    return -1;
                }
                

                if (connect(ftp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                    perror("verify-upload: error connecting to ftp server (2)");
                    return -1;
                }

                line = SERVICE_NAME;
                break;

            //legacy name from before multi-session implementation
            case COMPLETE_REPLY:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to upload: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                //request PASV for hash verification
                char* pasv2_cmd = "PASV\r\n";
                if (send(ftp_fd, pasv2_cmd, strlen(pasv2_cmd), 0) < 0) {
                    perror("verify-upload: error sending pasv");
                    returncode = -1;
                    goto end;
                }
                break;

            case PASV2_REPLY:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to upload: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                //parse pasv data and populate addr for hash service
                parse_pasv_response(rest_of_response, &pasv2_addr);
                
                if (loudness == LOUD) {
                    printf("Configuring hash service to PASV server at %s:%d\n", 
                            inet_ntoa(pasv2_addr.sin_addr), ntohs(pasv2_addr.sin_port));
                }

                //set custom port, record old as command port
                int commandport = ntohs(pasv2_addr.sin_port);
                pasv2_addr.sin_port = htons(8009);

                //retrieve file from server
                char retr_cmd[64];
                snprintf(retr_cmd, sizeof(retr_cmd), "RETR %s\r\n", filename);
                if (send(ftp_fd, retr_cmd, strlen(retr_cmd), 0) < 0) {
                    perror("verify-upload: error sending retrieve command");
                    returncode = -1;
                    goto end;
                } 


                //conect to hash service to verify
                if (loudness == LOUD) {
                    printf("Connecting to hash service...\n");
                }
               
                if (hashservice_hash(&pasv2_addr, commandport, &hash_response) < 0) {
                    returncode = -1;
                    goto end;
                }
                if (loudness == LOUD) {
                    printf("Got hash response: %s\n", hash_response);
                }

                break;

            case RETR_REPLY:
                if (ftp_resp != FTP_CONTINUE) {
                    fprintf(stderr, "bad response code to upload: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }
                break;

            case RETR_REPLY2:
                if (ftp_resp != FTP_SUCCESS) {
                    fprintf(stderr, "bad response code to upload: %s\n",
                            line_buf.line);
                    returncode = -1;
                    goto end;
                }

                goto end;
                
            }
        }
    }

end:

    switch (read_sz) {
    case 0:
        if (loudness == LOUD) {
            printf("Disconnected from ftp server\n");
        }
        break;
    default:
        switch (errno) {
        case EWOULDBLOCK:
            fprintf(stderr, "Connection to ftp server timed out\n");
            break;
        default:
            if (loudness == LOUD) {
                printf("Connection to ftp server terminated.\n");
            }
            //perror("verify-upload: receive failed");
        }
    }

    close(ftp_fd);

    if (returncode) return returncode;

    //verify that the hashes match
    if (loudness != QUIET) {
        printf("Hashing local file...\n");
    }

    unsigned char hash[32];
    hash_file(path, hash);

    char* local_hash = hash_to_string(hash);
   
    if (loudness != QUIET) { 
        printf("Local hash:  %s\n", local_hash);
        printf("Remote hash: %s\n", hash_response);
    }

    if (strcmp(local_hash, hash_response) != 0) {
        fprintf(stderr, "Hash comparison failed!\n");
        return -1;
    }

    free(hash_response);

    return 0;
}

void usage(int status) {
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Usage: %s [OPTION...] --server [IP]:[PORT] [FILE...]\n", 
                PROGRAM_NAME);
        fprintf(stderr, "Try '%s --help' for more information.\n", PROGRAM_NAME); 
        exit(status);
    }

    printf("Usage: %s [OPTION...] --server <IP>:[PORT] [FILE...]\n", PROGRAM_NAME);
    fputs("\
\n\
Connection Setup:\n\
  -s, --server=IP:PORT          connect to the server given IP and port\n\
  -u, --user=USERNAME           connect to the server with the specified username\n\
                                (default: ftp)\n\
  -p, --password=PASSWORD       connect to the server with the specified password\n\
                                (default: will prompt for password)\n\
\n\
Configuration:\n\
  -r, --retries=RETRIES         number of times to retry upload before giving up\n\
                                (default: 5)\n\
  -q, --quiet                   suppress console output and progress bar\n\
  -l, --loud                    print connection status information\n\
\n\
Etc:\n\
  -v, --version                 print version information\n\
  -h, --help                    print this help message\n\
\n\
", stdout);
    printf("See <%s> for more information.\n", SITE);
    exit(status);
}

void version() {
    printf("%s v%s\n", PROGRAM_NAME, VERSION);
    printf("Written by %s\n", AUTHOR);
    exit(EXIT_SUCCESS);
}


int main(int argc, char* argv[]) {
    char* server = NULL;
    char* username = "ftp";
    char* password = NULL;
    int retries = 5;

    int opt;
    static struct option const long_options[] = {
        {"server",      required_argument,      NULL, 's'},
        {"user",        required_argument,      NULL, 'u'},
        {"password",    required_argument,      NULL, 'p'},
        {"retries",     required_argument,      NULL, 'r'},
        {"quiet",       no_argument,            NULL, 'q'},
        {"loud",        no_argument,            NULL, 'l'},
        {"version",     no_argument,            NULL, 'v'},
        {"help",        no_argument,            NULL, 'h'},
        {NULL,          0,                      NULL,  0 }
    };

    while ((opt = getopt_long(argc, argv, "s:u:p:r:qlvh", 
                    long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                server = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'r':;
                char* endptr;
                retries = strtol(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "%s: retries must be a number\n\n", PROGRAM_NAME);
                    usage(EXIT_FAILURE);
                }
                break;
            case 'q':
                loudness = QUIET;
                break;
            case 'l':
                loudness = LOUD;
                break;
            case 'v':
                version();
            case 'h':
                usage(EXIT_SUCCESS);
            default:
                fprintf(stderr, "\n");
                usage(EXIT_FAILURE);
        }
    }

    if (optind == argc) {
        fprintf(stderr, "%s: no files specified\n\n", PROGRAM_NAME);
        usage(EXIT_FAILURE);
    }

    if (server == NULL) {
        fprintf(stderr, "%s: no server specified\n\n", PROGRAM_NAME);
        usage(EXIT_FAILURE);
    }

    //parse server
    int server_len = strlen(server);

    char* ip = strtok(server, ":");
    int port = 21;

    if (strlen(ip) != server_len) {
        char* port_str = strtok(NULL, "\0");

        char* endptr;
        port = strtol(port_str, &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, "%s: invalid port\n\n", PROGRAM_NAME);
            usage(EXIT_FAILURE);
        }
    }

    //ask for password if not supplied
    while (password == NULL) {
        password = getpass("FTP Password: ");
    }

    struct FtpCredentials c = {.uname=username, .passwd=password};

    if (loudness) {}


    for (int i = optind; i < argc; i++) {
        char* local_path = argv[i];
        char* remote_name = basename(local_path);

        if (loudness != QUIET) {
            printf("Uploading %s\n", remote_name);
        }

        //try to upload and verify the file a maximum of 5 times
        for (int i = 0; i < retries; i++) {
            if(upload(ip, port, c, remote_name, local_path) == 0) {
                break;
            }

            if (i == retries - 1) {
                printf("Upload failed again. Something's borked. Aborting...\n");
                return EXIT_FAILURE;
            }

            printf("Upload failed, trying again (%d)...\n", i+1);
        }
    }

    return EXIT_SUCCESS;
}
