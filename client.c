#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <mcrypt.h>

#define RECEIVE_BUFFER_SIZE 1024
#define INPUT_BUFFER_SIZE 1
#define LOG_BUFFER_SIZE 1024

struct termios saved_attributes, new_attributes;
int log_fd;
char cr_lf[2] = {0x0D, 0x0A};
static int encrypt_flag;
MCRYPT td;

void reset_input_mode (void)
{
  tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
}



void set_input_mode (void)
{
  if (tcgetattr(STDIN_FILENO, &saved_attributes) == -1) {
    fprintf(stderr, "Cannot get terminal attributes.\n");
    exit(EXIT_FAILURE);
  }

  new_attributes = saved_attributes;
  atexit(reset_input_mode);
  new_attributes.c_lflag &= ~(ICANON | ECHO);
  new_attributes.c_cc[VMIN] = 1;
  new_attributes.c_cc[VTIME] = 0;
  if (tcsetattr(STDIN_FILENO, TCSANOW, &new_attributes) == -1) {
    fprintf(stderr, "cannot output to the terminal.\n");
    exit(EXIT_FAILURE);
  }
}

//subroutine for the new thread
void *read_input(void *startroutine)
{
  int *sockfd = (int *)startroutine;
  char buf[RECEIVE_BUFFER_SIZE+1];
  char logbuf[LOG_BUFFER_SIZE];

  while (1) {
    int size = read(*sockfd, buf, RECEIVE_BUFFER_SIZE);
    if (size > 0) {
	buf[size] = 0;
	if (log_fd > 0) {
	  //log message
	  int logsize = sprintf(logbuf, "RECEIVED %d bytes: %s\n", size, buf);
	  if ( write(log_fd, logbuf, logsize) == -1) {
	    fprintf(stderr, "fail to write the log message.");
	    exit(EXIT_FAILURE);
	  }
	}
    	//encryption case need to be handled here.
	if (encrypt_flag) {
	  mdecrypt_generic(td, buf, size);
	}
	if (write(1, buf, size) <= 0) {
	  fprintf(stderr, "failed to write.\n");
	  exit(EXIT_FAILURE);
	}
      }
    else
      exit(0);   
  }
}




int main(int argc, char **argv)
{
  int c;
  int sockfd, portno;
  struct sockaddr_in serveraddr;
  //struct hostent *server;
  //char *hostname = "local host";

  static struct option long_options[] = {
    {"encrypt", no_argument,   &encrypt_flag, 'e'},
    {"port",    required_argument, 0,         'p'},
    {"log",     required_argument, 0,         'l'}
  };

  while (1) {
    int option_index = 0;
    c = getopt_long (argc, argv, "ep:l:", long_options, &option_index);
    if ( c == -1)
      break;
    switch(c) {
    case 'p':
      portno = atoi(optarg);
      break;
    case 'l':
      log_fd = creat(optarg, 0666);
      break;
    }
  }
  
  set_input_mode();
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Error opening socket");
    exit(0);
  }

  // server = gethostbyname(hostname);
  // if (server == NULL) {
  //  fprintf(stderr, "Error finding host");
  //  exit(0);
  //
  //}
  
  //build the server's internet address.
  memset((char *) &serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(portno);
  serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");

  //connect to the server
  if (connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
    perror("error establishing connection to server");
    exit(0);
  }
  
  pthread_t server_input;
  pthread_create(&server_input, NULL, read_input, &sockfd);


  //setup encryption after input.
  int i;
  char *key;
  char password[20];
  char *IV;
  int keysize = 16;

  if (encrypt_flag) {
    key = calloc(1, keysize);
    int key_fd = open("my.key", O_RDONLY);
    if (key_fd < 0) {
      perror("fail opening key file.");
      exit(1);
    }

    int read_size = read(key_fd, password, 20);
    password[read_size] = 0;
    memmove(key, password, strlen(password));
    td = mcrypt_module_open("blowfish", NULL, "cfb", NULL);
    if (td == MCRYPT_FAILED) {
      perror("Mcrypt failed.");
      exit(1);
    }
    IV = malloc(mcrypt_enc_get_iv_size(td));

    for ( i = 0; i < mcrypt_enc_get_iv_size(td); i++) {
      IV[i] = rand();
    }
    i = mcrypt_generic_init(td, key, keysize,IV);
    if (i < 0) {
      perror("key generation error.");
      exit(1);
    }
  }
 
  
  char input_buffer[INPUT_BUFFER_SIZE];
  char logbuffer[LOG_BUFFER_SIZE];
  
  while (1) {
    

    int nchar = read(0, input_buffer, INPUT_BUFFER_SIZE);
    input_buffer[nchar] = 0;
    int i;
    for (i = 0; i < nchar; i++ ) {
      if(input_buffer[i] == 0x04)
	exit(0);
      else if (*(input_buffer+i) == 0x0A || *(input_buffer+i) == 0x0D)
	write(STDOUT_FILENO, cr_lf, 2);
      else {
	if(write(STDOUT_FILENO, input_buffer+i, 1) < 0)
	  exit(1);
      }
    }
    
    
    if (encrypt_flag) {
      mcrypt_generic(td, input_buffer, strlen(input_buffer));
    }
    
    int nchar_sent;
    nchar_sent = write(sockfd, input_buffer, nchar);
    if (nchar_sent < 0) {
      perror("error sending to socket.\n");
      exit(EXIT_FAILURE);
    }
    
    if (log_fd > 0) {
      int log_size_sent = sprintf(logbuffer, "SENT %d bytes: %s\n", nchar_sent, input_buffer);
      write(log_fd, logbuffer, log_size_sent);
    }
    
    
  }
  return 0;
}	  

  
  
	    
	    
	    
	    
	    
