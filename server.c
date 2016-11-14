/* a TCP server */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <mcrypt.h>

#define INPUT_BUFFER_SIZE 1024
int encrypt_flag;
//later to implement pipes 
int pipe_from_shell[2];
int pipe_to_shell[2];
int shell_pid;
int shell_fd;

MCRYPT td;


//structs from in.h
/*
struct in_addr {
  unsigned int s_addr;
};

struct sockaddr_in {
  unsigned short int sin_family; //address family
  unsigned short int sin_port; //port number
  struct in_addr sin_addr; //IP address.
  unsigned char sin_zero[...]; //Pad to size of 'struct socketaddr.
};
*/

//struct from netdb.h
/*
struct hostent {
  char *h_name;
  char **h_aliases;
  int h_addrtype;
  int h_length;
  char **h_addr list;
};
*/

static void signal_handler(int signo)
{
  if(signo == SIGPIPE) {
    kill(shell_pid, SIGPIPE);
    exit(2);
  }
}


void *read_from_child(void* startroutine)
{
  char buffer[INPUT_BUFFER_SIZE];
  int *pipe = (int *)startroutine;

  while (1) {
    int read_size = read(*pipe, buffer, INPUT_BUFFER_SIZE);
    if (read_size > 0) {
      if (encrypt_flag) {
      	mcrypt_generic(td, buffer, read_size);
      }
      int write_size = write(1, buffer, read_size);
      if (write_size <= 0) {
	perror("cannot write to buffer");
	exit(1);
      }
    }
    else
      //error 
      exit(1);
  } 
}




void *write_to_child(void* startroutine)
{
  char buffer[INPUT_BUFFER_SIZE];
  int *pipe = (int *)startroutine;

  while (1) {
    int read_size = read(0, buffer, INPUT_BUFFER_SIZE);

    // if (encrypt_flag)
    //  mdecrypt_generic(td, buffer, read_size);
    if (read_size > 0) {
      int write_size = write(*pipe, buffer, read_size);
      if (write_size <= 0)
	exit(1);
    }
    else
      exit(2);
  }
}



  
int main(int argc, char **argv)
{
  int c;               //long option index
  int parentfd;        //parent socket.
  int childfd;         //child socket.
  int portno;          //port to listen to
  socklen_t cli_len;         // byte size of client's address
  struct sockaddr_in serveraddr; //server address
  struct sockaddr_in clientaddr; //client address
  struct hostent *hostp;  //client host info
 
 

  static struct option long_options[] = {
    {"port", required_argument, 0,      'p'},
    {"encrypt", no_argument,   &encrypt_flag, 'e'}
  };

  while (1) {
    int option_index = 0;

    c = getopt_long(argc, argv, "p:e", long_options, &option_index);
    if (c == -1)
      break;
    switch(c) {
      case 'p':
	portno = atoi(optarg);
	break;
    }
  }

  parentfd = socket(AF_INET, SOCK_STREAM, 0);
  if (parentfd < 0) {
    perror("Error opening socket");
    exit(1);
  }

  //used to eliminate "ERROR on binding"
  //setsockopt
  // optval = 1;
  //setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

  //build server Internet address.
  memset((char *) &serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddr.sin_port = htons((unsigned short)portno);

  //binding
  if (bind(parentfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
    perror("error on binding");
    exit(1);
  }

  //listen, allow at most 5 requests to be in the queue.
  if (listen(parentfd, 5) < 0){
    perror("error on listen");
    exit(0);
  }

  cli_len = sizeof(clientaddr);
  signal(SIGPIPE, signal_handler);
  //may need more work for the pipes

  //may need more work for encryption here.
  //mcrypt
  //tutorial from: mcrypt.hellug.gr/lib/mcrypt.3.html.
  int i;
  int key_fd;
  char *key;
  char password[20];
  //char block_buffer;
  char *IV;
  int keysize = 16;
  if (encrypt_flag) {
    key = calloc(1, keysize);
    key_fd = open("my.key", O_RDONLY);
    if (key_fd < 0) {
      perror("failure loading the key.");
    }
    if (read(key_fd, password, 20) < 0) {
      perror("fail openning the key file.\n");
      exit(1);
    }
    
    memmove(key, password, strlen(password));
    td = mcrypt_module_open("blowfish", NULL, "cfb", NULL);
    if (td == MCRYPT_FAILED) {
      perror("Encryption failed\n");
      exit(1);
    }
    IV = malloc(mcrypt_enc_get_iv_size(td));
    //psudorandom generator
    for (i = 0; i < mcrypt_enc_get_iv_size(td); i++) {
      IV[i] = rand();
    }
    i = mcrypt_generic_init(td, key, keysize, IV);
    if ( i < 0) {
      mcrypt_perror(i);
      exit(1);
    }
  }

  //mcrypt_generic() and mcrypt_end() can be used too
  //they are not used here, and mcrypt_generic() should be used 
  //to encrypt both the traffic into the server and the traffic into
  //the client, initiation takes place at both ends.

  
  while (1) {

    //accpet: wait for a connection request. 
    childfd = accept(parentfd, (struct sockaddr *) &clientaddr, &cli_len);
    if (childfd < 0 ) {
      perror("Error on accept");
      exit(0);
    }
    //determine who sent the message by gethostbyaddr
    hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
			  sizeof(clientaddr.sin_addr.s_addr), AF_INET);
    if (hostp == NULL) {
      perror("Error on gethostbyaddr.");
      exit(0);
    }
    char *hostaddrp;
    hostaddrp = inet_ntoa(clientaddr.sin_addr);
    if (hostaddrp == NULL) {
      perror("Error on inet_ntoa.");
      exit(0);
    }
    printf("server connected with %s (%s)\n", hostp->h_name, hostaddrp);

    //read from client
    shell_fd = childfd;

    if (pipe(pipe_from_shell) == -1) {
      perror("initiate pipe failed\n");
      exit(1);
    }

    if (pipe(pipe_to_shell) == -1) {
      perror("initiate pipe failed\n");
      exit(1);
    }

    pid_t child_pid;
    child_pid = fork();


    if (child_pid >= 0) {
      if (child_pid == 0) {
	close(pipe_from_shell[0]);
	dup2(pipe_from_shell[1], 1);
	close(pipe_to_shell[1]);
	dup2(pipe_to_shell[0], 0);
	close(2);
	dup2(pipe_from_shell[1], 2);

	execl("/bin/bash", "/bin/bash", NULL);
      }
      else {
	//parent
	shell_pid = child_pid;
	close(pipe_to_shell[0]);
	close(pipe_from_shell[1]);
	dup2(shell_fd, 0);
	dup2(shell_fd, 1);
	dup2(shell_fd, 2);

	
	pthread_t shell_input_thread;
	pthread_t shell_output_thread;
	
	pthread_create(&shell_input_thread, NULL, read_from_child, &pipe_from_shell[0]);
	pthread_create(&shell_output_thread, NULL, write_to_child, &pipe_to_shell[1]);
	close(shell_fd);
      }
    }
    else {
      perror("fork failed.\n");
      exit(2);
    }
    
  }
  return 0;
}
