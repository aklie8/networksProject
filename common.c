#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "common.h"
#include "cJSON.h"
/*
struct config{
  char [32] server_IP;
  int src_port;
  int dest_UDP_port;
  int dest_TCP_head_port;
  int dest_TCP_tail_port;
  int TCP_pre_probing_port;
  int TCP_post_probing_port;
  int UDP_payload_size;
  int inter_measurement_time;
  int UDP_packet_count;
  int UDP_packets_TTL;      
}
*/
struct config * createConfig(char * json_str){
  struct config * config = (struct config *) calloc(1, sizeof(struct config));
 
  config->src_port = 9876;
  config->dest_UDP_port = 8765;
  config->dest_TCP_head_port = 9999;
  config->dest_TCP_tail_port = 8888;
  config->TCP_pre_probing_port = 7777;
  config->TCP_post_probing_port = 6666;
  config->UDP_payload_size = 1000;
  config->inter_measurement_time = 15;
  config->UDP_packet_count = 6000;
  config->UDP_packets_TTL = 255;
 
  cJSON *json = cJSON_Parse(json_str);
  cJSON *subObject;

  if(!cJSON_IsObject(json)){
    printf("Expected json object\n");
    return NULL;
  }
  if(subObject = cJSON_GetObjectItem(json, "server_IP")){
    if(cJSON_IsString(subObject)){
      strcpy(config->server_IP, subObject->valuestring);
    }
  }
  else{
    printf("Server IP unspecified in json\n");
    return NULL;
  }

  if(subObject = cJSON_GetObjectItem(json, "src_port")){
    if(cJSON_IsNumber(subObject)){
      config->src_port = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "dest_UDP_port")){
    if(cJSON_IsNumber(subObject)){
      config->dest_UDP_port = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "dest_TCP_head_port")){
    if(cJSON_IsNumber(subObject)){
      config->dest_TCP_head_port = subObject->valueint;
    }
  }
 
  if(subObject = cJSON_GetObjectItem(json, "dest_TCP_tail_port")){
    if(cJSON_IsNumber(subObject)){
      config->dest_TCP_tail_port = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "TCP_pre_probing_port")){
    if(cJSON_IsNumber(subObject)){
      config->TCP_pre_probing_port = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "TCP_post_probing_port")){
    if(cJSON_IsNumber(subObject)){
      config->TCP_post_probing_port = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "UDP_payload_size")){
    if(cJSON_IsNumber(subObject)){
      config->UDP_payload_size = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "inter_measurement_time")){
    if(cJSON_IsNumber(subObject)){
      config->inter_measurement_time = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "UDP_packet_count")){
    if(cJSON_IsNumber(subObject)){
      config->UDP_packet_count = subObject->valueint;
    }
  }

  if(subObject = cJSON_GetObjectItem(json, "UDP_packets_TTL")){
    if(cJSON_IsNumber(subObject)){
      config->UDP_packets_TTL = subObject->valueint;
    }
  }

  cJSON_Delete(json);
  return config;
}

void freeConfig (struct config * config){
  free(config);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int createServerTCPSocket(char * port)
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
        

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, 1) == -1) {
		perror("listen");
		exit(1);
        }

	printf("server: waiting for connections...\n");

	return sockfd;
}

int createClientTCPSocket(char * port, char * ip_addr)
{
	int sockfd, numbytes;  
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(ip_addr, port, &hints, &servinfo)) != 0) {
		printf("%s %s\n", ip_addr , port);
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return -1;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

        return sockfd;
}


struct config * receiveConfig (char * port){
  char s[INET6_ADDRSTRLEN];
  socklen_t sin_size;
  struct sockaddr_storage their_addr;  
  int sockfd = createServerTCPSocket(port);

  sin_size = sizeof their_addr;
  int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
  if (new_fd == -1) {
    perror("accept");
    exit(1);
  }

  inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof(s));
  printf("server: got connection from %s\n", s);
  close(sockfd); 

  char buffer[10000];
  memset (buffer, '\0', 10000); 

  if (recv(new_fd, buffer, 9999, 0) == -1){
    perror("recv failed to receive data");
    exit(1);
  }

  close(new_fd);  
  printf("%s\n", buffer);
  return createConfig(buffer);
}

void sendConfig (struct config * config, char * json_str){
  char port[6];
  sprintf(port, "%d", config->TCP_pre_probing_port);
 
  int sockfd = createClientTCPSocket(port, config->server_IP);
  
  if ((send(sockfd, json_str, strlen(json_str), 0)) == -1) {
    perror("send\n");
    exit(1);
  }
  

  printf("config sent \n");

  close(sockfd);
}

void sendResults(struct config * config, bool compression_detected){
  char s[INET6_ADDRSTRLEN];
  socklen_t sin_size;
  struct sockaddr_storage their_addr; // connector's address information
  char port[6];
  sprintf(port, "%d", config->TCP_post_probing_port);
  int sockfd = createServerTCPSocket(port);

  sin_size = sizeof their_addr;
  int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
  if (new_fd == -1) {
    perror("accept");
    exit(1);
  }

  inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof(s));
  printf("server: got connection from %s\n", s);
  close(sockfd); 


  if (send(new_fd, (compression_detected ? "Compression Detected\n": "No Compression Detected\n"), 50,0) == -1){
    perror("recv failed to receive data");
    exit(1);
  }

  close(new_fd); 
}

void receiveResults(struct config * config){
  char port[6];
  char buf[51];
  memset(buf, '\0', 51);
  sprintf(port, "%d", config->TCP_post_probing_port);
 
  int sockfd = createClientTCPSocket(port, config->server_IP);
 
  while(sockfd == -1){
    sleep(1);
    printf("Retrying Connection\n");
    sockfd = createClientTCPSocket(port, config->server_IP);
  }

  if ((recv(sockfd, buf, 50, 0)) == -1) {
    perror("recv");
    exit(1);
  }
  printf("%s", buf);
}


int createUdpListener(char * port)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		exit(2);
	}

	freeaddrinfo(servinfo);

	printf("listener: waiting to recvfrom...\n");
	
	return sockfd;
}

int createUdpSender(char * port, char * host)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		return 2;
	}

        connect(sockfd, p->ai_addr, p->ai_addrlen);

	if ((numbytes = send(sockfd, "message here", strlen("message here"), 0)) == -1) {
		perror("talker: sendto");
		exit(1);
	}

	freeaddrinfo(servinfo);

	printf("talker: sent %d bytes to %s\n", numbytes, host);
	close(sockfd);

	return 0;
}

//method that dtermines if packet compression exists
bool processPacketTrains(struct config * config){
  char port[6];
  sprintf(port, "%d",config->dest_UDP_port);
  char * buf = calloc(1, config->UDP_payload_size + 1);  
  int sockfd = createUdpListener(port);
  int numbytes; 
  if ((numbytes = recvfrom(sockfd, buf, config->UDP_payload_size, 0, NULL, NULL)) == -1) {
    perror("recvfrom");
    exit(1);
  }

  printf("listener: packet is %d bytes long\n", numbytes);
  buf[numbytes] = '\0';
  printf("listener: packet contains \"%s\"\n", buf);

  close(sockfd);
  free(buf);
}
