#include <stdio.h>
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
      strcpy(config->server_IP, subObject->string);
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
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(ip_addr, port, &hints, &servinfo)) != 0) {
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
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);

	close(sockfd);

	return 0;
}


struct config * receiveConfig (char * port){
  char s[INET6_ADDRSTRLEN];
  socklen_t sin_size;
  struct sockaddr_storage their_addr; // connector's address information
  int sockfd = createServerTCPSocket(port);

  sin_size = sizeof their_addr;
  int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
  if (new_fd == -1) {
    perror("accept");
    exit(1);
  }

  inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof(s));
  printf("server: got connection from %s\n", s);
  close(sockfd); // child doesn't need the listener

  char buffer[10000];
  memset (buffer, '\0', 10000); 

  if (recv(new_fd, buffer, 9999, 0) == -1){
    perror("recv failed to receive data");
    exit(1);
  }

  close(new_fd);  // parent doesn't need this
  printf("%s\n", buffer);
  return createConfig(buffer);
}

void sendConfig (struct config * config, char * json_str){
}
