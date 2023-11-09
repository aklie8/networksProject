#include<stdio.h>
#include<stdlib.h>
#include "common.h"

int main(int argc, char * argv[]){
  if(argc != 2){
    printf("Expected 1 arg (the TCP Port)\n");
    return 1;
  }

  char * TCP_port = argv[1];
 // printf("%d\n", TCP_port);

  if(atoi(TCP_port) > 65535 || atoi(TCP_port) <= 0){
    printf("Invalid Port\n");
  }

  struct config * config = receiveConfig(TCP_port);

}
