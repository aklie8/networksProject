#include<stdio.h>
#include<stdlib.h>

int main(int argc, char * argv[]){
  if(argc != 2){
    printf("Expected 1 arg (the TCP Port)\n");
    return 1;
  }

  int TCP_port = atoi(argv[1]);
 // printf("%d\n", TCP_port);

  if(TCP_port > 65535 || TCP_port <= 0){
    printf("Invalid Port\n");
  }

}
