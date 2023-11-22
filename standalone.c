#include<stdio.h>
#include<stdlib.h>
#include "common.h"
#include <unistd.h>

int main(int argc, char * argv[]){
  if(argc != 2){
    printf("Expected 1 arg (the JSON config file)\n");
    return 1;
  }

  char * file_path = argv[1];
  printf("%s\n", file_path);

  FILE *config_file = fopen(file_path, "r");

  if(config_file == NULL){
    printf("The file can not be opened\n");
    return 1;
  }

  fseek(config_file, 0L, SEEK_END);
  int file_size = ftell(config_file);
  rewind(config_file);

  char * file_data = (char *) calloc(1, file_size + 1);
 
  if(fread(file_data, file_size, 1, config_file) != 1){
    printf("failed to read file\n");
    return 1;
  }

  fclose(config_file);

  struct config * config = createConfig(file_data);
  free(file_data);

  long long firstTrainDuration = standAloneSendTrain(config, false);
  sleep(config->inter_measurement_time);
  long long secondTrainDuration = standAloneSendTrain(config, true);
 
  if (firstTrainDuration < 0 || secondTrainDuration < 0){
    printf("Failed to detect due to insufficient information\n");  
  }
  else if(secondTrainDuration - firstTrainDuration > 100){
    printf("Compression Detected\n");
  }
  else{
    printf("No Compression Detected\n");
  }
  freeConfig(config);
}

