#include <stdbool.h>

struct config{
  char server_IP [32];
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
};

struct config * createConfig(char * json_str);

void freeConfig (struct config * config);

void sendConfig (struct config * config, char * json_str);

struct config * receiveConfig (char * port);


void sendResults(struct config * config, bool compression_detected);

void receiveResults(struct config * config);

bool processPacketTrains(struct config * config);
