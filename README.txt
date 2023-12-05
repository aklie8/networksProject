# Networks Project 

## Developer
    - Aklile Tesfaye

## Table of contents
    - Porject Overview
    - Installations
    - Code Structure and Description
    - Building & Running the Code
    - Configurations
    - TroubleShooting & FAQ
    - Incomplete Required Features

## Project Overview:
    - This README provides essential information for the "End-to-End Detection of Network Compression" 
      project for the CS336 Computer Networks course, Fall 2023.
 
## Installations:
    - GCC: sudo apt install gcc
    - Wireshak: /bin/wireshark
    - Git: sudo apt install git

## Code Structure & Description:
_
├── common.c               # Source file containing common utility functions
├── common.h               # Header file with structures and functions for network configuration
├── cJSON.c                # cJSON library source file for JSON parsing
├── cJSON.h                # cJSON library header file with JSON parsing function declarations
├── client.c               # Source file for the client application's main functionality
├── client.h               # Header file for client-specific structures and functions
├── standalone.c           # Source file for the standalone client application's main functionality
├── server.c               # Source file for the server application's main functionality
├── newConfig.json         # Example JSON configuration file for the application
├── README.txt             # Documentation file explaining the code organization and its usage

    - common.c: code used for network testing, focusing on measuring network characteristics,
      checking for compression, and sending/receiving configuration information over 
      TCP connections. It involves both TCP and UDP socket programming, threading
      checksum caclulation and raw socket usage.
 
    - client.c: contains the source code for the client-side application. 
    It handles tasks such as reading a JSON configuration file, sending data to the server, and interacting
    with the server.

    - common.h: provides a clear interface for the common functionalities in the project. 
    It includes functions for creating, freeing, sending, and receiving configurations, 
    as well as handling results and packet trains.The struct config defines the configuration 
    parameters used throughout the code.

    - server.c: is a crucial source file responsible for the server-side functionality. 
    It includes necessary headers, validates input arguments, receives configuration information 
    from clients, processes packet trains, detects compression, and sends results back to clients.

     # Important Notes for server.c
      - Compile and run server.c to initiate the server. Ensure that the correct TCP port is provided as a command line argument.

    - standalone.c: serves as the standalone client application that reads a JSON configuration file, 
    establishes a connection with the server, and conducts two consecutive packet train transmissions. 
    It then analyzes the time durations between RST packets to detect potential compression.

     # Important Notes for standalone.c
      - Compile and run standalone.c with the JSON configuration file as a command line argument
      to ensure standalone client's functionalities and the sequence of actions involved in 
      compression detection are correct.

    - newConfig.JSON: JSON file used to configure the network parameters for the client/server 
    communication and standalone application. It specifies the IP addresses for both the server and host 
    in the network.

     # Important Notes for newConfig.JSON
     - Provide newConfig.JSON as a command line argument when running the standalone.c and client.c appliactions.

## Configuration (Common.h): Structure to hold configuration parameters
struct config {
    char host_IP[32];     // IP address of the host (used by client and standalone applications)
    char server_IP[32];   // IP address of the server (used by client and server applications)
    int src_port;         // Source port for communication (used by client and standalone applications)
    int dest_UDP_port;    // Destination port for UDP communication (used by client, server, and standalone applications)
    int dest_TCP_head_port; // Port for the head of TCP communication during post-probing phase (used by client and server applications)
    int dest_TCP_tail_port; // Port for the tail of TCP communication during post-probing phase (used by client and server applications)
    int TCP_pre_probing_port; // Port for TCP pre-probing phase (used by client and server applications)
    int TCP_post_probing_port; // Port for TCP post-probing phase (used by client and server applications)
    int UDP_payload_size; // Size of UDP payload in the UDP packet train (used by client, server, and standalone applications)
    int inter_measurement_time; // Time interval between measurements (used by client and server applications)
    int UDP_packet_count; // Number of UDP packets in the UDP packet train (used by client, server, and standalone applications)
    int UDP_packets_TTL; // Time-to-live (TTL) for UDP packets in the UDP packet train (used by standalone application)
};

## Configuration (Common.c): Configuration structure with the default values for the parameters
 //@param json_str A JSON-formatted string that may contain configuration details. (Not fully implemented in this snippet)

struct config *createConfig(char *json_str) {
    // Allocate memory for the configuration structure
    struct config *config = (struct config *)calloc(1, sizeof(struct config));

    // Set default values for each parameter
    config->host_IP[0] = '\0';            // Initialize host IP as an empty string
    config->src_port = 9876;              // Default source port for communication
    config->dest_UDP_port = 8765;         // Default destination port for UDP communication
    config->dest_TCP_head_port = 9999;    // Default destination port for TCP head during post-probing phase
    config->dest_TCP_tail_port = 8888;    // Default destination port for TCP tail during post-probing phase
    config->TCP_pre_probing_port = 7777;  // Default port for TCP pre-probing phase
    config->TCP_post_probing_port = 6666; // Default port for TCP post-probing phase
    config->UDP_payload_size = 1000;      // Default size of UDP payload in the packet train
    config->inter_measurement_time = 15;  // Default time interval between measurements
    config->UDP_packet_count = 6000;      // Default number of UDP packets in the packet train
    config->UDP_packets_TTL = 255;        // Default TTL for UDP packets in the packet train
  
//rest of the code ...
}

## Building and Running the Code:
    - Ensure you have GCC installed (version 7.0 or later).

## Build and Run the Client Application:

  # On the client system locate the directory
  cd networksProject
   
  # Compilation command to build the project
  gcc -o client client.c common.c cJSON.c 
   
  # Execution command to run the project
  ./client newConfig.json

## Build and Run the Server Application:

  # On the server system locate the directory 
  cd networksProject

  # Compilation command to build the project
  gcc -o server server.c common.c cJSON.c  
  
  # Execution command to run the project
  ./server 7777

## Build and Run the Standalone Application:

  # On the client system
  cd networksProject
 
  # Compilation command to build the project
  gcc -o standalone standalone.c common.c cJSON.c

  # Execution command to run the project
  sudo ./standalone newconfig.json

## TroubleShooting & FAQ:
 Setting up a Git Repository for the project:

   When create a new repository on my GitHub for the project I followed the commands on 
   provided through this link: [https://gist.github.com/alexpchin/102854243cd066f8b88e]
   When running "git commit -m 'First commit'" on UTM Terminal I recived the error "Author identity unknown"
   I resolved this by doing "git config --global user.email potc55bhu@gmail.com" 
   and "git config --global user.name "aklie8"

  When running "git push -u origin main" I recived the error "error: failed to push some refs to orgin"
  I tried to fix teh error by cloning my project repository using the SSH URL into the UTM terminal I ran into the error "Fatal: Cound 
  real from remote repository. Please make sure you have the correct access rights and the repository exists."
  I resolved this by cloing the my project repository using the HTTPS URL into the UTM terminal, then doing 
  cd networksProject, then doing nano README.md with "hello world" in the file then adding, commiting 
  and pushing that README.md file, when pushing I encountered another error "fatal: Authentication failed
  for[https://github.com/aklie8/networksProject.git]" so then I did cd .. and created an SSH keys on my github 
  follwing these intructions: 
  [https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent]
  then after generating an SSH key, cd back into networksProject, did "git remote rm origin, 
  git remote -v", "git remote add origin git@github.com:aklie8/networksProject.git", then
  when i did "git push --set upstream origin main" then that worked to set up one 
  Git Repository for the project for both client and server. 
  
 
 Part 2 RawSocket: 

   I have the raw socket working but when I am running Wireshark from the server
   I can see the SYN packets received from the client however the server does not 
   respond with an RST packet it just sends an ICMP packets saying "unreachable". 
   However when I ping the client from the server using the same IP address it works correctly. 
   I could't figure our why the server can't find the client when I run part 2 of the project 
   even thought it can find it for part 1.

   After brutally debugging and asking on Piazza I learned that if RST packets are not generated 
   only in response to my SYN packets, then that means, there is at least one header field (TCP or IP header) 
   that is not properly set (e.g., the checksum is not properly calculated on the packet pesudoheader).
   Then after checking checking if the checksum is properly calculated by enabling Wireshark 
   checksum validation I realized it was off it waa flipped I was getting Checksum: 0xa7c5 but the 
   expected Checksum was 0xc5a7. I created a tcp_udp_check_sum_16_rfc() function to calculate 
   the checksum and then when I call this function in the sendSynPacket() method I call it 
   around htons() function.

## Incomplete Required Features:
    - Coding Style

## Important Notes 
    - Superuser Permissions: Some parts of the code, such as raw socket creation, may require superuser permissions to run successfully. 
      Ensure the program is executed with the necessary privileges.

## Refrences 
    - [https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent?platform=linux]
    - [https://beej.us/guide/bgnet/html/split/client-server-background.html#cb47-1]
    - [https://github.com/DaveGamble/cJSON]
    - [https://linux.die.net/man/2/setsockopt]
    - [https://man7.org/linux/man-pages/man2/gettimeofday.2.html]
    - [https://www.tutorialspoint.com/c-program-to-display-hostname-and-ip-address]
    - [https://www.geeksforgeeks.org/c-program-display-hostname-ip-address/]
    - [https://www.drupal.org/docs/develop/managing-a-drupalorg-theme-module-or-distribution-project/documenting-your-project/readmemd-template]   
