## Developer
 
  Aklile Tesfaye

## Table of contents 

 - Porject Overview
 - Installations
 - Code Structure
 - Building & Running the Code
 - TroubleShooting & FAQ
 - Incomplete Required Features

## Project Overview:

  This README provides essential information for the "End-to-End Detection of Network Compression" 
  project for the CS336 Computer Networks course, Fall 2023.

## My project code can be found by following the command:

  git clone git@github.com:aklie8/networksProject.git
  
  Alterntaively copy & paste my Github Repository URL for this project.
  The URL: https://github.com/aklie8/networksProject
 
## Installations:

   GCC: sudo apt install gcc
   Wireshak: /bin/wireshark
   Git: sudo apt install git

## Code Structure:
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

-- common.c Code used for network testing, focusing on measuring network characteristics,
                             checking for compression, and sending/receiving configuration information
                             over TCP connections. It involves TCP socket programming, threading, checksum
                             caclulation and raw socket usage.
 
-- client.c contains the source code for the client-side application. 
It handles tasks such as reading a JSON configuration file, sending data to the server, and interacting
with the server.

-- common.h provides a clear interface for the common functionalities in the project. 
It includes functions for creating, freeing, sending, and receiving configurations, 
as well as handling results and packet trains. 
The struct config defines the configuration parameters used throughout the code.

-- server.c is a crucial source file responsible for the server-side functionality. 
It includes necessary headers, validates input arguments, receives configuration information 
from clients, processes packet trains, detects compression, and sends results back to clients.
Important notes: Compile and run server.c to initiate the server. 
                 Ensure that the correct TCP port is provided as a command line argument.

-- standalone.c serves as the standalone client application that reads a JSON configuration file, 
establishes a connection with the server, and conducts two consecutive packet train transmissions. 
It then analyzes the time durations between RST packets to detect potential compression.
Important Notes: Compile and run standalone.c with the JSON configuration file as a command line argument
                 to ensure standalone client's functionalities and the sequence of actions involved in 
                 compression detection are correct.

-- newConfig.JSON is a JSON file used to configure the network parameters for the client/server 
communication and standalone application. It specifies the IP addresses for both the server and host 
in the network. Important Notes: When running the standalone.c and client.c appliactions,
                 provide newConfig.JSON as a command line argument.

## Configuration (Common.h)
# Structure to hold configuration parameters
struct config {
  char host_IP[32];
  char server_IP[32];
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

# Important Notes 
  This holds configuration parameters for the application, such as IP addresses, port numbers, payload size,
  and timing intervals.

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
  ./server 7000

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
   provided through this link: https://gist.github.com/alexpchin/102854243cd066f8b88e
   When running "git commit -m 'First commit'" on UTM Terminal I recived the error "Author identity unknown"
   I resolved this by doing "git config --global user.email potc55bhu@gmail.com" 
   and "git config --global user.name "aklie8"

  When running "git push -u origin main" I recived the error "error: failed to push some refs to orgin"
  I tried to fix teh error by cloning my project repository using the SSH URL into the UTM terminal I ran into the error "Fatal: Cound 
  real from remote repository. Please make sure you have the correct access rights and the repository exists."
  I resolved this by cloing the my project repository using the HTTPS URL into the UTM terminal, then doing 
  cd networksProject, then doing nano README.md with "hello world" in the file then adding, commiting 
  and pushing that README.md file, when pushing I encountered another error "fatal: Authentication failed
  for https://github.com/aklie8/networksProject.git" so then I did cd .. and created an SSH keys on my github 
  follwing these intructions: 
  https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent
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
  - Error Handling: 
     Improve the code to handle more unexpected scenarios and provide informative error messages.

## Important Notes 

Superuser Permissions: 
  Some parts of the code, such as raw socket creation, may require superuser permissions to run successfully. 
  Ensure the program is executed with the necessary privileges.

