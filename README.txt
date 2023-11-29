Developer: 
  Aklile Tesfaye

Project Overview:
  This README provides essential information for the "End-to-End Detection of Network Compression" project for the CS336 Computer Networks course, Fall 2023.

Code Structure:
 
├── common.h               # Header file containing common structures and function declarations
├── cJSON.c                # cJSON library source file for JSON parsing
├── cJSON.h                # cJSON library header file
├── common.c               # Code used for network testing, focusing on measuring network characteristics, checking for compression, and sending/receiving configuration information over TCP connections. It involves both TCP and UDP socket programming, threading, and raw socket usage.
└── README.txt             # Documentation file explaining the code and its usage

Installations:
GCC: sudo install gcc
Wireshak: sudo /bin/wireshark
Git: sudo install git 

Building and Running the Code:
  git clone <git@github.com:aklie8/networksProject.git>

Run the Client/Server Application:
 # On the client system
 cd networksProject/networksProject
   
  # compilation command
  gcc -o client client.c common.c cJSON.c 
   
  # Execution command
  ./client newConfig.json

 # On the server system
 cd networksProject

  # compilation command
  gcc -o server server.c common.c cJSON.c  
  
  # Execution command
  ./server 7000

Run the Standalone Application:
  # On the client system
  cd networksProject/networksProject
 
  # compilation command
  gcc -o standalone standalone.c common.c cJSON.c

  # Execution command
  sudo ./standalone newconfig.json

Incomplete Required Features:
  Error Handling: Improve the code to handle unexpected scenarios gracefully and provide informative error messages.
