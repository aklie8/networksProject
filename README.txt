Developer: 
  Aklile Tesfaye

Project Overview:
  This README provides essential information for the "End-to-End Detection of Network Compression" project for the CS336 Computer Networks course, Fall 2023.

My project can be found by following the command:
  git clone git@github.com:aklie8/networksProject.git
  
  Alterntaively copy & paste my Github Repository URL for this project.
  The URL: https://github.com/aklie8/networksProject
 
Installations:
GCC: sudo apt install gcc
Wireshak: /bin/wireshark
Git: sudo apt install git

Code Structure:
 
├── common.h               # Header file containing common structures and function declarations
├── cJSON.c                # cJSON library source file for JSON parsing
├── cJSON.h                # cJSON library header file
├── common.c               # Code used for network testing, focusing on measuring network characteristics, checking for compression, and sending/receiving configuration information over TCP connections. It involves both TCP and UDP socket programming, threading, and raw socket usage.
└── README.txt             # Documentation file explaining the code and its usage
 

Building and Running the Code:
- Ensure you have GCC installed (version 7.0 or later).

Build and Run the Client Application:
  # On the client system locate the directory
  cd networksProject/networksProject
   
  # Compilation command to build the project
  gcc -o client client.c common.c cJSON.c 
   
  # Execution command to run the project
  ./client newConfig.json

Build and Run the Server Application:
  # On the server system locate the directory 
  cd networksProject

  # Compilation command to build the project
  gcc -o server server.c common.c cJSON.c  
  
  # Execution command to run the project
  ./server 7000

Build and Run the Standalone Application:
  # On the client system
  cd networksProject/networksProject
 
  # Compilation command to build the project
  gcc -o standalone standalone.c common.c cJSON.c

  # Execution command to run the project
  sudo ./standalone newconfig.json

TroubleShooting:
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
  follwing these intructions

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

Incomplete Required Features:
  - Coding Style
  - Error Handling: 
  Improve the code to handle more unexpected scenarios and provide informative error messages.
