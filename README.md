
# KerberosChatRooms
## Overview
This repository implements a chat room system similar to chat apps message groups, utilizing the Kerberos protocol <br> 
to ensure secure authentication and communication between authorized users and available chat rooms servers.<br> 


![kerberos.png](Images/kerberos.png)

## Usage
write about export python path if module not found error
- Written in Python 3.9 with PyCharm on Windows 11.
- add console for run auth server
- add console for run msg server
- add console for run client
- all with arg parser examples with dev mode

## Architecture
Client-Server architecture that utilizes python socket library.

![software_architecture.jpg](Images%2Fsoftware_architecture.jpg)

### Major Components

#### Client:
* A CLI based multithreaded client that operates according to requests from the user.
* Responsible for initiating communication with the AS and register.
* Upon successful registration the client can request list of services and their resources from the TGS.
* Responsible for initiating communication with the service of his choice to exchange resources.
* Starts chatting with the other chat group users.

#### Auth Server:
* A multithreaded server.
* Waits for requests from clients and services.
* Operates in batch mode according to a custom communication protocol.
* Contains both Authentication Server and Ticket Granting Server and acts as KDC.

#### Msg Server:
* A multithreaded server.
* Operates as a client at start, will initiate communication with the AS and register.
* Upon successful registration will exchange resources with the AS, then will function as a chat room.
* Waits for connection requests from clients.
* Prints messages to the screen.

#### Service Manager:
* A custom orchestrator that handles creation and management of a given number of services.

#### Protocol Handler:
* Handles all the logic of the communication protocol with an emphasis on packing and unpacking packets.

#### Socket:
* Handles all the logic for sending and receiving packets. 


## Communication Protocol
1. Binary TCP based protocol with positive number values represented as little-endian.
2. Sockets are implemented with python socket library.
3. Packets are packed and unpacked with python struct library.
4. Encryption and Decryption is symmetric, AES-CBC based, with 256 bits size keys and random IV's, with Crypto.Cipher library.

#### Architecture:
![kerberos_communication_architecture.jpg](Images%2Fkerberos_communication_architecture.jpg)

#### Client:
1. The Client will have the following files: <br>
   - **srv.info** - Will have one line --> KDC connection credentials.
   - **me.info** - Will have two line --> 1. Client username, 2. Client unique UUID received from the AS.
   ```text
   Michael Jackson
   4e43ae195f4d43b799ce2cca77178cfb
   ```
   - **services_info.json** - Will Operate as a database that contain all the available services details received from the KDC as JSON objects.
   ```json
   {
     // The hexed service unique UUID
     "server_id": "5821f9a674174062ad3af49ee1432681",
     "server_name": "Printer 10",
     "server_ip": "127.0.0.1",
     "server_port": 58023,
     // The base64 encoded service AES key        
     "aes_key": "Ph7tXPYg8xmNkgLQaDs2wnj8TdEqKco0j1zZqgzjClE=",
     // The hexed encrypted key IV       
     "encrypted_key_iv": "327762044450156fc138733dfa979415", 
     // The base64 encoded ticket packet
     "ticket": "GE5DrhlfTUO3mc4syncXjPtYIfmmdBdAYq069J7hQyaBrtB3/zNADD8KSeAS9ax/ki2yUtCoH/DdqjB3Mq0C7en8jsLMMwXzR0EYCjaKwM31Y4EHV5NGaBLJlz5E4KmKJgTjZRPkC/tW9iPS8YXa+bUUm1Vb3OCgala1lwj6A5/lVoWSrkwYdkV0lbM8ogKfPne8kgOLGTQF59FXyKW7Bgo="
   }
   ```
2. **Registration Request (Diagram 1)** - The Client will send registration request, upon register success the client will receive a unique UUID from the AS.
3. **Available Services Request (Diagram 2)** - The Client will receive response containing all the registered services from the KDC. 
4. **Encrypted Key and Ticket Request (Diagram 3)** - The Client will select his service of choice, and will receive an encrypted AES key and a generated Ticket from the TGS.
5. **Symmetric Key Request (Diagram 4)** - The Client will generate an Authenticator and send a connection request to the selected service with the Authenticator and the received Ticket.  
6. **Encrypted Message Request (Diagram 5)** - Chat Mode. the Client will send encrypted messages to the service to be printed out to the screen after decryption.

#### Auth Server:
1. The Auth Server will have the following files: <br>
   - **port.info** - Will contain the KDC port number.
   - **clients.txt** - Will contain all the client's info. line structure --> ID: Name: PasswordHash: LastSeen. operates as the client's database.
   ```text
   fa8a3d1e99584c08ac58ba28c93e03c9: Michael Jackson: 4d4f26369171994f3a46776ee2d88494fb9955800a5bb6261c016c4bb9f30b56: 26/02/24_22:02:49
   ```
   - **services.json** - Will contain all the service's info. operates as the service's database, each service entry is represented as JSON object.
   ```json
   {
    "server_id_hex": "d593dd40438b41b88622b2d7cf07e55d",
    "name": "Printer 10",
    "aes_key_hex": "63edf1a37b40a012757847169c8da6026ffd7d1a750c7ecc86b0e126d2946309",
    "server_ip": "127.0.0.1",
    "server_port": 61590
   }
   ```
2. The Auth Server Will read his port number from 'port.info' file, if the file does not exist's or corrupted a default port number will be assigned.
3. The Auth Server will load clients data from clients.txt file.
4. The Auth Server will wait for requests from Clients and Services.
5. **Registration Response (Diagram 1)** - The Auth Server (as the AS) will send registration success with a unique generated UUID for both Clients and Service, or registration failure.
6. **Available Services Response (Diagram 2)** - The Auth Server (as the KDC) will send the available registered services as a list back to the Client.
7. **Encrypted Key and Ticket Response (Diagram 3)** - The Auth Server (as the TGS) will send a generated Ticket and Encrypted AES key for the dedicated service back to client.

#### Msg Server:
1. The Msg Server will have the following files: <br>
   - **msg.info** - Will contain 4 lines --> 1. KDC IP:Port, 2. Service name, 3. Service unique UUID received from the AS, 4. Service AES key. operates as a default registered service.
   ```text
   127.0.0.1:1234
   Printer 1
   0949dca733904f77a9e3928dfcbbe687
   ss4iqLtqm75tGrDCbIzW1MnY3M9VA+tYfWfTnxXEUBU=
   ```
   - **services_pool.json** - Will contain all the service's info. operates as the service's database, each service entry is represented as JSON object.
   ```json
   {
    "connection_protocol": "tcp",
    "ip_address": "127.0.0.1",
    "auth_port": 1234,
    "port": 1234,
    "server_id_hex": "0949dca733904f77a9e3928dfcbbe687",
    "service_name": "Printer 1",
    "ticket_iv": null,
    "aes_key_hex": "ss4iqLtqm75tGrDCbIzW1MnY3M9VA+tYfWfTnxXEUBU=",
    "message_iv": null,
    "is_registered": true
   }
   ```
2. The Service Manager will create and register services according to the amount given by the KDC system administrator. upon failure a default service will be registered.
3. **Registration Request (Diagram 1)** - The Msg Server, as a client, will send registration request, upon register success will receive a unique UUID from the AS and will start operating as a chat room server.
4. **Symmetric Key Response (Diagram 4)** - The Msg Server (as a chat room) will receive the Authenticator and Ticket from the client, and will send ACK upon success.
5. **Encrypted Message Request (Diagram 5)** - Chat Mode. The Msg Server (as a chat room) will receive encrypted messages, and will print the decrypted message content to the screen. 

### Protocol Packets Format
#### Server Requests
**Header:**<br>

| Request          | Field     | Size | Use                        |
|---------------|-----------|--------|----------------------------|
| Header      | Client ID | 16-Bytes   | Client/Service unique UUID |
| Header    | Version   | 1-Byte | Client/Service version     |
| Header  | Code      | 2-Bytes   | Request code               |
| Header  | Payload size        | 4-Bytes   | Packet payload size        |
| Payload  | Payload        | Changing   | Packet Payload             |

**Payloads:**<br>
Request Code 1024 - Client Registration.

| Field    | Size | Use                                   |
|----------| --- |---------------------------------------|
| Name     | 255-Bytes | Client name with null termination     |
| Password | 255-Bytes | Client password with null termination |

Request Code 1025 - Service Registration.

| Field         | Size      | Use                                    |
|---------------|-----------|----------------------------------------|
| Name          | 255-Bytes | Service name with null termination     |
| Symmetric Key | 32-Bytes  | Service AES key, for Ticket decryption |

Request Code 1026 - Available Services.

Request Code 1027 - Encrypted Key and Ticket.

| Field      | Size     | Use                           |
|------------|----------|-------------------------------|
| Service ID | 16-Bytes | The wanted Service unique UUID |
| Nonce      | 8-Bytes  | A Random generated value      |

Request Code 1028 - Symmetric Key.

| Field         | Size     | Use                                       |
|---------------|----------|-------------------------------------------|
| Authenticator |  | The Client generated Authenticator packet |
| Ticket        |   | The TGS Generated Ticket packet           |

Authenticator Packet Structure:

| Field            | Size     | Use                                |
|------------------|----------|------------------------------------|
| Authenticator IV | 16-Bytes |                                    |
| Version          | 16-Bytes | Encrypted with the Service AES key |
| Client ID        | 32-Bytes | Encrypted with the Service AES key |
| Service ID       | 32-Bytes | Encrypted with the Service AES key |
| Creation Time    | 32-Bytes | Encrypted with the Service AES key |

Ticket Packet Structure:


| Field           | Size     | Use                                                    |
|-----------------|----------|--------------------------------------------------------|
| Version         | 1-Byte   | Service version                                        |
| Client ID       | 16-Bytes | Client unique UUID                                     |
| Service ID      | 16-Bytes | Service unique UUID                                    |
| Creation Time   | 8-Bytes  | Ticket creation timestamp                              |
| Ticket IV       | 16-Bytes |                                                        |
| AES Key         | 48-Bytes | Encrypted with the Service AES key                     |
| Expiration Time | 32-Bytes | Ticket expiration time, Encrypted with Service AES key |


Request Code 1029 - Encrypted Message Request.

| Field           | Size     | Use                                                |
|-----------------|----------|----------------------------------------------------|
| Message Size    | 4-Bytes  | Encrypted message size                             |
| Message IV      | 16-Bytes |                                                    |
| Message Content | Changing | The encrypted message content with Service AES key |


#### Server Responses
**Header:**<br>

| Request          | Field     | Size | Use                    |
|---------------|-----------|--------|------------------------|
| Header    | Version   | 1-Byte | Client/Service version |
| Header  | Code      | 2-Bytes   | Response code          |
| Header  | Payload size        | 4-Bytes   | Packet payload size    |
| Payload  | Payload        | Changing   | Packet Payload         |

Response Code 1600 - Registration Success.

| Field            | Size     | Use                                  |
|------------------|----------|--------------------------------------|
| Client ID | 16-Bytes | A unique UUID for the Client/Service |

Response Code 1601 - Registration Failure.

Response Code 1602 - Available Services List.

| Field        | Size      | Use                                |
|--------------|-----------|------------------------------------|
| Service ID   | 16-Bytes  | The unique UUID of the Service     |
| Service Name | 255-Bytes | Service name with null termination |
| Service IP   | 4-Bytes   | Service IP address                 |
| Service Port | 2-Bytes   | Service port number                |

Response Code 1603 - Encrypted Key and Ticket.

| Field         | Size     | Use                        |
|---------------|----------|----------------------------|
| Client ID     | 16-Bytes | The unique UUID of the Client |
| Encrypted Key |  | The service AES key packet |
| Ticket        |  | The TGS Generated Ticket packet         |

Encrypted Key Packet Structure:

| Field            | Size     | Use                                                          |
|------------------|----------|--------------------------------------------------------------|
| Encrypted Key IV | 16-Bytes |                                                              |
| Nonce            | 16-Bytes | Encrypted with the Client password hash                      |
| AES Key          | 32-Bytes | The Service AES key, Encrypted with the Client password hash |


Response Code 1604 - Symmetric Key ACK.<br>
Response Code 1605 - Encrypted Message ACK.<br>
Response Code 1609 - Server General Error.<br>



1. record a demo with x cmd windows open that shows auth, msg and at least 2 clients sending message in msg group
2. record with wireshark and show the encrypted protocol.
3. create setup.py script with dependencies, and check that only Crypto.Cipher needed to be installed.
4. Add protocol add-ons 1700-1703 codes
5. add comments to json files examples
6. refactor json example for services_pool with IVs
7. dev mode colors:
   - Green - struct format related output
   - Yellow - struct unpack related output
   - Blue - struct pack related output
   - Cyan - DB related output
   - Magenta - Communication protocol related output
   - insert to readme examples of dev mode run time, all the colors and custom messages