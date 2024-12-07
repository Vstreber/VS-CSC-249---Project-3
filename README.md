# YOU WOULDN'T DOWNLOAD A CAT. (encrypted version)

### Overview of Application
> This is a demo of a client-server setup that utilizes a VPN and symmetric keys to mask conversation with a black market pet server. The program performs a TLC handshake with a simulated certificate authority and key generators to complete this task securely. 

### Format of an unsigned certificate
Taking the format used for the client-VPN application-layer header as an example, an unsigned certificate consists of three parts divded by data indicators in tildas (\~IP\~ and \~port\~). It looks like this:
```
[server IP]~IP~[server port]~port~[public key]
```
The client can then extract information by using the tilda indicators as indices and manipulating the strings according to its knowledge of what should be there (length of an IP address, port, etc).

### Example Output
CLIENT:
```
$ python secure_client.py --message DOG
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (46828, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
TLS handshake complete: sent symmetric key '33628', waiting for acknowledgement
Received acknowledgement 'Symmetric key '33628' received', preparing to send message
Sending message 'HMAC_22213[symmetric_33628[DOG]]' to the server
Message sent, waiting for reply
Received raw response: 'b"HMAC_14639[symmetric_33628[/n             ,\n            |`-.__\n            / ' _/\n           ****` \n          /    }\n         /  \\ /\n     \\ /`   \\\\ \n      `\\    /_\\ \n       `~~~~~``~` \n]]"' [187 bytes]
Decoded message '/n             ,
            |`-.__
            / ' _/
           ****`
          /    }
         /  \ /
     \ /`   \\
      `\    /_\
       `~~~~~``~`
' from server
client is done!
```

VPN:
```
$ python VPN.py
VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 61925)
Received client message: 'b'127.0.0.1~IP~65432~port~I would like a TLS Handshake, please!'' [61 bytes]  
connecting to server at IP 127.0.0.1 and port 65432 
server connection established, sending message 'I would like a TLS Handshake, please!'
message sent to server, waiting for reply
Received server response: 'b'D_(9705, 56533)[127.0.0.1~IP~65432~port~(33975, 56533)]'' [55 bytes], forwarding to client
Received client message: 'b'E_(33975, 56533)[33628]'' [23 bytes], forwarding to server
Received server response: 'b"symmetric_33628[Symmetric key '33628' received]"' [47 bytes], forwarding to client
Received client message: 'b'HMAC_22213[symmetric_33628[DOG]]'' [32 bytes], forwarding to server
Received server response: 'b"HMAC_14639[symmetric_33628[/n             ,\n            |`-.__\n          
  / ' _/\n           ****` \n          /    }\n         /  \\ /\n     \\ /`   \\\\ \n      `\\    /_\\ \n       `~~~~~``~` \n]]"' [187 bytes], forwarding to client
VPN is done!
```

SERVER:
```
$ python secure_server.py
Generated public key '(33975, 56533)' and private key '22558'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '127.0.0.1~IP~65432~port~(33975, 56533)'
Connection established, sending certificate '127.0.0.1~IP~65432~port~(33975, 56533)' to the certificate authority to be signed
Received signed certificate 'D_(9705, 56533)[127.0.0.1~IP~65432~port~(33975, 56533)]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 61926)
Received client message: 'b'I would like a TLS Handshake, please!'' [37 bytes]
Sending signed certificate to client: 'D_(9705, 56533)[127.0.0.1~IP~65432~port~(33975, 56533)]' [55 bytes]
Received client encrypted symmetric key: 'b'E_(33975, 56533)[33628]'' [23 bytes]
TLS handshake complete: established symmetric key '33628', acknowledging to client
Received client message: 'b'HMAC_22213[symmetric_33628[DOG]]'' [32 bytes]
Decoded message 'DOG' from client
Client requested a dog. Sending ASCII art.
Responding '/n             ,
            |`-.__
            / ' _/
           ****`
          /    }
         /  \ /
     \ /`   \\
      `\    /_\
       `~~~~~``~`
' to the client
Sending encoded response 'HMAC_14639[symmetric_33628[/n             ,
            |`-.__
            / ' _/
           ****`
          /    }
         /  \ /
     \ /`   \\
      `\    /_\
       `~~~~~``~`
]]' back to the client
server is done!
```

CERTIFICATE AUTHORITY:
```
$ python certificate_authority.py
Certificate Authority started using public key '(46828, 56533)' and private key '9705'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 61916)
Received client message: 'b'$127.0.0.1~IP~65432~port~(33975, 56533)'' [39 bytes]
Signing '127.0.0.1~IP~65432~port~(33975, 56533)' and returning it to the client.
Received client message: 'b'done'' [4 bytes]        
('127.0.0.1', 61916) has closed the remote connection - listening
Connected established with ('127.0.0.1', 61924)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (46828, 56533) to the client
Received client message: 'b'done'' [4 bytes]        
('127.0.0.1', 61924) has closed the remote connection - listening
```

### TLS Handshake Walkthrough

1. The client reaches out to the server, requesting a handshake.
2. The server receives this request, and sends a signed certificate to the client. This details the server's socket information and public key, and gives something for the client to verify the server's validity with. 
3. Using the certificate authority public key, the client verifies the signed certificate's validity. As this one is signed, the client is able to continue the handshake safely, so long as they trust the certificate authority's signature.
4. The client generates a symmetric key, saves it for itself, and sends an encrypted version of it to the server using the server's public key. This way only the server and client have access to the key, and therefore all future commincations involving it -- no interceptors such as the VPN or malicious eavesdroppers will be able to obtain it.
5. The server receives the encrypted symmetric key, decrypts it using its own public key, and saves the symmetric key for future use. Now, both client and server have access to a key without revealing any unencrypted information to outsiders -- and, they can send encrypted messages to eachother in the future. 

### Failures of the Simulation

#### 1. Usage of eval() function
> Python's eval() function is able to take in strings and turn them into functions. This means that if there's an avenue for public input that goes into eval() at any point, anyone can send in malicious code and the program will run it. 
   
#### 2. The certificate authority's public key distribution system
> The certificate authority gives out a public key to anyone that has their socket information and requests it with the string 'key', which is not secure due to how easily these two things can be found/guessed. A person could then request handshakes from servers, and find out who uses which certificate authority by checking which CA key is able to verify the server's signed certificate. This could be used maliciously to decide what certificate authorities and/or servers to target to reach a desired outcome.

### Acknowledgements
- Zoe Plumridge, for helping me work through some of my initial issues with ports and syntax.
- Albert, for the struggles of editing/fixing this assignment on the fly, and for the extension. It was a fun project!

### Client->Server and Server->Client Aplication Layer
This program's application layer has no difference from my project 2 for CSC249 -- I just wanted to add it in again for fun. The syntax is pretty basic: if you message 'CAT' or 'DOG' to the server, you will receive art of whichever one you requested. If you message anything else, you'll receive an error message telling you the required messages. 
