This project and program was written and created for the Centre for Cyberseucurity Insitutute, Vocational Training Programme, Network Research Module.

The aim of the project was to demonstrate the importance of ensuring that all steps of connection is secured properly. To demonstrate this, Nipe was used for anonymity and an attempt to keep the true path of the data transfer confidential, but due to usage of FTP dor downloading the results, it was trivial for an adversary to sniff the packets' data using a common packet tracing program like wireshark, as shown in the report. When a more secure protocol, SFTP, was used, it was not possible to easily sniff the data out. 

The bash script does the following:
1. Automation of checks of requried installed progams on the user's machine, and install them if missing. Progams such as nmap and nipe, were checked.
2. User input of various ip address and URLs, automated logging into the remote server, and remote probing of said input.
3. Deliberately downloading the results using an insecure protocol, FTP.

In the report, a more secure protocol, SFTP, was demonstrated to show how using it in place of FTP prevents data leaks by using proper authentication methods to secure data transfers.
