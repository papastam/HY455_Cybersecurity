# Cybersecurity Lab [HY455](https://csd.uoc.gr/~hy455)

This repository contains the assignments of the course [HY455](https://csd.uoc.gr/~hy455) I attended during the spring semester of 2023 at the [Computer Science Department](https://www.csd.uoc.gr) of the [University of Crete](https://www.uoc.gr). During this course, we learned about the basic principles of computer security, the most common attacks and how to defend against them. We also learned about the most common vulnerabilities in web applications and how to exploit them.

For most of the assignments we used the [Kali Linux](https://www.kali.org) distribution, which is a Linux distribution based on Debian and designed for digital forensics and penetration testing.

## [Assignment 1](./assignment1/) (Target Profiling)

For this assignment each student was assigned a fellow student to profile and collect as much info as possible. The assignemnt also included some privacy concerning questions that we had to answer based on sourced that we found online.

The results of the assignment are described in the [assignment's report](./assignment1/report.pdf).

_For the shake of my colleague's privacy, The collected info is censored from the report_

## [Assignment 2](./assignment2/) (Wireless Attacks)

For this assignment we had to perform a series of attacks on a wireless network. The attacks included:

- Pawning hidden SSIDs _(`airodump-ng`)_
- MAC address spoofing _(`macchanger`)_
- Network Scanning _(`airodump-ng`)_
- Cracking WEP passwords _(`aircrack-ng`)_
- Cracking WPA passwords (Dictionary attack) _(`aircrack-ng`)_
- Attacking WPS (Pixie Dust attack) _(`reaver`)_

The methodology and the results of the attacks are described in the [assignment's report](./assignment2/report.pdf).

## [Assignment 3](./assignment3/) (Password Cracking)

For this assignment we had to perform a series of attacks on some given password hashes. The attacks included:

- Hash Identification _(`hashid`)_
- Dictionary attack _(`john`)_
- Wordlist generation _(`cupp`, `mentalist`)_
- Zip file password cracking _(`rar2john`, `john`)_
- Pattern based password cracking _(`john`)_

The methodology and the results of the attacks are described in the [assignment's report](./assignment3/report.pdf).

## [Assignment 4](./assignment4/) (Intrustion Detection)

For this assignment we had to implement some basic intrusion detection systems. The systems included:

- Configuring `Snort` and creating some basic rules
- Configuring a `Snort` Frontend platform
- Using `Snort` to identify `WannaCry` traffic
- `Wireshark` flag capture

The methodology and the results of the attacks are described in the [assignment's report](./assignment4/report.pdf).

## [Assignment 5](./assignment5/) (Reverse Engineering)

For this assignment we had to perform some basic reverse engineering tasks. The assignment required us to reverse engeneer two "programs":

- A simple [passowrd manager](./assingment5/password_manager) 

- A simpler implementation of the `WannaCry` ransomware (called [WannaBeCry](./assignment5/wannabecry)) 

Both programs were written in `C` and compiled for `x86_64` architecture. For the reverse engineering we used the `Ghidra` tool.

The methodology and the results of the attacks are described in the [assignment's report](./assignment5/report.pdf).

## [Assignment 6](./assignment6/) (Live Pentesting)

This assignment was the most interesting one. For this assignment we had to perform a series of attacks on a live system. The system was running in a virtual machine and we had to perform the attacks from our own machine. The attacks included:

- Network scanning _(`nmap`)_
- Service enumeration _(`nmap`)_
- Hash identification and cracking _(`hashid`, `john`)_
- Directory enumeration _(`dirbuster`)_
- PHP code injection
- Reverse shell _(`netcat`)_
- Host filesystem enumeration _(`find`, `lenpeas`)_
- Privilege escalation _(`sudo`, `linpeas`)_

The methodology and the results of the attacks are described in the [assignment's report](./assignment6/report.pdf).

## [Assignment 7](./assignment7/) (Vulnerability Assessment)

For this assignent we had to create a simple python tool (alongside a mySQL database) that could preform the following actions:

- Fetch all `CVE`s from the [NVD](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) database
- Fetch all vaulnerabilities from the [exploit-db](https://www.exploit-db.com/) database
- Enumerate all the installed packages on the system
- Querry the database or NVD for specific `CVE`s (based on `CWE`, Pub. Date, etc.)
- Detect installed packages with associated `CVE`s and report them to the user.

The tool can be executed by running the [assignment7.py](./assignment7/assignment7.py) file. 


Preqrequisites:
- Python 3.8
- MySQL 8.0.25
- MySQL Connector/Python 8.0.25
- Change the credentials in the [assignment7.py](./assignment7/assignment7.py) (line 10-15) file to match your database credentials.

The tool's usage is described in the [assignment's report](./assignment7/report.pdf).