# Raw Socket Simple Packet Tracer

## Description

This is a simple packet tracer, written in C for Linux environment.
It utilizes the Raw Socket technology, and uses the socket as the sniffer.
By default, it will process only TCP, UDP, and ICMP Packets.

## Getting Started

### Compiling and Running

1. Compile
```
gcc sniffer.c -o sniffer
```
2. Run as root
```
sudo ./sniffer
```
3. Watch packets fly