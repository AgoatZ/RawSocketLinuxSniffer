#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 17
#define BUFFMAXSIZE 65536

void print_tcp_packet(char *buffer, int size);
void print_udp_packet(char *buffer, int size);
void print_icmp_packet(char *buffer, int size);
void print_ip_header(char *buffer);
void print_data(char *data, int size);
void process_packet(unsigned char *buffer, int size);

struct iphdr *ipv4_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;
struct icmp *icmp_header;
struct sockaddr_in source, destination;

int main()
{
    int raw_socket;
    unsigned char buffer[BUFFMAXSIZE];
    socklen_t saddr_size;
    int data_size;

    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0)
    {
        perror("Socket creation error");
        return 1;
    }

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        saddr_size = sizeof(source);
        data_size = recvfrom(raw_socket, buffer, BUFFMAXSIZE, 0, (struct sockaddr *)&source, &saddr_size);
        if (data_size < 0)
        {
            perror("Recvfrom function error");
            return 1;
        }

        process_packet(buffer, data_size);
    }

    close(raw_socket);
    return 0;
}

void print_tcp_packet(char *buffer, int size)
{
    unsigned short ip_header_length;

    ipv4_header = (struct iphdr *)buffer;
    ip_header_length = (unsigned int)(ipv4_header->ihl) * 4;
    tcp_header = (struct tcphdr *)(buffer + ip_header_length);

    printf("+++++++++++++++++++TCP Packet+++++++++++++++++++\n\n");
    print_ip_header(buffer);
    printf("TCP Header:\n");
    printf("|-- Source Port: %u\n", ntohs(tcp_header->th_sport));
    printf("|-- Destination Port: %u\n", ntohs(tcp_header->th_dport));
    printf("|-- Sequence Number: %u\n", ntohl(tcp_header->seq));
    printf("|-- Acknowledge Number: %u\n", ntohl(tcp_header->ack_seq));
    printf("|-- Header Length: %d DWORDS or %d BYTES\n", (unsigned int)tcp_header->doff, (unsigned int)tcp_header->doff * 4);
    printf("|-- CWR Flag: %d\n", (unsigned int)(tcp_header->th_flags & 128) / 128);
    printf("|-- ECN Flag: %d\n", (unsigned int)(tcp_header->th_flags & 64) / 64);
    printf("|-- Urgent Flag: %d\n", (unsigned int)tcp_header->urg);
    printf("|-- Acknowledgement Flag: %d\n", (unsigned int)tcp_header->ack);
    printf("|-- Push Flag: %d\n", (unsigned int)tcp_header->psh);
    printf("|-- Reset Flag: %d\n", (unsigned int)tcp_header->rst);
    printf("|-- Synchronise Flag: %d\n", (unsigned int)tcp_header->syn);
    printf("|-- Finish Flag: %d\n", (unsigned int)tcp_header->fin);
    printf("|-- Window: %d\n", ntohs(tcp_header->th_win));
    printf("|-- Checksum: %d\n", ntohs(tcp_header->check));
    printf("|-- Urgent Pointer: %d\n", tcp_header->urg_ptr);

    printf("\n----------------------Data----------------------\n");
    printf("IP Header:\n");
    print_data(buffer, ip_header_length);
    printf("TCP Header:\n");
    print_data(buffer + ip_header_length, (unsigned int)(tcp_header->doff) * 4);
    printf("Data Payload:\n");
    print_data(buffer + ip_header_length + (unsigned int)(tcp_header->doff) * 4, size - (sizeof(struct ethhdr) + (unsigned int)(tcp_header->doff) * 4 + (ip_header_length)));
    printf("\n\n");
    fflush(NULL);
}

void print_udp_packet(char *buffer, int size)
{
    unsigned short ip_header_length;

    ipv4_header = (struct iphdr *)buffer;
    ip_header_length = (unsigned int)(ipv4_header->ihl) * 4;
    udp_header = (struct udphdr *)(buffer + ip_header_length);

    printf("+++++++++++++++++++UDP Packet+++++++++++++++++++\n\n");
    print_ip_header(buffer);
    printf("\nUDP Header\n");
    printf("|-- Source Port : %d\n", ntohs(udp_header->source));
    printf("|-- Destination Port : %d\n", ntohs(udp_header->dest));
    printf("|-- UDP Length : %d\n", ntohs(udp_header->len));
    printf("|-- UDP Checksum : %d\n", ntohs(udp_header->check));

    printf("\n----------------------Data----------------------\n");
    printf("IP Header:\n");
    print_data(buffer, ip_header_length);
    printf("UDP Header:\n");
    print_data(buffer + ip_header_length, sizeof(struct udphdr));
    printf("Data Payload:\n");
    print_data(buffer + ip_header_length + sizeof(struct udphdr), size - (sizeof(struct ethhdr) + sizeof(struct udphdr) + ip_header_length));
    printf("\n\n");
    fflush(NULL);
}

void print_icmp_packet(char *buffer, int size)
{
    unsigned short ip_header_length;

    ipv4_header = (struct iphdr *)buffer;
    ip_header_length = (unsigned short)(ipv4_header->ihl) * 4;
    icmp_header = (struct icmp *)(buffer + ip_header_length);

    printf("+++++++++++++++++++ICMP Packet+++++++++++++++++++\n\n");
    print_ip_header(buffer);
    printf("\nICMP Header\n");
    printf("|-- Type: %d\n", (unsigned int)(icmp_header->icmp_type));

    if ((unsigned int)(icmp_header->icmp_type) == 11)
    {
        printf("TTL Expired\n");
    }
    if ((unsigned int)(icmp_header->icmp_type) == 0)
    {
        printf("ICMP Echo Reply\n");
    }

    printf("|-- Code: %d\n", (unsigned int)(icmp_header->icmp_code));
    printf("|-- Checksum: %d\n", ntohs(icmp_header->icmp_cksum));
    printf("|-- ID: %d\n", ntohs(icmp_header->icmp_hun.ih_idseq.icd_id));
    printf("|-- Sequence: %d\n", ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq));

    printf("\n----------------------Data----------------------\n");
    printf("IP Header:\n");
    print_data(buffer, ip_header_length);
    printf("ICMP Header:\n");
    print_data(buffer + ip_header_length, sizeof(struct icmp));
    printf("Data Payload:\n");
    print_data(buffer + ip_header_length + sizeof(struct icmp), size - (sizeof(struct ethhdr) + sizeof(struct icmp) + ip_header_length));
    printf("\n\n");
    fflush(NULL);
}

void print_ip_header(char *buffer)
{
    unsigned short ip_header_length;

    ipv4_header = (struct iphdr *)buffer;
    ip_header_length = (unsigned short)(ipv4_header->ihl) * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipv4_header->saddr;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = ipv4_header->daddr;

    printf("\nIP Header\n");
    printf("|-- IP Version: %d\n", (unsigned int)ipv4_header->version);
    printf("|-- IP Header Length: %d DWORDS or %d Bytes\n", (unsigned short)ipv4_header->ihl, ip_header_length);
    printf("|-- Type Of Service: %d\n", (unsigned int)ipv4_header->tos);
    printf("|-- IP Total Length: %d Bytes(Size of Packet)\n", ntohs(ipv4_header->tot_len));
    printf("|-- Identification: %d\n", ntohs(ipv4_header->id));
    printf("|-- Fragment Offset: %d\n", (unsigned int)ipv4_header->frag_off);
    printf("|-- TTL: %d\n", (unsigned int)ipv4_header->ttl);
    printf("|-- Protocol: %d\n", (unsigned int)ipv4_header->protocol);
    printf("|-- Checksum: %d\n", ntohs(ipv4_header->check));
    printf("|-- Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("|-- Destination IP: %s\n", inet_ntoa(destination.sin_addr));
    fflush(NULL);
}

void print_data(char *data, int size)
{
    char add, line[17], chr;
    int i, j;

    for (i = 0; i < size; i++)
    {
        chr = data[i];
        printf(" %.2x", (unsigned char)chr);                      /*Print Hexadecimal*/
        add = (chr > 31 && chr < 129) ? (unsigned char)chr : '.'; /*Add char to line*/
        line[i % 16] = add;
        if (i != 0 && (i + 1) % 16 == 0 || i == size - 1)
        {
            line[i % 16 + 1] = '\0';
            printf("          ");

            for (j = strlen(line); j < 16; j++)
            {
                printf("   ");
            }
            printf("%s \n", line);
        }
    }
    printf("\n");
    fflush(NULL);
}

void process_packet(unsigned char *buffer, int size)
{
    struct ethhdr *eth_header = (struct ethhdr *)buffer;
    ipv4_header = (struct iphdr *)buffer + sizeof(struct ethhdr);
    int p = ((unsigned int)(ipv4_header->protocol));
    
    switch (p)
    {
        case ICMP:
            print_icmp_packet(buffer + sizeof(struct ethhdr), size);
            break;
        case IGMP:
            break;
        case TCP:
            print_tcp_packet(buffer + sizeof(struct ethhdr), size);
            break;
        case UDP:
            print_udp_packet(buffer + sizeof(struct ethhdr), size);
            break;
        default:
            break;
    }
}
