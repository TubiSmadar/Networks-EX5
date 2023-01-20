#include <stdio.h>
#include <pcap/pcap.h>
#include <strings.h>
#include <net/ethernet.h>

#define TIME 1000 // 1000 = 1 second
#define PROM_MODE 1 // flag
#define STATUS_CODE 0x03ff
#define C_FLAG 0x1000
#define S_FLAG 0x0800
#define T_FLAG 0x0400
#define MAX_PACKET 800
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

///* ICMP Header */
//struct icmpheader {
//    unsigned char icmp_type; // ICMP message type
//    unsigned char icmp_code; // Error code
//    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
//    unsigned short int icmp_id;     //Used for identifying request
//    unsigned short int icmp_seq;    //Sequence number
//} ;
/* Ethernet Header */
struct ethheader
{
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
} ;


/* IP Header */
struct ipheader
{
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
} ;

/*TCP Header*/
struct tcpheader
{

    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset:4;  // 4 bits
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_p;
} ;

struct calculatorheader
{
    uint32_t timestamp;
    uint16_t total_length;
    union
    {
        uint16_t reserved:3,cache_flag:1,steps_flag:1,type_flag:1,status_code:10;
        uint16_t flags;
    };

    uint16_t cache_control;
    uint16_t padding;
    char data[8180];
};

int main(int argc, char *argv[]) {
    char filter[] = "tcp port 9999";
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    char errbuf[PCAP_ERRBUF_SIZE];/* Device to sniff on *//* Error string */



// Set device, can change to any other device in your computer
    char *dev = "lo";

    printf("Device: %s\n", dev);

// Open device for sniffing
    pcap_t *handle;  /* Session handle */

    handle = pcap_open_live(dev, BUFSIZ, PROM_MODE, TIME, errbuf); // BUFSIZ means how many bytes needed PROM_MODE on TIME in milisec
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }


    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
        return(2);
    }

// Compile the filter
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }

// Set the filter to sniff
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    pcap_loop(handle, -1, got_packet, NULL);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);// put in a txt file as needed
    /* Close the session */
    pcap_close(handle);
    printf("test\n");
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
//    open a new file
    FILE *fp = fopen("315638577_otherID ","a+");
            if (fp == NULL) {
                perror("Error opening file");
                return;
            }

/* IP Header */
    struct ipheader *ip_header;
    ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));

/* TCP Header */
    struct tcpheader *tcp_header;
    tcp_header = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

/* exFivePacket */
    struct calculatorheader *app_packet;
    app_packet = (struct calculatorheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
    // Print to file
    fprintf(fp, "source ip: %s\n" , inet_ntoa(ip_header->iph_sourceip));
    fprintf(fp, "destination ip: %s\n" , inet_ntoa(ip_header->iph_destip));
    fprintf(fp, "source_port: %hu\n" , ntohs(tcp_header->src_port));
    fprintf(fp, "destination_port: %hu\n" , ntohs(tcp_header->dst_port));
    fprintf(fp, "timestamp: %hu, ", ntohl(app_packet->timestamp));
    fprintf(fp, "total_length: %hu, ", ntohs(app_packet->total_length));
    fprintf(fp, "cache_flag: %hu, ", (ntohs(app_packet->flags) & C_FLAG) >> 12);
    fprintf(fp, "steps_flag: %hu, ", (ntohs(app_packet->flags) & S_FLAG) >> 11);
    fprintf(fp, "type_flag: %hu, ", (ntohs(app_packet->flags) & T_FLAG) >> 10);
    fprintf(fp, "status_code: %hu, ", (ntohs(app_packet->flags) & STATUS_CODE));
    fprintf(fp, "cache_control: %hu \n", ntohs(app_packet->cache_control));
    fprintf(fp, "data: \n");
    for (int i=0; i<MAX_PACKET; i++)
    {
        if (i%16 == 0)
        {
            fprintf(fp,"\n");
        }
        fprintf(fp, " %02X", (unsigned char) packet[i]);
    }
    fprintf(fp, "\n\n");
// close file.
    printf("packet received\n");
    fclose(fp);


        }
