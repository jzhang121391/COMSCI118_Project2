#include "icmp.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
//#include "sr_checksum.h"


int handle_icmp(struct sr_instance* sr, uint8_t* packet, char* interface, uint8_t type, uint8_t code)
{

//printf("INSIDE HANDLE ICMP ******************* \n");

uint8_t *buf;
size_t buf_len, icmp_len;

/* ICMP header */
struct icmp_hdr *icmpHdr;

/* Ethernet headers */
struct sr_ethernet_hdr *in_eth_hdr;
struct sr_ethernet_hdr *out_eth_hdr;

/* IP headers */
struct ip *in_ip_hdr;
struct ip *out_ip_hdr;

/* Getting packet information */
in_eth_hdr = (struct sr_ethernet_hdr*)packet;
in_ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));


/* each ICMP message type has a different size
 * set up ICMP message with size dictated by the type of message
*/
switch(type)
{
case TYPE_UNREACHABLE:
	icmp_len = SIZE_UNREACHABLE;
	break;
case TYPE_TIMEOUT:
	icmp_len = SIZE_TIMEOUT;
	break;
case TYPE_ECHO_REPLY:
    icmp_len= SIZE_ECHO_REPLY - 28 + ntohs(in_ip_hdr->ip_len);
	break;
case TYPE_TRACEROUTE:
    icmp_len= SIZE_TRACEROUTE; 
	break;
default:
	return -1; //ICMP type not supported
}
buf_len = (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + icmp_len);
buf = (uint8_t*)malloc(buf_len);
bzero(buf, buf_len);

/* sectioning off buf for ethernet and ip header to send ICMP message */

out_eth_hdr = (struct sr_ethernet_hdr*)buf;
out_ip_hdr = (struct ip*)(buf + sizeof(struct sr_ethernet_hdr));

/* setting up ethernet header for ICMP message */
memcpy(out_eth_hdr->ether_dhost, in_eth_hdr->ether_shost, ETHER_ADDR_LEN);
memcpy(out_eth_hdr->ether_shost, in_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
out_eth_hdr->ether_type = htons(ETHERTYPE_IP);

//printf("TYPE OF SERVICE OF RECIEVED IP ADDRESS IS: %X", in_ip_hdr->ip_tos);
//printf("setting up ip header for icmp message");

/* setting up ip header for ICMP message */
out_ip_hdr->ip_hl = 5;
out_ip_hdr->ip_v = 4;
out_ip_hdr->ip_tos = 0;
out_ip_hdr->ip_id = in_ip_hdr->ip_id; //i dont think this matters
out_ip_hdr->ip_off = 0;
out_ip_hdr->ip_ttl = 64; //default value
out_ip_hdr->ip_p = 1; //for ICMP
out_ip_hdr->ip_src = in_ip_hdr->ip_dst;
out_ip_hdr->ip_dst = in_ip_hdr->ip_src;
out_ip_hdr->ip_len = htons(20 + icmp_len);
//out_ip_hdr->ip_sum = htons((uint16_t)ip_checksum(out_ip_hdr));
uint16_t *iphead = (uint16_t*)out_ip_hdr;
uint32_t summ = 0;

//printf("TTL FOR MY SENDING ICMP MESSAGGE IS: %x", out_ip_hdr->ip_ttl);

for(int j = 0; j < 10; j++)
summ += iphead[j];

summ = (summ & 0xFFFF) + (summ >> 16);
summ = (summ & 0xFFFF) + (summ >> 16);

summ = ~summ;

out_ip_hdr->ip_sum = (uint16_t)summ;

/*setting up ICMP Header */
icmpHdr = (struct icmp_hdr*)(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
icmpHdr->type = type;
icmpHdr->code = code;

//printf("type is %d and code is %d \n", icmpHdr->type, icmpHdr->code);

switch(type)
{
case TYPE_UNREACHABLE:
	//copy ip header and first 8 bytes of the original datagram's data
	memcpy( (uint8_t*)(&icmpHdr->field3), in_ip_hdr, sizeof(struct ip) + 8);
	break;
case TYPE_TIMEOUT:
	//copy ip  header and first 8 bytes of the orginal datagram's data
        memcpy( (uint8_t*)(&icmpHdr->field3), in_ip_hdr, sizeof(struct ip) + 8);
        //modify ip_src if this doesnt worki. may be change to interface's iP
	break;
case TYPE_ECHO_REPLY:
	//ID and seq number and copy data into outgoing icmp message
	icmpHdr->field1 = ( (struct icmp_hdr*)( ((uint8_t*)in_ip_hdr) + sizeof(struct ip) ))->field1;
	icmpHdr->field2 = ( (struct icmp_hdr*)( ((uint8_t*)in_ip_hdr) + sizeof(struct ip) ))->field2;
	memcpy((uint8_t*)(&icmpHdr->field3), ((uint8_t*)in_ip_hdr) + 28, ntohs(in_ip_hdr->ip_len) -28);
	break;
case TYPE_TRACEROUTE:
	//
	break;
}

icmpHdr->checksum = 0;
/* calculate ICMP checksum */
size_t num_halfWords = icmp_len/2;
uint16_t *header = (uint16_t*)icmpHdr;
uint32_t sum = 0;

for(int i = 0; i < num_halfWords; i++)
	sum += header[i];

sum = (sum & 0xFFFF) + (sum >> 16);
sum = (sum & 0xFFFF) + (sum >> 16);


sum = ~sum;

icmpHdr->checksum = (uint16_t)sum;

sr_send_packet(sr, buf, buf_len, interface);

free(buf);

return 1;
}
