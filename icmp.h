#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_protocol.h"
struct sr_instance; 
/* ICMP Header struct definition */
struct icmp_hdr
{
uint8_t type;
uint8_t code;
uint16_t checksum;
uint16_t field1;
uint16_t field2;
uint16_t field3;
uint16_t field4;
uint32_t field5;
} __attribute__ ((packed));

/* ICMP type fields */
#define TYPE_UNREACHABLE 3
#define CODE_PORT_UNREACHABLE 3
#define SIZE_UNREACHABLE 36

#define TYPE_TIMEOUT 11
#define CODE_TIMEOUT 0
#define SIZE_TIMEOUT 36

#define TYPE_ECHO_REPLY 0
#define CODE_ECHO_REPLY 0
#define SIZE_ECHO_REPLY 8

#define TYPE_TRACEROUTE 30
#define SIZE_TRACEROUTE 20

#define PING_REQUEST 8



int handle_icmp(struct sr_instance* sr, uint8_t* packet, char* interface ,uint8_t type, uint8_t code);



#endif /*SR_ICMP_H */
