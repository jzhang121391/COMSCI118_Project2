#ifndef ARP_REQUEST_H
#define ARP_REQUEST_H

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp_cache.h"
#include "icmp.h"

struct ip_packet
{
	uint8_t *packet_data;
	unsigned int packet_length;
	struct ip_packet *next;
};

struct arp_request
{
	uint32_t target_ip;
	struct sr_if *interface;
	struct ip_packet *packet_queue;
	size_t t_count;
	struct arp_request *next;
};

void* update_arp_req(void *arg);
void arp_request_queue_init(struct sr_instance *sr);
void make_arp_request(struct sr_instance *sr, uint32_t target_ip, struct sr_if *interface,
	uint8_t *packet_data, unsigned int packet_length);

#endif
