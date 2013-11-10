
#ifndef ARP_CACHE_H
#define ARP_CACHE_H

#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"

#define MAX_AC_LEN 100
#define ARP_EXP_TIME

struct arp_cache_item
{	
	uint32_t ip_addr;
	unsigned char mac_addr[ETHER_ADDR_LEN];
	time_t age;
};

struct arp_cache
{
	struct arp_cache_item list[MAX_AC_LEN];
	int length;
	pthread_mutex_t AC_mutex;
	pthread_t thread;
};

void AC_init(struct arp_cache *AC);
void AC_insert(struct arp_cache *AC, uint32_t ip_addr, unsigned char* mac_addr);
struct arp_cache_item* AC_search(struct arp_cache *AC, uint32_t ip_addr);
int AC_erase(struct arp_cache *AC, uint32_t ip_addr);
void* AC_update(void *arg);

#endif
