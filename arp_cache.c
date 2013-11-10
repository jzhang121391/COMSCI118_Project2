#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "sr_protocol.h"
#include "sr_if.h"
#include "arp_cache.h"


void AC_init(struct arp_cache *AC)
{
	AC->length=0;
	int i;
	for(i=0; i<MAX_AC_LEN; i++)
	{
		AC->list[i].ip_addr=0;
		//set all ip addresses to 0; indicates that entry is empty
	}
	pthread_mutex_init(&(AC->AC_mutex), NULL);
	pthread_create(&(AC->thread), 0, AC_update, AC);
}
void AC_insert(struct arp_cache* AC, uint32_t ip_addr, unsigned char* mac_addr)
{
	int full=1;
	int i;
	pthread_mutex_lock(&(AC->AC_mutex));
	{
		//look for empty slot
		for(i=0; i<MAX_AC_LEN; i++)
		{
			if(AC->list[i].ip_addr==0)
			{
				full=0;
				break;
			}
			if(AC->list[i].ip_addr==ip_addr)
				return;
		}
		//if no empty slots, start from the top of list
		if(full)
			i=0;
		AC->length++;
		//set values of arp entry 	
		AC->list[i].ip_addr = ip_addr;
		
		memcpy(AC->list[i].mac_addr, mac_addr, ETHER_ADDR_LEN);
		//strcpy(AC->list[i].interface, iface);
		AC->list[i].age=time(NULL); 
	}
	pthread_mutex_unlock(&(AC->AC_mutex));
}

struct arp_cache_item *AC_search(struct arp_cache *AC, uint32_t ip_addr)
{	
	int i;
	struct arp_cache_item* temp=NULL;
	pthread_mutex_lock(&(AC->AC_mutex));
	{	
		for(i=0; i<MAX_AC_LEN; i++)
		{
			if(AC->list[i].ip_addr == ip_addr){
				temp= &AC->list[i];
				break;
			}
		}
	}
	pthread_mutex_unlock(&(AC->AC_mutex));
	return temp;
}

int AC_erase(struct arp_cache *AC, uint32_t ip_addr)
{
	int i;
	int success=0;
	pthread_mutex_lock(&(AC->AC_mutex));
	{
		for(i=0; i<MAX_AC_LEN; i++)
		{
			if(AC->list[i].ip_addr==ip_addr)
			{
				AC->list[i].ip_addr=0;
				success= 1;
			}
		}
	}
	pthread_mutex_unlock(&(AC->AC_mutex));
	return success;
}

void* AC_update(void *arg)
{
	struct arp_cache *AC=(struct arp_cache*)arg;
	time_t current;
	//loop through the list and check if entry has expired
	int i;
	while(1)
	{
		sleep(1);
		current=time(NULL);
		pthread_mutex_lock(&(AC->AC_mutex));
		{
			for(i=0; i<MAX_AC_LEN; i++)
			{
				if(AC->list[i].ip_addr!=0)
				{
					if(current - AC->list[i].age > 15){
						AC->list[i].ip_addr=0;
						AC->length--;
					}
				}
			}
		}
		pthread_mutex_unlock(&(AC->AC_mutex));
	}
}
