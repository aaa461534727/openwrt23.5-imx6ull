#ifndef __CS_BOARD_H__
#define __CS_BOARD_H__

#include "cs_common.h"

typedef struct sim_slot {
    char *idx;
    char *lable;
    char *value;
}sim_slot_t;

typedef struct net_interface {
    char idx[8];
    char lable[32];
	char value[32];
}net_interface_t;

typedef struct serial_port {	
    char *idx;
    char *name;
    char *port;
}serial_port_t;

extern sim_slot_t sim_slot_list[];
extern serial_port_t serial_port_list[];

extern int get_interface_list(net_interface_t interface_list[]);

#endif

