#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h> 
#include <setjmp.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <time.h>

#define NETLINK_USER 30     //netlink传递数据编号
#define TYPE_STRING 0x01
#define TYPE_HEX    0x02
#define TYPE_INT    0x03
#define TYPE_FLOAT  0x04

#endif
