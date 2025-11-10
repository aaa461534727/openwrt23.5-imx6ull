/************************************************************************
#
#  Copyright (c) 2016-2019  CO-CLOUD(SHENZHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2016-9-19
# 
# Unless you and CO-CLOUD execute a separate written software license 
# agreement governing use of this software, this software is licensed 
# to you under the terms of the GNU General Public License version 2 
# (the "GPL"), with the following added to such license:
# 
#    As a special exception, the copyright holders of this software give 
#    you permission to link this software with independent modules, and 
#    to copy and distribute the resulting executable under terms of your 
#    choice, provided that you also meet, for each linked independent 
#    module, the terms and conditions of the license of that module. 
#    An independent module is a module which is not derived from this
#    software.  The special exception does not apply to any modifications 
#    of the software.  
# 
# Not withstanding the above, under no circumstances may you combine 
# this software in any way with any other CO-CLOUD software provided 
# under a license other than the GPL, without CO-CLOUD's express prior 
# written consent. 
#    
# Revision Table
#
# Version     | Name             |Date           |Description
# ------------|------------------|---------------|-------------------
#  1.0.1      |lishengming       |2016-9-19      |Trial Version
#
*************************************************************************/


#ifndef __WIFI_H__
#define __WIFI_H__

/******************************************************************************
 *                               INCLUDES                                     *
 ******************************************************************************/

#include <unistd.h>  
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>  
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <math.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

typedef uint32_t __u32;  // 替换 typedef __uint32_t __u32;
typedef int32_t  __s32;  // 替换 typedef __int32_t __s32;
typedef uint16_t __u16;  // 替换 typedef __uint16_t __u16;
typedef int16_t  __s16;  // 替换 typedef __int16_t __s16;
typedef uint8_t  __u8;   // 替换 typedef __uint8_t __u8;
typedef int 		        SINT32;
typedef unsigned int        UINT32;
typedef short int 	        SINT16;
typedef unsigned short int  UINT16;
typedef char 		        SINT8;

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
//typedef long long int64_t;
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
//typedef unsigned long long u_int64_t;

#define MAX_LEN_OF_MAC_TABLE	544
#define MAX_NUM_OF_CHS			54
#define IFNAMSIZ                16

typedef union _HTTRANSMIT_SETTING {
#ifdef RT_BIG_ENDIAN
        struct {
                u16 MODE:3;  /* Use definition MODE_xxx. */
                u16 iTxBF:1;
                u16 eTxBF:1;
                u16 STBC:1;  /* only support in HT/VHT mode with MCS0~7 */
                u16 ShortGI:1;       /* TBD: need to extend to 2 bits for HE GI */
                u16 BW:2;    /* channel bandwidth 20MHz/40/80 MHz */
                u16 ldpc:1;
                u16 MCS:6;   /* MCS */
        } field;
#else
        struct {
                u16 MCS:6;
                u16 ldpc:1;
                u16 BW:2;
                u16 ShortGI:1;
                u16 STBC:1;
                u16 eTxBF:1;
                u16 iTxBF:1;
                u16 MODE:3;
        } field;
#endif
        u16 word;
} HTTRANSMIT_SETTING, *PHTTRANSMIT_SETTING;

typedef struct _RT_802_11_MAC_ENTRY {
	u8 ApIdx;
	u8 Addr[6];
	u16 Aid;
	u8 Psm;		/* 0:PWR_ACTIVE, 1:PWR_SAVE */
	u8 MimoPs;		/* 0:MMPS_STATIC, 1:MMPS_DYNAMIC, 3:MMPS_Enabled */
	s8 AvgRssi0;
	s8 AvgRssi1;
	s8 AvgRssi2;
	u32 ConnectedTime;
	HTTRANSMIT_SETTING TxRate;
	u32 LastRxRate;
	/*
		sync with WEB UI's structure for ioctl usage.
	*/
	s16 StreamSnr[3];				/* BF SNR from RXWI. Units=0.25 dB. 22 dB offset removed */
	s16 SoundingRespSnr[3];			/* SNR from Sounding Response. Units=0.25 dB. 22 dB offset removed */
	/*	s16 TxPER;	*/					/* TX PER over the last second. Percent */
	/*	s16 reserved;*/
} RT_802_11_MAC_ENTRY, *PRT_802_11_MAC_ENTRY;

typedef struct _RT_802_11_MAC_TABLE {
	long Num;
	RT_802_11_MAC_ENTRY Entry[MAX_LEN_OF_MAC_TABLE];
} RT_802_11_MAC_TABLE, *PRT_802_11_MAC_TABLE;

	
/* --------------------------- SUBTYPES --------------------------- */
/*
 *	Generic format for most parameters that fit in an int
 */
struct	iw_param
{
  __s32 	value;		/* The value of the parameter itself */
  __u8		fixed;		/* Hardware should not use auto select */
  __u8		disabled;	/* Disable the feature */
  __u16 	flags;		/* Various specifc flags (if any) */
};

/*
 *	For all data larger than 16 octets, we need to use a
 *	pointer to memory alocated in user space.
 */
struct	iw_point
{
  caddr_t	pointer;	/* Pointer to the data	(in user space) */
  __u16 	length; 	/* number of fields or size in bytes */
  __u16 	flags;		/* Optional params */
};

/*
 *	A frequency
 *	For numbers lower than 10^9, we encode the number in 'm' and
 *	set 'e' to 0
 *	For number greater than 10^9, we divide it by the lowest power
 *	of 10 to get 'm' lower than 10^9, with 'm'= f / (10^'e')...
 *	The power of 10 is in 'e', the result of the division is in 'm'.
 */
struct	iw_freq
{
	__u32		m;		/* Mantissa */
	__u16		e;		/* Exponent */
	__u8		i;		/* List index (when in range struct) */
};

/*
 *	Quality of the link
 */
struct	iw_quality
{
	__u8		qual;		/* link quality (%retries, SNR or better...) */
	__u8		level;		/* signal level */
	__u8		noise;		/* noise level */
	__u8		updated;	/* Flags to know if updated */
};

/*
 *	Packet discarded in the wireless adapter due to
 *	"wireless" specific problems...
 */
struct	iw_discarded
{
	__u32		nwid;		/* Wrong nwid */
	__u32		code;		/* Unable to code/decode */
	__u32		misc;		/* Others cases */
};

/* ------------------------ WIRELESS STATS ------------------------ */
/*
 * Wireless statistics (used for /proc/net/wireless)
 */
struct	iw_statistics
{
	__u16		status; 	/* Status
					 * - device dependent for now */

	struct iw_quality	qual;		/* Quality of the link
						 * (instant/mean/max) */
	struct iw_discarded discard;	/* Packet discarded counts */
};

/* ------------------------ IOCTL REQUEST ------------------------ */
/*
 * The structure to exchange data for ioctl.
 * This structure is the same as 'struct ifreq', but (re)defined for
 * convenience...
 *
 * Note that it should fit on the same memory footprint !
 * You should check this when increasing the above structures (16 octets)
 * 16 octets = 128 bits. Warning, pointers might be 64 bits wide...
 */
struct	iwreq 
{
	union
	{
		char	ifrn_name[IFNAMSIZ];	/* if name, e.g. "eth0" */
	} ifr_ifrn;

	/* Data part */
	union
	{
		/* Config - generic */
		char		name[IFNAMSIZ];
		/* Name : used to verify the presence of  wireless extensions.
		 * Name of the protocol/provider... */

		struct iw_point essid;	/* Extended network name */
		struct iw_param nwid;	/* network id (or domain - the cell) */
		struct iw_freq	freq;	/* frequency or channel :
					 * 0-1000 = channel
					 * > 1000 = frequency in Hz */

		struct iw_param sens;		/* signal level threshold */
		struct iw_param bitrate;	/* default bit rate */
		struct iw_param txpower;	/* default transmit power */
		struct iw_param rts;		/* RTS threshold threshold */
		struct iw_param frag;		/* Fragmentation threshold */
		__u32		mode;		/* Operation mode */

		struct iw_point encoding;	/* Encoding stuff : tokens */
		struct iw_param power;		/* PM duration/timeout */

		struct sockaddr ap_addr;	/* Access point address */

		struct iw_point data;		/* Other large parameters */
	}	u;
};





#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif /* __WIFI_H__ */
