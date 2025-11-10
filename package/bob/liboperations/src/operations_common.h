#ifndef _LIB_OPERATIONS_FIREWALL_H_
#define _LIB_OPERATIONS_FIREWALL_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

#include "cs_common.h"

typedef enum
{
       OPERATIONS_FALSE,
       OPERATIONS_TRUE,
}OPERATIONS_BOOL;

/*********************************************************************/
/*                        system network port handle                 */
/*********************************************************************/
int wanup_set_net_server(void);
int domain_access_config(void);

extern int dns_genetrate(void);

/*********************************************************************/
/*                        operations network                         */
/*********************************************************************/
OPERATIONS_BOOL CsRealReloadNetwork(void);
OPERATIONS_BOOL CsRealReloadMcm(void);
OPERATIONS_BOOL CsRealReloadStaticRoute(void);
OPERATIONS_BOOL CsRealReloadStaticTunnelRoute(void);
OPERATIONS_BOOL CsRealReloadDhcp(void);
OPERATIONS_BOOL CsRealWanPortDown(void);
OPERATIONS_BOOL CsRealWanPortUp(void);

#if defined(CONFIG_DDNS_SUPPORT)
OPERATIONS_BOOL CsRealReloadDdns(void);
#endif


/*********************************************************************/
/*                        operations system                          */
/*********************************************************************/
OPERATIONS_BOOL CsRealUploadSettings(void);
OPERATIONS_BOOL CsRealReloadFwUpgrade(void);
#if defined(CONFIG_CLOUDUPDATE_SUPPORT)
int forced_cloud_upgrade(void);
OPERATIONS_BOOL CsRealReloadAutoFwUpgrade(void);
OPERATIONS_BOOL CsRealCloudUpgadeCheck(void);
#endif
OPERATIONS_BOOL CsRealReloadUpnpd(void);
OPERATIONS_BOOL CsRealReloadIgmpproxy(void);

/*********************************************************************/
/*                        operations wireless                         */
/*********************************************************************/
OPERATIONS_BOOL CsRealReloadWireless(void);
OPERATIONS_BOOL CsRealReloadWps(void);
OPERATIONS_BOOL CsRealReloadAcl(void);


#endif /* _LIB_OPERATIONS_FIREWALL_H_ */
