
#ifndef _LIB_FIREWALL_PRIVATE_H_
#define _LIB_FIREWALL_PRIVATE_H_

#define SCRIPT_FIREWALL		"/etc/firewall_script.sh"

/* firewall_api.c */
static const char ipt_fname[] = "/tmp/iptables.rules";
static FILE *ipt_file;
#if defined(USE_IPV6)
static const char ip6t_fname[] = "/tmp/ip6tables.rules";
static FILE *ip6t_file;
#endif
static int ipt_fopen(void);
static void ipt_write(const char *format, ...);
static void ipt_fclose(void);
static int ipt_restore(void);
#if defined(USE_IPV6)
static int ip6t_fopen(void);
static void ip6t_write(const char *format, ...);
static void ip6t_fclose(void);
static int ip6t_restore(void);
#endif

#endif /* _LIB_FIREWALL_PRIVATE_H_ */
