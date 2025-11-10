#include "cs_board.h"

sim_slot_t sim_slot_list[] = 
{
#if defined(CONFIG_BOARD_F535)
	{"1", "sim1"  , "slot1"},
	{"2", "sim2"  , "slot2"},
#else
	{"1", "sim1"  , "slot1"},
#endif
	{NULL, NULL  , NULL},
};

serial_port_t serial_port_list[] = 
{
#if defined(CONFIG_BOARD_D520)
	{"1", "485A", "/dev/ttyS3"},
	{"2", "485B", "/dev/ttyS7"},
#endif
	{NULL, NULL , NULL},
};


int get_interface_list(net_interface_t interface_list[])
{
	int idx = 0, i = 0;
	char if_name[32] = {0}, section_key[64] = {0};

	snprintf(interface_list[idx].idx, sizeof(interface_list[idx].idx), "%d", idx);
	snprintf(interface_list[idx].lable, sizeof(interface_list[idx].lable), "LAN");
	snprintf(interface_list[idx].value, sizeof(interface_list[idx].value), "%s", "br-lan");
	
	idx++;

	for(i = 0; i < 4; i++) {
		snprintf(section_key, sizeof(section_key), "modem%d_ifname", i + 1);
		memset(if_name, 0, sizeof(if_name));
		datconf_get_by_key(TEMP_MODEM_FILE, section_key, if_name, sizeof(if_name));
		if(strlen(if_name) > 0) {
			snprintf(interface_list[idx].idx, sizeof(interface_list[idx].idx), "%d", idx);
			snprintf(interface_list[idx].lable, sizeof(interface_list[idx].lable), "Modem%d", i + 1);
			snprintf(interface_list[idx].value, sizeof(interface_list[idx].value), "%s", if_name);
			idx++;
		}
		else {
			break;
		}
	}
	
#if defined(WIFI_SUPPORT)
	snprintf(interface_list[idx].idx, sizeof(interface_list[idx].idx), "%d", idx);
	snprintf(interface_list[idx].lable, sizeof(interface_list[idx].lable), "%s","WIFI 2.4G");
	snprintf(interface_list[idx].value, sizeof(interface_list[idx].value), "%s",WL_IF[W24G_IF].ifname);
	idx++;

#if defined(BOARD_HAS_5G_RADIO)
	snprintf(interface_list[idx].idx, sizeof(interface_list[idx].idx), "%d", idx);
	snprintf(interface_list[idx].lable, sizeof(interface_list[idx].lable), "%s","WIFI 5G");
	snprintf(interface_list[idx].value, sizeof(interface_list[idx].value), "%s",WL_IF[W58G_IF].ifname);
	idx++;
#endif

#endif

	return idx;
}

