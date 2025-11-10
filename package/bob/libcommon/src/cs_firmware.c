#include <sys/mman.h>
#include "cs_common.h"


int firmware_check(char *imagefile, int offset, int len, char *err_msg, char *re_csid)
{
	char meta_info[1024] = { 0 }, tmp_buf[128]={0}, cur_csid[16] = { 0 };

	cJSON *root, *node_array, *item;

	int count, j, ret=0;

	doSystem("/usr/libexec/validate_firmware_image %s",imagefile);

	f_read("/tmp/sysupgrade.meta",meta_info,sizeof(meta_info));

	root = cJSON_Parse(meta_info);
	
	if(root==NULL)
	{
		strcpy(err_msg, "MM_cloud_fw2flash1");
		return 0;
	}

	node_array = cJSON_GetObjectItem(root, "supported_devices");

	if(node_array==NULL)
	{
		cJSON_Delete(root);
		strcpy(err_msg, "MM_cloud_fw2flash1");
		return 0;
	}

	/* check csid */
	// Uci_Get_Str(PKG_PRODUCT_CONFIG, "custom", "csid",  cur_csid);
	Uci_Get_Str(PKG_PRODUCT_CONFIG, "sysinfo", "hard_model",  cur_csid);

	count=cJSON_GetArraySize(node_array);
	for(j=0;j<count;j++)
	{
		item = cJSON_GetArrayItem(node_array, j);
		memset(tmp_buf, 0, sizeof(tmp_buf));
		snprintf(tmp_buf, sizeof(tmp_buf), "%s", item->valuestring);
		if(strstr(tmp_buf,cur_csid)!=NULL)
		{
			ret=1;
			break;
		}
	}
	cJSON_Delete(root);

	return ret;
}

