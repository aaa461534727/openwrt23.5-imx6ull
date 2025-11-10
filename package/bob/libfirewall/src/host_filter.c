
int host_filter_add(const char *host, const int group_id)
{
	char buf[256];
	sprintf(buf, "+%s %d", host, group_id);

	return f_write_string("/proc/host_list", buf, 0, 0);
}

int host_filter_del(const char *host)
{
	char buf[256];
	sprintf(buf, "-%s", host);

	return f_write_string("/proc/host_list", buf, 0, 0);
}

int host_filter_flush(void)
{
	return f_write_string("/proc/host_list", "/", 0, 0);
}

void dpi_filter_url(void)
{
	int i, i_enable;

	char rules[4096], rule[128];

	char url[128];

	Uci_Get_Int(PKG_CSFW_CONFIG, "url",   "enable", &i_enable);

	memset(rules,0,sizeof(rules));
	Uci_Get_Str(PKG_CSFW_CONFIG, "url", "rules",  rules);

	if (is_module_loaded("host_filter")){
		host_filter_flush();
		module_smart_unload("host_filter", 0);
	}

	if(i_enable==0 || strlen(rules)==0){
		return;
	}

	module_smart_load("host_filter", NULL);
	host_filter_flush();

	i=0;
	while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 )
	{
		if ((get_nth_val_safe(0, rule, ',', url, sizeof(url)) == -1))
		{
			continue;
		}

		host_filter_add(url,1);
	}

}

