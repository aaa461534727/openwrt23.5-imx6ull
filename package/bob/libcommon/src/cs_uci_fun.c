#include "cs_uci_fun.h"

UCI_FUN_BOOL Uci_Get_Str(int title, const char *section, const char *option, char *value)
{
	char cli_str[CMD_STR_LEN];
	struct cs_uci_get_context* uci_lib = NULL;

	if((title <= PKG_UNDEFINE)||(option == NULL)||(value == NULL))
	{
		//printf("Uci_Get_Str: invalid pointer!\n");
		return UCI_FUN_FALSE;
	}
	
	memset(cli_str, 0, CMD_STR_LEN);
	
	uci_lib = cs_uci_get_uci_context_nla(title, NULL);
	
	snprintf(cli_str,CMD_STR_LEN,"%s.%s.%s",PKG_ID_TOFILE(title),section,option);

	cs_uci_get_option(uci_lib,cli_str,value);

	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Get_Str_By_Section_Index(int title,char *section_type,int index, char *option,char *value)
{
	char cli_str[CMD_STR_LEN];
	struct cs_uci_get_context* uci_lib = NULL;

	if((title <= PKG_UNDEFINE)||(option == NULL)||(value == NULL))
	{
		return UCI_FUN_FALSE;
	}
	
	memset(cli_str, 0, CMD_STR_LEN);
	
	uci_lib = cs_uci_get_uci_context_nla(title, NULL);
	
	snprintf(cli_str,CMD_STR_LEN,"%s.@%s[%d].%s",PKG_ID_TOFILE(title),section_type,index,option);

	cs_uci_get_option(uci_lib,cli_str,value);

	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Get_Int_By_Section_Index(int title,char *section_type,int index, char *option,int *value)
{
	
	char value_str[RESULT_STR_LEN] ={0};
		
	if(UCI_FUN_FALSE == Uci_Get_Str_By_Section_Index(title,section_type,index,option,value_str))
	{
		printf("Uci_Get_Str_By_Section_Index: Uci_Get_Str_By_Section_Index Failed!\n");
		return UCI_FUN_FALSE;
	}
	
	*value = atoi(value_str);
	

	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Get_Int(int title, const char *section, const char *option, int *value)
{
	char value_str[RESULT_STR_LEN] ={0};
	*value=0;

	if(UCI_FUN_FALSE == Uci_Get_Str(title,section,option,value_str))
	{
		printf("Uci_Get_Int: Uci_Get_Str Failed!\n");
		return UCI_FUN_FALSE;
	}

	*value = atoi(value_str);

	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Get_Long(int title, const char *section, const char *option, long *value)
{
	char value_str[RESULT_STR_LEN] ={0};
	
	if(UCI_FUN_FALSE == Uci_Get_Str(title,section,option,value_str))
	{
		printf("Uci_Get_Int: Uci_Get_Str Failed!\n");
		return UCI_FUN_FALSE;
	}

	*value = strtoul(value_str,0,10);

	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Get_Long_Long(int title, const char *section, const char *option, long long *value)
{
	char value_str[RESULT_STR_LEN] ={0};
	
	if(UCI_FUN_FALSE == Uci_Get_Str(title,section,option,value_str))
	{
		printf("Uci_Get_Int: Uci_Get_Str Failed!\n");
		return UCI_FUN_FALSE;
	}

	*value = strtoull(value_str,0,10);

	return UCI_FUN_TRUE;
}



UCI_FUN_BOOL Uci_Set_Str(int title, const char *section, const char *option, char *value)
{
	char cmd[LONG_BUFF_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(option == NULL)||(value == NULL))
	{
		//printf("Uci_Get_Str: invalid pointer!\n");
		return UCI_FUN_FALSE;
	}

	snprintf(cmd, sizeof(cmd), "uci -c %s set %s.%s.%s=\"%s\"", \
		PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section,option,value);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Add_Interface(int title, const char *section, char *value)
{
	char cmd[LONG_BUFF_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(value == NULL))
	{
		//printf("Uci_Get_Str: invalid pointer!\n");
		return UCI_FUN_FALSE;
	}

	snprintf(cmd, sizeof(cmd), "uci -c %s set %s.%s=\"%s\"", \
		PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section,value);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Get_Interface(int title, const char *section, char *value)
{
	char cli_str[CMD_STR_LEN];
	struct cs_uci_get_context* uci_lib = NULL;

	if((title <= PKG_UNDEFINE)||(value == NULL))
	{
		//printf("Uci_Get_Str: invalid pointer!\n");
		return UCI_FUN_FALSE;
	}
	
	memset(cli_str, 0, CMD_STR_LEN);
	
	uci_lib = cs_uci_get_uci_context_nla(title, NULL);
	
	snprintf(cli_str,CMD_STR_LEN,"%s.%s",PKG_ID_TOFILE(title),section);

	cs_uci_get_option(uci_lib,cli_str,value);

	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Add_List(int title, const char *section, const char *option, char *value)
{
	char cmd[CMD_STR_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(option == NULL)||(value == NULL))
	{
		return UCI_FUN_FALSE;
	}
	
	snprintf(cmd, sizeof(cmd), "uci -c %s add_list %s.%s.%s=\"%s\"", \
		PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section,option,value);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Del_List(int title, const char *section, const char *option, char *value)
{
	char cmd[CMD_STR_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(option == NULL)||(value == NULL))
	{
		return UCI_FUN_FALSE;
	}
	
	snprintf(cmd, sizeof(cmd), "uci -c %s del_list %s.%s.%s=\"%s\"", \
		PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section,option,value);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Del_List_All(int title, const char *section, const char *option)
{
	char cmd[CMD_STR_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(option == NULL))
	{
		return UCI_FUN_FALSE;
	}
	snprintf(cmd, sizeof(cmd), "uci -c %s delete %s.%s.%s", \
	PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section,option);
	CsteSystem(cmd,CSTE_PRINT_CMD);

	return UCI_FUN_TRUE;
}


UCI_FUN_BOOL Uci_Add_Section(int title, const char *section_type)
{
	char cmd[CMD_STR_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(section_type == NULL))
	{
		return UCI_FUN_FALSE;
	}
	
	snprintf(cmd, sizeof(cmd), "uci -c %s add %s %s >/dev/null", \
		PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section_type);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Del_Section(int title, const char *section_name)
{
	char cmd[CMD_STR_LEN] = {0};

	if((title <= PKG_UNDEFINE)||(section_name == NULL))
	{
		return UCI_FUN_FALSE;
	}
	
	snprintf(cmd, sizeof(cmd), "uci -c %s delete %s.%s >/dev/null", \
		PKG_FILE_PATH(title),PKG_ID_TOFILE(title),section_name);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Commit(int title)
{
	char cmd[CMD_STR_LEN] = {0};

	if(title <= PKG_UNDEFINE)
	{
		return UCI_FUN_FALSE;
	}
	
	snprintf(cmd, sizeof(cmd), "uci -c %s commit %s", PKG_FILE_PATH(title),PKG_ID_TOFILE(title));
	CsteSystem(cmd,CSTE_PRINT_CMD);
	
	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Get_Str_By_Idx(int title, const char *section, int idx, const char *option, char *value)
{
	char buff[CMD_STR_LEN] = { 0 };

	if ( idx > 1 )
		snprintf(buff, CMD_STR_LEN, "%s%d", section, idx);
	else
		snprintf(buff, CMD_STR_LEN, "%s", section);

	return Uci_Get_Str(title, buff, option, value);
}

UCI_FUN_BOOL Uci_Get_Int_By_Idx(int title, const char *section, int idx, const char *option,int *value)
{
	char value_str[RESULT_STR_LEN] ={0};
	
	if(UCI_FUN_FALSE == Uci_Get_Str_By_Idx(title,section,idx,option,value_str))
	{
		printf("Uci_Get_Int: Uci_Get_Str Failed!\n");
		return UCI_FUN_FALSE;
	}

	*value = atoi(value_str);

	return UCI_FUN_TRUE;
}

UCI_FUN_BOOL Uci_Set_Str_By_Idx(int title, const char *section, int idx, const char *option, char *value)
{
	char buff[CMD_STR_LEN] = { 0 };
	
	assert(value);

	if ( idx > 1 )
		snprintf(buff, CMD_STR_LEN, "%s%d", section, idx);
	else
	{
		snprintf(buff, CMD_STR_LEN, "%s", section);
	}
	
	return Uci_Set_Str(title, buff, option, value);
}

UCI_FUN_BOOL Uci_Get2Json(cJSON* root, int title, const char *section, const char *option, char *objname )
{
	//need set the uci max value, LONG_BUFF_LEN*2
	char value[LONG_BUFF_LEN] = { 0 };

	Uci_Get_Str(title, section, option, value);
	if ( strlen(value) > 0 )
	{
		cJSON_AddStringToObject(root, objname, value);
	}
	else
	{
		cJSON_AddStringToObject(root, objname, "");
	}

	return 0;
}

UCI_FUN_BOOL Uci_Get2Json_By_Idx(cJSON* root, int title, const char *section, int idx, const char *option, char *objname )
{
	//need set the uci max value, LONG_BUFF_LEN*2
	char value[LONG_BUFF_LEN] = { 0 };
	Uci_Get_Str_By_Idx(title, section, idx, option, value);
	if ( strlen(value) > 0 )
	{
		cJSON_AddStringToObject(root, objname, value);
	}
	else
	{
		cJSON_AddStringToObject(root, objname, "");
	}

	return 0;
}

UCI_FUN_BOOL get_num_uci2json(cJSON* root,int title, char *section, char *option, char *key)
{
	char value[128] = { 0 };
	
	Uci_Get_Str(title,section,option,value);
	if ( strlen(value) > 0 )
	{
		cJSON_AddStringToObject(root, key, value);
	}
	else
	{
		cJSON_AddStringToObject(root, key, "0");
	}
	return 0;
}

UCI_FUN_BOOL get_uci2json(cJSON* root,int title, char *section, char *option, char *key)
{
	char value[128] = { 0 };
	
	Uci_Get_Str(title,section,option,value);
	if ( strlen(value) > 0 )
	{
		cJSON_AddStringToObject(root, key, value);
	}
	else
	{
		cJSON_AddStringToObject(root, key, "");
	}
	return 0;
}
