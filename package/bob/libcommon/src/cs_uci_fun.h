#ifndef __CS_UCI_FUN_H__
#define __CS_UCI_FUN_H__


#include <string.h>
#include <stdlib.h>
#include "cs_uci.h"
#include <cJSON.h>
#include "cs_common.h"


typedef enum
{
	UCI_FUN_FALSE = 0,
	UCI_FUN_TRUE=1,
}UCI_FUN_BOOL;


UCI_FUN_BOOL Uci_Get_Str(int title, const char *section, const char *option, char *value);
UCI_FUN_BOOL Uci_Get_Int(int title, const char *section, const char *option, int *value);
UCI_FUN_BOOL Uci_Get_Long(int title, const char *section, const char *option, long *value);
UCI_FUN_BOOL Uci_Get_Long_Long(int title, const char *section, const char *option, long long *value);
UCI_FUN_BOOL Uci_Set_Str(int title, const char *section, const char *option, char *value);
UCI_FUN_BOOL Uci_Add_List(int title, const char *section, const char *option, char *value);
UCI_FUN_BOOL Uci_Del_List(int title, const char *section, const char *option, char *value);
UCI_FUN_BOOL Uci_Del_List_All(int title, const char *section, const char *option);
UCI_FUN_BOOL Uci_Add_Section(int title, const char *section_type);
UCI_FUN_BOOL Uci_Del_Section(int title, const char *section_name);
UCI_FUN_BOOL Uci_Commit(int title);
UCI_FUN_BOOL Uci_Get_Str_By_Idx(int title, const char *section, int idx, const char *option, char *value);
UCI_FUN_BOOL Uci_Get_Int_By_Idx(int title, const char *section, int idx, const char *option,int *value);
UCI_FUN_BOOL Uci_Set_Str_By_Idx(int title, const char *section, int idx, const char *option, char *value);
UCI_FUN_BOOL Uci_Get2Json(cJSON* root, int title, const char *section, const char *option, char *objname);
UCI_FUN_BOOL Uci_Get2Json_By_Idx(cJSON* root, int title, const char *section, int idx, const char *option, char *objname);
UCI_FUN_BOOL Uci_Get_Str_By_Section_Index(int title,char *section_type,int index, char *option,char *value);
UCI_FUN_BOOL Uci_Get_Int_By_Section_Index(int title,char *section_type,int index, char *option,int *value);
UCI_FUN_BOOL get_num_uci2json(cJSON* root,int title, char *section, char *option, char *key);
UCI_FUN_BOOL get_uci2json(cJSON* root,int title, char *section, char *option, char *key);


#endif


