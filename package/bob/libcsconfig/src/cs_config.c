#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "cs_config.h"

int config_init_file(config_t *config, const char *file_path)
{
    config_init(config);

    return config_read_file(config, file_path);
}

int config_get_int(config_t *config, const char *path)
{
    config_setting_t *setting;

    setting = config_lookup(config, path);

    if(setting == NULL)
        return -1;

    return config_setting_get_int(setting);
}

int config_lazy_get_int(const char *key, const char *file_path)
{
    int ret;
    config_t cfg;

    if(!config_init_file(&cfg, file_path)) {
        ret = -1;
        goto out;
    }

    ret = config_get_int(&cfg, key);

out:
    config_destroy(&cfg);
    return ret;
}

int config_set_int(config_t *config, const char *key, int value)
{
    int type;
    config_setting_t *root, *setting;

    root = config_root_setting(config);
    setting = config_lookup(config, key);

    if(setting == NULL) {
        setting = config_setting_add(root, key, CONFIG_TYPE_INT);
    }

    if(setting == NULL)
        return -1;

    type = config_setting_type(setting);
    if(type != CONFIG_TYPE_INT)
        return -2;

    return config_setting_set_int(setting, value) == 1 ? 0 : -1;
}

int config_lazy_set_int(const char *key, int value, const char *file_path)
{
    int ret;
    config_t cfg;

    if(!config_init_file(&cfg, file_path)) {
        ret = -1;
        goto out;
    }

    ret = config_set_int(&cfg, key, value);
    config_write_file(&cfg, file_path);

out:
    config_destroy(&cfg);
    return ret;
}

static const char *__config_get_string(config_t *config, const char *path)
{
    config_setting_t *setting;

    setting = config_lookup(config, path);

    if(setting == NULL)
        return NULL;

    return config_setting_get_string(setting);
}

const char *config_get_string(config_t *config, const char *path)
{
    const char *value = __config_get_string(config, path);

    if(value)
        return value;
    else
        return NULL;
}

char *config_lazy_get_string(const char *key, const char *file_path)
{
    const char *ptr;
    char *ret_p;
    config_t cfg;

    ret_p = NULL;
    if(!config_init_file(&cfg, file_path)) {
        goto out;
    }

    ptr = config_get_string(&cfg, key);
    if(ptr)
        ret_p = strdup(ptr);

out:
    config_destroy(&cfg);
    if(ret_p)
    	return ret_p;
    else
	return "";
}

int config_set_string(config_t *config, const char *key, const char *value)
{
    int type;
    config_setting_t *root, *setting;

    root = config_root_setting(config);
    setting = config_lookup(config, key);

    if(setting == NULL) {
        setting = config_setting_add(root, key, CONFIG_TYPE_STRING);
    }

    if(setting == NULL)
        return -1;

    type = config_setting_type(setting);
    if(type != CONFIG_TYPE_STRING)
        return -2;

    return config_setting_set_string(setting, value)  == 1 ? 0 : -1;
}

int config_lazy_set_string(const char *key, const char *value, const char *file_path)
{
    int ret;
    config_t cfg;

    if(!config_init_file(&cfg, file_path)) {
        ret = -1;
        goto out;
    }

    ret = config_set_string(&cfg, key, value);
    config_write_file(&cfg, file_path);

out:
    config_destroy(&cfg);
    return ret;
}

#if 0
//config status file
int cfg_get_status(const char *key, char *value, int len)
{
    if(!key || ! value || !len)
        return -1;

    (void)memset(value, 0, len);
    char *ptr = config_lazy_get_string(key , STATUS_TEMP_FILE);
    if(ptr)
    {
        memcpy(value, (char *)ptr, len-1);
        free(ptr);
        return 0;
    }
    else {
        value[0] = '\0';
    }
    return -1;
}

int cfg_get_status_int(const char *key)
{
    if(!key)
        return -1;

    return config_lazy_get_int(key, STATUS_TEMP_FILE);
}

int cfg_set_status(const char *key, char *value)
{
    if(!key || ! value)
        return -1;

    return config_lazy_set_string(key, value, STATUS_TEMP_FILE);
}

int cfg_set_status_int(const char *key, int value)
{
    if(!key)
        return -1;
return config_lazy_set_int(key, value, STATUS_TEMP_FILE); } //config temp file
int cfg_get_temp(const char *key, char *value, int len)
{
    if(!key || ! value || !len)
        return -1;

    (void)memset(value, 0, len);
    char *ptr = config_lazy_get_string(key , CONFIG_TEMP_FILE);
    if(ptr)
    {
        memcpy(value, (char *)ptr, len-1);
        free(ptr);
        return 0;
    }
    else {
        value[0] = '\0';
    }
    return -1;
}

int cfg_get_temp_int(const char *key)
{
    if(!key)
        return -1;

    return config_lazy_get_int(key, CONFIG_TEMP_FILE);
}

int cfg_set_temp(const char *key, char *value)
{
    if(!key || ! value)
        return -1;

    return config_lazy_set_string(key, value, CONFIG_TEMP_FILE);
}

int cfg_set_temp_int(const char *key, int value)
{
    if(!key)
        return -1;

    return config_lazy_set_int(key, value, CONFIG_TEMP_FILE);
}

//config flash file
int cfg_get_flash(const char *key, char *value, int len)
{
    if(!key || ! value || !len)
        return -1;

    memset(value, 0, len);
    char *ptr = config_lazy_get_string(key , CONFIG_FLASH_FILE);
    if(ptr)
    {
        strncpy(value, ptr, len-1);
        free(ptr);
        return 0;
    }
    else {
        value[0] = '\0';
    }
    return -1;
}

int cfg_get_flash_int(const char *key)
{
    if(!key)
        return -1;

    return config_lazy_get_int(key, CONFIG_FLASH_FILE);
}

int cfg_set_flash(const char *key, char *value)
{
    if(!key || ! value)
        return -1;

    return config_lazy_set_string(key, value, CONFIG_FLASH_FILE);
}

int cfg_set_flash_int(const char *key, int value)
{
    if(!key)
        return -1;

    return config_lazy_set_int(key, value, CONFIG_FLASH_FILE);
}

//config data file
int cfg_get_data(const char *key, char *value, int len)
{
    if(!key || ! value || !len)
        return -1;

    memset(value, 0, len);
    char *ptr = config_lazy_get_string(key , CONFIG_DATA_FILE);
    if(ptr)
    {
        memcpy(value, (char *)ptr, len-1);
        free(ptr);
        return 0;
    }
    else {
        value[0] = '\0';
    }
    return -1;
}

int cfg_get_data_int(const char *key)
{
    if(!key)
        return -1;

    return config_lazy_get_int(key, CONFIG_DATA_FILE);
}

int cfg_set_data(const char *key, char *value)
{
    if(!key || ! value)
        return -1;

    return config_lazy_set_string(key, value, CONFIG_DATA_FILE);
}

int cfg_set_data_int(const char *key, int value)
{
    if(!key)
        return -1;

    return config_lazy_set_int(key, value, CONFIG_DATA_FILE);
}

int cfg_get(const char *key, char *value, int len)
{
    int ret;
    ret = cfg_get_temp(key, value, len);
    if(ret == -1)
        ret = cfg_get_data(key, value, len);
    if(ret == -1)
        ret = cfg_get_flash(key, value, len);
    return ret;
}
int cfg_get_int(const char *key)
{
    int ret;
    ret = cfg_get_status_int(key);
    if(ret == -1)
        ret = cfg_get_temp_int(key);
    if(ret == -1)
        ret = cfg_get_data_int(key);
    if(ret == -1)
        ret = cfg_get_flash_int(key);
    return ret;
}
#endif
