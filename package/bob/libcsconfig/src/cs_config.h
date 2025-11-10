
#include "libconfig.h"

int config_init_file(config_t *config, const char *file_path);
int config_get_int(config_t *config, const char *path);
int config_lazy_get_int(const char *key, const char *file_path);
int config_set_int(config_t *config, const char *key, int value);
int config_lazy_set_int(const char *key, int value, const char *file_path);
char *config_lazy_get_string(const char *key, const char *file_path);
int config_set_string(config_t *config, const char *key, const char *value);
int config_lazy_set_string(const char *key, const char *value, const char *file_path);


