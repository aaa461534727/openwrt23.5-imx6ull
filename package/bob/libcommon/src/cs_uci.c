#include "cs_uci.h"

static pthread_mutex_t g_ctx_cache_lock;

static struct cs_uci_get_context* g_uci_contexts[PKG_NUM_OF_PKG];

static struct uci_context* create_uci_context(const char* path) 
{

  //printf("Create CS CTX, Path: %s\n", path);

  struct uci_context* ctx = uci_alloc_context();

  if (!ctx) {
	  printf("Failed to allocate UCI context, out of memory?\n");
	  return NULL;
  }

  //printf("Create UCI Context: %p\n", ctx);

  uci_add_delta_path(ctx, "/var/state");
  if (path)
    uci_set_confdir(ctx, path);
  else
    uci_set_confdir(ctx, DEFAULT_UCI_STATUS_PATH);

  return ctx;

}

/**
 * Init UCI context
 * path - don't set path if path is null
 * packages - shall be multiple (i.e SYSTEM|NETWORK)
 */
static int
init_uci_context(struct uci_context* ctx, unsigned char package)
{

  //printf("INIT CS CTX: %i\n", package);

  if(uci_load(ctx, PKG_ID_TOFILE(package), NULL) != UCI_OK)
  {
	//printf("%s/%s is missing or corrupt\n", ctx->confdir, PKG_ID_TOFILE(package));
	return 0;
  }
  return 1;

}

static void release_global_get_context(struct cs_uci_get_context* get_ctx) {
    if (get_ctx) 
	{
        pthread_mutex_lock(&(get_ctx->get_ctx_lock));

		if (get_ctx->get_uci_context) 
		{
            clean_uci_context((get_ctx->get_uci_context));
            get_ctx->get_uci_context = NULL;
        }
		
        pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
		
        pthread_mutex_destroy(&(get_ctx->get_ctx_lock));
    }
}


/**
 * Clean up the specified ctx context
 */
void clean_uci_context(struct uci_context* ctx) 
{
  //printf("Clean CS UCI Context: %p\n", ctx);
  if (ctx)
  {
      uci_free_context(ctx);
  }
}

/*
 * Get global get context cache
 */
static struct cs_uci_get_context* get_global_get_context(unsigned char package) {

    struct cs_uci_get_context* get_ctx;

    get_ctx = g_uci_contexts[package];
    if (get_ctx == NULL) {
        pthread_mutex_lock(&g_ctx_cache_lock);
        get_ctx = g_uci_contexts[package];
        if (get_ctx == NULL) {
            get_ctx = (struct cs_uci_get_context *) malloc(sizeof(struct cs_uci_get_context));
            if (get_ctx == NULL) {
                printf("Failed to create UCI get context\n");
                pthread_mutex_unlock(&g_ctx_cache_lock);
                return NULL;
            }
            // Init get context
            memset(get_ctx, 0 , sizeof(struct cs_uci_get_context));
            get_ctx->package = package;
            pthread_mutex_init(&(get_ctx->get_ctx_lock),NULL);

            // Store the context
            g_uci_contexts[package] = get_ctx;
        }
        pthread_mutex_unlock(&g_ctx_cache_lock);
    }

    return get_ctx;

}


/**
 * Get the uci option using the uci string
 * If the uci option is a list, a concatenated string will be returned with the space as the delimiter
 * For option list, the list size larger than MAX_UCI_VALUE_LEN will be truncated
 * It is caller's responsibility to ensure the result has enough space to carry result
 * @ctx  		UCI context
 * @uci_str  	UCI option string
 * @result		UCI result value string
 * @return 0, if failed
 */
int cs_uci_get_option(struct cs_uci_get_context *get_ctx,  char *uci_str, char *result)
{
	struct uci_ptr ptr;
	char get_uci_str[MAX_UCI_STRLEN + 1];
	struct uci_element *e = NULL;
	bool sep = false;
    char* t_result = result;

	if (!get_ctx || !uci_str || !result) {
		return 0;
	}

    pthread_mutex_lock(&(get_ctx->get_ctx_lock));

    /* The internal UCI context may become empty, if the cache is being dropped after the get context is initialized */
	if (get_ctx->get_uci_context == NULL) {
	    printf("CS UCI Get Context is invalid, reinit now\n");
	    if (!refresh_uci_get_context(get_ctx, (long) time(NULL))) {
	        printf("Unable to reinit the context\n");
	        pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
	        return 0;
	    }
	}

	memset(&ptr, 0, sizeof(struct uci_ptr));
	memset(get_uci_str, 0, sizeof(get_uci_str));

	/* Construct the Get UCI string, since uci_str pass to uci api must not be a const string */
	strcpy(get_uci_str, uci_str);

	uci_lookup_ptr(get_ctx->get_uci_context, &ptr, get_uci_str, true);
	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		//printf("Lookup is incomplete, %s CTX:%p\n", uci_str, get_ctx->get_uci_context);
		pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
		return 0;
	}

	e = ptr.last;
	switch (e->type) {
	case UCI_TYPE_OPTION:
		if (ptr.o->type == UCI_TYPE_STRING) {
			strcpy(result, ptr.o->v.string);
		} else if (ptr.o->type == UCI_TYPE_LIST) {
			*t_result = '\0';
			uci_foreach_element(&(ptr.o->v.list), e) {
				/* Ignore the string if the result is already full */
				if ((strlen(result) + strlen(e->name) + 2) <= (MAX_UCI_VALUE_LEN-1)) {
					t_result += sprintf(t_result, "%s%s", sep?" ":"", e->name);
					sep = true;
				}
			}
		} else {
		    pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
			return 0;
		}
		break;
	default:
	    pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
		return 0;
	}
	pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
	return 1;
}



/**
 * Refresh UCI get context,
 * MUST get get_ctx->get_ctx_lock before call this method
 *
 * Refresh or create new underlying uci context
 */
int refresh_uci_get_context(struct cs_uci_get_context* get_ctx, long now) 
{

    int ret;

    //printf("Refresh Get Context, Package: %i\n", get_ctx->package);

    if (get_ctx->get_uci_context != NULL) {
        clean_uci_context(get_ctx->get_uci_context);
    }

    get_ctx->get_uci_context = create_uci_context(PKG_FILE_PATH(get_ctx->package));
    if (get_ctx->get_uci_context == NULL) {
        return 0;
    }

    ret = init_uci_context(get_ctx->get_uci_context, get_ctx->package);
    if (!ret) {
        clean_uci_context(get_ctx->get_uci_context);
        get_ctx->get_uci_context = NULL;
        return 0;
    }

    if (IS_PKG_CAN_CACHE(get_ctx->package)) {
        get_ctx->ctx_lastupdate = now;
    }

    return 1;
}


static struct cs_uci_get_context* i_cs_uci_get_uci_context(unsigned char package, const char* path, bool disable_la) 
{

	struct cs_uci_get_context* get_ctx;
	long now = (long) time(NULL);

	/* Init the get context if it is not initialized yet */
	get_ctx = get_global_get_context(package);

	if (get_ctx == NULL) 
	{
	  return NULL;
	}

	//printf("Get CS CTX, Package: %i %s Time: %ld Last Updated: %ld Last Accessed: %ld\n", package, path, now, get_ctx->ctx_lastupdate, get_ctx->ctx_lastaccess);

	pthread_mutex_lock(&(get_ctx->get_ctx_lock));

	/* Refresh the UCI context if: */
	/* - The context is empty */
	/* - The existing context is timeout and last access is exceeded the timeout. */

#if 0 //add by sky 20200513 for update time lead to ctx_lastupdate time is bigger than now
	if ((get_ctx->get_uci_context == NULL) || (((get_ctx->ctx_lastupdate + DEFAULT_CTX_TIMEOUT) <= now )
				  && (disable_la || ((get_ctx->ctx_lastaccess + DEFAULT_CTX_LASTACCESS_TIMEOUT) <= now)))) {
	  /* Refresh the underlying UCI context */
	  if (!refresh_uci_get_context(get_ctx, now)) {
	      pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
	      return NULL;
	  }
	}
#else
   /*
 		long ctx_lastupdate = get_ctx->ctx_lastupdate>now?get_ctx->ctx_lastupdate-now:now-get_ctx->ctx_lastupdate;
 		long ctx_lastaccess = get_ctx->ctx_lastaccess>now?get_ctx->ctx_lastaccess-now:now-get_ctx->ctx_lastaccess;
 		if ((get_ctx->get_uci_context == NULL) || ((ctx_lastupdate > DEFAULT_CTX_TIMEOUT )
					  && (disable_la || (ctx_lastaccess > DEFAULT_CTX_LASTACCESS_TIMEOUT)))) {
 		  // Refresh the underlying UCI context 
 		  if (!refresh_uci_get_context(get_ctx, now)) {
 			  pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
 			  return NULL;
 		  }
 		}
   */
 	  if (!refresh_uci_get_context(get_ctx, now)) {
 		  pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
		  return NULL;
 	  } 	  
#endif 

	/* Update the last access time */
	if (IS_PKG_CAN_CACHE(package)) {
	  get_ctx->ctx_lastaccess = now;
	}

	pthread_mutex_unlock(&(get_ctx->get_ctx_lock));

	//printf("Got CS CTX, Package: %i CTX dir:%s\n", package, get_ctx->get_uci_context->confdir);

	return get_ctx;

}

static int i_cs_uci_force_refresh_context(unsigned char package) 
{
	struct cs_uci_get_context* get_ctx;

	long now = (long) time(NULL);

	/* Init the get context if it is not initialized yet */

	get_ctx = get_global_get_context(package);
	if (get_ctx == NULL) {
		return 0;
	}

  	pthread_mutex_lock(&(get_ctx->get_ctx_lock));
	/* force refresh the UCI context when needed*/
	if (!refresh_uci_get_context(get_ctx, now)) 
	{
 		pthread_mutex_unlock(&(get_ctx->get_ctx_lock));
     	return 0;
  	}

  	/* Update the last access time */
  	if (IS_PKG_CAN_CACHE(package)) {
	  	get_ctx->ctx_lastaccess = now;
  	}

  	pthread_mutex_unlock(&(get_ctx->get_ctx_lock));

  	return 1;

}

struct cs_uci_get_context* cs_uci_get_uci_context_nla(unsigned char package, const char* path) 
{
	return i_cs_uci_get_uci_context(package, path, true);
}

int cs_uci_force_refresh_context(unsigned char package) {
	return i_cs_uci_force_refresh_context(package);
}

void cs_uci_init(void)
{
  memset(g_uci_contexts, 0, sizeof(g_uci_contexts));
}

void cs_uci_release(void) 
{
  	int i;
  	pthread_mutex_lock(&g_ctx_cache_lock);
  
  	for (i=0;i<PKG_NUM_OF_PKG;i++) 
  	{
		if (g_uci_contexts[i]) 
		{
	    	release_global_get_context(g_uci_contexts[i]);
			free(g_uci_contexts[i]);
			g_uci_contexts[i] = NULL;
		}
  	}

  	pthread_mutex_unlock(&g_ctx_cache_lock);

	pthread_mutex_destroy(&g_ctx_cache_lock);


}


