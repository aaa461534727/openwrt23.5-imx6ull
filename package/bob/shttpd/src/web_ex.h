
#ifndef WEB_EX_HEADER_INCLUDED
#define	WEB_EX_HEADER_INCLUDED

#define PROTOCOL_VERSION		"HTTP/1.0"
#define CACHE_AGE_VAL			5*60					//缓存5分钟
#define RFC1123FMT		"%a, %d %b %Y %H:%M:%S GMT"

extern char syslog_txt[];
extern char no_cache_IE[];

extern void saveSystemSetting_do_file(FILE *conn_fp);
extern int  make_headers(int status, const char *title, const char *extra_header, const char *mime_type, const struct stat *st, char *header_buf);
extern void send_redirect_async(const char *path, struct conn *c);
extern void send_error_async(int status, const char *title, const char *extra_header, const char *text, struct conn *c);

extern void send_headers_sync(int status, const char *title, const char *extra_header, const char *mime_type, const struct stat *st, FILE *conn_fp);
extern void send_redirect_sync(const char *path, FILE *conn_fp);
extern void send_error_sync(int status, const char *title, const char *extra_header, const char *text, FILE *conn_fp);
extern void send_check_auth_respond(int err_code, char *err_msg, FILE *conn_fp);

extern int check_auth_login(struct conn *c, char *err_msg, int len);

/* Generic MIME type handler */
struct mime_handler {
	char *pattern;
	char *mime_type;
	char *extra_header;
	void (*do_response)(struct conn *c, struct mime_handler *handler);
	int need_auth;
};
extern struct mime_handler mime_handlers[];

extern void do_cste(struct conn *c, struct mime_handler *handler);
extern void do_upload(struct conn *c, struct mime_handler *handler);

#if !defined(NO_CGI)
extern void do_cgi_bin(struct conn *c, struct mime_handler *handler);
#endif /* !NO_CGI */
extern void register_show_post(struct conn *c, struct mime_handler *handler);
extern void do_syslog_file(struct conn *c, struct mime_handler *handler);
extern void do_file(struct conn *c, struct mime_handler *handler);
extern void do_register(struct conn *c, struct mime_handler *handler);

//io_post.c
struct post_arg {
	struct conn *conn;

	char *body_buf;
	void *state;		/* User state*/
	int body_buf_len;

	struct mime_handler *handler;

	int pair[2];
	int pid;

	void (*v_func)(struct post_arg *arg, FILE *conn_fp);			//子进程执行的回调函数

	void *priv_data;		//解析post_buf后获得的私有数据
};

extern void shttpd_do_post(struct conn *c, struct mime_handler *handler, void *func);

//session_auth.c
#if defined(SESSION_AUTH)
extern char *get_session_id(const char *query, char *sid, int len);
extern int  check_session_id(const char *cookie);
extern int  generate_session_id();
extern int  http_login_check(const char *client_ip);
extern void update_login_data(const char *client_ip);
extern void reset_login_data(void);
extern int  get_query_param(char *query, char *param_key, char *param_val, int len);
#endif

#endif /* WEB_EX_HEADER_INCLUDED */
