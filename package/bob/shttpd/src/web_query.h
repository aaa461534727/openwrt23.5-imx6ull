
#ifndef WEB_QUERY_HEADER_INCLUDED
#define	WEB_QUERY_HEADER_INCLUDED
extern char *get_cgi(struct hsearch_data *htab, char *name);
extern void set_cgi(struct hsearch_data *htab, char *name, char *value);
extern void init_cgi(struct hsearch_data *htab, char *query);
extern void dump_htab(struct hsearch_data *htab);

#define safeget_cgi(htab, key, default) (get_cgi(htab, key) ? : (default))

#endif /* WEB_QUERY_HEADER_INCLUDED */
