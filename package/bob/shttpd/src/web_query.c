
#include "defs.h"

static void
unescape(char *s)
{
	unsigned int c;

	while ((s = strpbrk(s, "%+"))) {
		/* Parse %xx */
		if (*s == '%') {
			sscanf(s + 1, "%02x", &c);
			*s++ = (char) c;
			strncpy(s, s + 2, strlen(s) + 1);
		}
		/* Space is special */
		else if (*s == '+')
			*s++ = ' ';
	}
}

char *
get_cgi(struct hsearch_data *htab, char *name)
{
	ENTRY e, *ep;
#ifdef _GNU_SOURCE
	if ((!htab)||(!htab->__tab))
#else
	if ((!htab)||(!htab->table))
#endif
		return NULL;

	e.key = name;
	hsearch_r(e, FIND, &ep, htab);

	return ep ? ep->data : NULL;
}

void
set_cgi(struct hsearch_data *htab, char *name, char *value)
{
	ENTRY e, *ep;

#ifdef _GNU_SOURCE
	if ((!htab)||(!htab->__tab))
#else
	if ((!htab)||(!htab->table))
#endif
		return;

	e.key = name;
	hsearch_r(e, FIND, &ep, htab);
	if (ep)
		ep->data = value;
	else {
		e.data = value;
		hsearch_r(e, ENTER, &ep, htab);
	}
}

void
init_cgi(struct hsearch_data *htab, char *query)
{
	int len, nel;
	char *q, *name, *value;

	/* Clear variables */
	if (!query) {
		hdestroy_r(htab);
		return;
	}

	/* Parse into individual assignments */
	q = query;
	len = strlen(query);
	nel = 1;
	while (strsep(&q, "&;"))
		nel++;
	hcreate_r(nel, htab);

	for (q = query; q < (query + len);) {
		/* Unescape each assignment */
		unescape(name = value = q);

		/* Skip to next assignment */
		for (q += strlen(q); q < (query + len) && !*q; q++);

		/* Assign variable */
		name = strsep(&value, "=");
		if (value)
			set_cgi(htab, name, value);
	}
}

struct cgi_entry {
	unsigned int used;
	char *key;
	void *data;
};

static void print_cgi_entry(struct cgi_entry *e)
{
	DBG(("used=%d key=%s data=%s", e->used, e->key, (char *)e->data));
}

void 
dump_htab(struct hsearch_data *htab)
{
#if 0
	int i, j = 0;
	struct cgi_entry *e = (struct cgi_entry *)(htab->table);

	for(i = 0; i < htab->size + 1; i++) {
		if(e->used) {
			print_cgi_entry(e);
			j++;
		}
		e++;
	}
	DBG(("i=%d j=%d htab->size=%d htab->filled=%d", i, j, htab->size, htab->filled));
#endif
}
