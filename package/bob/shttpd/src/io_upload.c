#include "defs.h"


int get_last_data_length(const char *buf, int total)
{
	int len=0, i=0;
	char *ptr=NULL;

	for(i=0; i < total; i++){
		if(buf[i] == 0x0d && buf[i+1] == 0x0a && buf[i+2] == 0x2d && buf[i+2] == 0x2d ){
			len=i;
			break;
		}
	}
	
	return len;
}
int get_file_httphead_offset(const char *buf)
{
	int offset=0;
	char *ptr=NULL;
	while(1){
		if((ptr=strstr(buf+offset, "\r\n")) !=NULL){
			offset =(ptr-buf) + strlen("\r\n");
		}
		else{
			break;
		}
	}
	
	if(ptr)
		close(ptr);
	
	return offset;
}

void shttpd_do_upload(struct conn *c, struct mime_handler *handler, void *func)
{
	if((c->rem.content_len < 0) || (c->rem.content_len > MAX_POST_LENGTH)) {
		_shttpd_send_server_error(c, 411, "Length invalid");
		return;
	}

	struct post_arg *arg = calloc(1, sizeof(struct post_arg) + 1024 + 1);
	if(arg == NULL) {
		_shttpd_send_server_error(c, 500, "Cannot allocate post_arg");
		return;
	}
	arg->conn = c;

	arg->body_buf = (char *)(arg + 1);
	arg->handler = handler;

	arg->pair[0] = -1;
	arg->pair[1] = -1;
	arg->pid = -1;

	arg->v_func = func;

	c->extra = arg;
	c->loc.io.head = c->loc.io.tail = c->loc.io.total = 0;
	c->loc.io_class = &_shttpd_io_upload;
	c->loc.flags = FLAG_R | FLAG_W | FLAG_ALWAYS_READY;

}

static void
handle_upload(struct post_arg *arg, FILE *conn_fp)
{
	if(arg->v_func == NULL){
		dbg("arg->v_func is NULL");
	}else{
		arg->v_func(arg, conn_fp);
	}
}

static void
shttpd_run_upload(struct post_arg *arg)
{
	struct conn *c = arg->conn;

	if (shttpd_socketpair(arg->pair) != 0) {
		_shttpd_send_server_error(c, 500, "Socketpair fail");
		return;
	}

	arg->pid = fork();
	if(arg->pid < 0) {
		closesocket(arg->pair[0]);
		closesocket(arg->pair[1]);
		_shttpd_send_server_error(c, 500, "Fork fail");
		return;
	} else if(arg->pid == 0) {
		/* Child */
		closesocket(arg->pair[0]);

		FILE *conn_fp;

		conn_fp = fdopen(arg->pair[1], "r+");				//把fd转换为fp
		if(conn_fp) {
			handle_upload(arg, conn_fp);
			fflush(conn_fp);
			fclose(conn_fp);
		}
		closesocket(arg->pair[1]);
		exit(0);
	} else {
		/* Parent */
		closesocket(arg->pair[1]);

		c->loc.chan.sock = arg->pair[0];
	}
}

static int
write_upload(struct stream *stream, const void *buf, size_t len)			//这里buf=io_data(&c->rem.io)
{
	struct conn *c = stream->conn;
	struct post_arg *arg = (struct post_arg *)c->extra;
	int copy_len;
	//int offset=0;

	struct state {
		size_t	cl; 	    /* Content-Length	*/
		size_t	nread;		/* Number of bytes read */
		FILE	*fp;
	} *state;

	stream->flags |= FLAG_DONT_CLOSE;

	if(arg->pid == -1 && len > 0) {										//通过pid判断post_buf是否聚合完成
		if(len < c->rem.content_len) {
			copy_len = (arg->body_buf_len + len > c->rem.content_len) ? (c->rem.content_len - len) : len;
		} else {
			copy_len = (arg->body_buf_len + len > c->rem.content_len) ? (c->rem.content_len - arg->body_buf_len) : len;
		}

#if 0
	//在这里就去掉http头部和尾部，只写入固件实际的数据
		if (arg->state == NULL) {
		/* New request. Allocate a state structure, and open a file */
			arg->state = state = calloc(1, sizeof(*state));
			state->fp = fopen(TMP_UPLOAD_FILE, "wb+");

			printf("buf=%s\n", buf);

			//去掉头部
			offset=get_file_httphead_offset(buf);
			printf("buf+offset=%s\n", buf+offset);
			(void) fwrite(buf+offset, copy_len-offset, 1, state->fp);
		} else {
			state = arg->state;
		/*
	 	* Write the POST data to a file. We do not do any URL
	 	* decoding here. File will contain form-urlencoded stuff.
	 	*/

			if ((state->nread +copy_len)  >= c->rem.content_len) {
				int data_len=0;
				//去掉尾部
				data_len = get_last_data_length(buf, copy_len);
			
				if(data_len == 0)
					data_len = copy_len;
			
				(void) fwrite(buf, data_len, 1, state->fp);
			
			}
			else	
				(void) fwrite(buf, copy_len, 1, state->fp);
		}
	
#else
		if (arg->state == NULL) {
			/* New request. Allocate a state structure, and open a file */
			arg->state = state = calloc(1, sizeof(*state));
			state->fp = fopen(TMP_UPLOAD_FILE, "wb+");

			//offset=get_file_httphead_offset(buf);
		} else {
			state = arg->state;
		}
		/*
		 * Write the POST data to a file. We do not do any URL
		 * decoding here. File will contain form-urlencoded stuff.
		 */
		(void) fwrite(buf, copy_len, 1, state->fp);
#endif
		state->nread += copy_len;

		/* Data stream finished? Close the file, and free the state */
		if (state->nread >= c->rem.content_len) {
			(void) fclose(state->fp);
			free(state);
		}
		//memcpy(arg->body_buf + arg->body_buf_len, buf, copy_len);
		arg->body_buf_len += copy_len;
	}

	io_inc_tail(&c->rem.io, len);

	return 0;
}

static int
read_upload(struct stream *stream, void *buf, size_t len)
{
	struct conn *c = stream->conn;
	struct post_arg *arg = (struct post_arg *)c->extra;
	int n;

	stream->flags |= FLAG_DONT_CLOSE;

	if(arg->pid == -1) {									//没有子进程，post_buf没有聚合完成
		if(arg->body_buf_len == c->rem.content_len)
			shttpd_run_upload(arg);							//fork子进程处理post数据

		return 0;
	}

	assert(stream->chan.sock != -1);
	n = recv(stream->chan.sock, buf, len, 0);				//接收子进程发送过来的HTTP响应数据
	if(n == 0) {											//子进程已经退出或关闭socket
		stream->flags &= ~FLAG_DONT_CLOSE;
	} else if(n < 0 && ERRNO != EWOULDBLOCK) {
		_shttpd_send_server_error(stream->conn, 500, "Error running POST");
		return (n);
	}

	return n;
}

static void
close_upload(struct stream *stream)
{
	assert(stream->chan.sock != -1);
	closesocket(stream->chan.sock);
}

const struct io_class	_shttpd_io_upload =  {
	"upload",
	read_upload,
	write_upload,
	close_upload
};
