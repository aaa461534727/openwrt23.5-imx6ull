
#include "defs.h"

/*******************************************************************************************
io_post: fork一个进程来处理post cgi请求（主要但不限于处理post请求），防止垃圾代码危害主进程。
在fork之前，必须先完成post_buf的聚合。
post_buf聚合代码逻辑参考io_emb，fork进程的代码逻辑参考io_cgi
*******************************************************************************************/
void
shttpd_do_post(struct conn *c, struct mime_handler *handler, void *func)
{
	DBG(("%s %d: uri=[%s]", __FUNCTION__, __LINE__, c->uri));

	if((c->rem.content_len < 0) || (c->rem.content_len > MAX_POST_LENGTH)) {
		_shttpd_send_server_error(c, 411, "Length invalid");
		return;
	}

	struct post_arg *arg = calloc(1, sizeof(struct post_arg) + c->rem.content_len + 1);
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
	c->loc.io_class = &_shttpd_io_post;
	c->loc.flags = FLAG_R | FLAG_W | FLAG_ALWAYS_READY;
}

static void
handle_post(struct post_arg *arg, FILE *conn_fp)
{
	if(arg->v_func == NULL){
		DBG(("%s %d: arg->v_func is NULL", __FUNCTION__, __LINE__));
	}else{
		DBG(("%s %d: strlen(body_buf)=%d body_buf=%s", __FUNCTION__, __LINE__, strlen(arg->body_buf), arg->body_buf));

		arg->v_func(arg, conn_fp);
	}
}

static void
shttpd_run_post(struct post_arg *arg)
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
			handle_post(arg, conn_fp);
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
write_post(struct stream *stream, const void *buf, size_t len)			//这里buf=io_data(&c->rem.io)
{
	DBG(("%s %d: stream_type=%s", __FUNCTION__, __LINE__, _shttpd_get_stream_type(stream)));

	struct conn *c = stream->conn;
	struct post_arg *arg = (struct post_arg *)c->extra;
	int copy_len;

	stream->flags |= FLAG_DONT_CLOSE;

	if(arg->pid == -1 && len > 0) {										//通过pid判断post_buf是否聚合完成
		if(len < c->rem.content_len) {
			copy_len = (arg->body_buf_len + len > c->rem.content_len) ? (c->rem.content_len - len) : len;
		} else {
			copy_len = (arg->body_buf_len + len > c->rem.content_len) ? (c->rem.content_len - arg->body_buf_len) : len;
		}

		memcpy(arg->body_buf + arg->body_buf_len, buf, copy_len);
		arg->body_buf_len += copy_len;

		DBG(("%s %d: copy_len=%d strlen(body_buf)=%d body_buf=%s", __FUNCTION__, __LINE__, copy_len, strlen(arg->body_buf), arg->body_buf));

		io_inc_tail(&c->rem.io, len);
	} else {
		io_inc_tail(&c->rem.io, len);			//eat garbage \r\n (IE6, ...) or browser ends up with a tcp reset error message
	}

	return 0;
}

static int
read_post(struct stream *stream, void *buf, size_t len)
{
	DBG(("%s %d: stream_type=%s", __FUNCTION__, __LINE__, _shttpd_get_stream_type(stream)));

	struct conn *c = stream->conn;
	struct post_arg *arg = (struct post_arg *)c->extra;
	int n;

	stream->flags |= FLAG_DONT_CLOSE;

	if(arg->pid == -1) {									//没有子进程，post_buf没有聚合完成
		if(arg->body_buf_len == c->rem.content_len)
			shttpd_run_post(arg);							//fork子进程处理post数据

		return 0;
	}

	assert(stream->chan.sock != -1);
	n = recv(stream->chan.sock, buf, len, 0);				//接收子进程发送过来的HTTP响应数据
	if(n == 0) {											//子进程已经退出或关闭socket
		DBG(("%s %d: socket closed", __FUNCTION__, __LINE__));
		stream->flags &= ~FLAG_DONT_CLOSE;
	} else if(n < 0 && ERRNO != EWOULDBLOCK) {
		_shttpd_send_server_error(stream->conn, 500, "Error running POST");
		return (n);
	}

	return n;
}

static void
close_post(struct stream *stream)
{
	assert(stream->chan.sock != -1);
	closesocket(stream->chan.sock);
}

const struct io_class	_shttpd_io_post =  {
	"post",
	read_post,
	write_post,
	close_post
};
