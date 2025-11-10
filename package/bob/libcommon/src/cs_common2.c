
#include "cs_common.h"

/*
 *  * description: parse va and do system
 *   */
int doSystem(const char *fmt, ...)
{
	char cmd_buf[512];
	va_list pargv;

	va_start(pargv, fmt);
	vsnprintf(cmd_buf, sizeof(cmd_buf), fmt, pargv);
	va_end(pargv);

	return system(cmd_buf);
}

void notice_set(const char *path, const char *format, ...)
{
	char p[256];
	char buf[2048];
	va_list args;

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	mkdir("/var/notice", 0755);
	snprintf(p, sizeof(p), "/var/notice/%s", path);
	f_write_string(p, buf, 0, 0);
	if (buf[0]) syslog(LOG_INFO, "notice[%s]: %s", path, buf);
}

int _eval(char *const argv[], char *path, int timeout, int *ppid)
{
	sigset_t set;
	pid_t pid, ret;
	int status;
	int fd;
	int flags;
	int sig, i;

	switch (pid = fork()) {
	case -1:	/* error */
		perror("fork");
		return errno;
	case 0:	 /* child */
		/* Reset signal handlers set for parent process */
		for (sig = 0; sig < (_NSIG-1); sig++)
			signal(sig, SIG_DFL);

		/* Unblock signals if called from signal handler */
		sigemptyset(&set);
		sigprocmask(SIG_SETMASK, &set, NULL);

		/* Clean up */
		for (i=3; i<256; i++)    // close un-needed fd
			close(i);
		ioctl(0, TIOCNOTTY, 0);	// detach from current process
		setsid();
		
		/* Redirect stdout to <path> */
		if (path) {
			flags = O_WRONLY | O_CREAT;
			if (!strncmp(path, ">>", 2)) {
				/* append to <path> */
				flags |= O_APPEND;
				path += 2;
			} else if (!strncmp(path, ">", 1)) {
				/* overwrite <path> */
				flags |= O_TRUNC;
				path += 1;
			}
			if ((fd = open(path, flags, 0644)) < 0)
				perror(path);
			else {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
		}
		
		/* execute command */
		setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
		alarm(timeout);
		execvp(argv[0], argv);
		perror(argv[0]);
		exit(errno);
	default:	/* parent */
		if (ppid) {
			*ppid = pid;
			return 0;
		} else {
			do
				ret = waitpid(pid, &status, 0);
			while ((ret == -1) && (errno == EINTR));
			
			if (ret != pid) {
				perror("waitpid");
				return errno;
			}
			if (WIFEXITED(status))
				return WEXITSTATUS(status);
			else
				return status;
		}
	}
}

#define MAX_XSTART_ARGC 16
int _xstart(const char *cmd, ...)
{
	va_list ap;
	char *argv[MAX_XSTART_ARGC];
	int argc;
	int pid;

	argv[0] = (char *)cmd;
	argc = 1;
	va_start(ap, cmd);
	while ((argv[argc++] = va_arg(ap, char *)) != NULL) {
		if (argc >= MAX_XSTART_ARGC) {
			printf("%s: too many parameters\n", __FUNCTION__);
			break;
		}
	}
	va_end(ap);

	return _eval(argv, NULL, 0, &pid);
}

//-------------------------------------------------------------------------

int
is_module_loaded(const char *module_name)
{
	DIR *dir_to_open = NULL;
	char mod_path[64];

	snprintf(mod_path, sizeof(mod_path), "/sys/module/%s", module_name);
	dir_to_open = opendir(mod_path);
	if (dir_to_open) {
		closedir(dir_to_open);
		return 1;
	}

	return 0;
}

int
get_module_refcount(const char *module_name)
{
	FILE *fp;
	char mod_path[64], mod_refval[16];
	int refcount = 0;

	snprintf(mod_path, sizeof(mod_path), "/sys/module/%s/refcnt", module_name);
	fp = fopen(mod_path, "r");
	if (!fp)
		return -1;

	mod_refval[0] = 0;
	fgets(mod_refval, sizeof(mod_refval), fp);
	if (strlen(mod_refval) > 0)
		refcount = atoi(mod_refval);

	fclose(fp);

	return refcount;
}

int
module_smart_load(const char *module_name, const char *module_param)
{
	int ret;

	if (is_module_loaded(module_name))
		return 0;

	if (module_param && *module_param)
		ret = doSystem("modprobe -q %s %s", module_name, module_param);
	else
		ret = doSystem("modprobe -q %s", module_name);

	return (ret == 0) ? 1 : 0;
}

int
module_smart_unload(const char *module_name, int recurse_unload)
{
	int ret;
	int refcount = get_module_refcount(module_name);

	/* check module not loaded */
	if (refcount < 0)
		return 0;

	/* check module is used */
	if (refcount > 0)
		return 1;

	if (recurse_unload)
		ret = doSystem("modprobe -r %s", module_name);
	else
		ret = doSystem("rmmod %s", module_name);

	return (ret == 0) ? 1 : 0;
}
