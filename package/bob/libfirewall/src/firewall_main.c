
#include "libfirewall.h"

int main(int argc, char *argv[])
{
	stop_firewall();
	return start_firewall();
}
