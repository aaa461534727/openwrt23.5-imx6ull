#ifndef CS_BASE64_H

//#include <stdio.h>
//#include <string.h>


#define CS_BASE64_H

#define BASE64_DECODE 1
#define BASE64_ENCODE 1

#include <stdio.h>
#include <string.h>

//#if (BASE64_ENCODE == 1)
  char *base64_encode(const unsigned char * bindata, char * base64, int binlength);
//#endif

//#if (BASE64_DECODE == 1)
	int base64_decode(const char * base64, unsigned char * bindata);
//#endif

#endif
