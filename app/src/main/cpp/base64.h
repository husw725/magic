/*base64.h*/
#ifndef _BASE64_H
#define _BASE64_H

#include <stdlib.h>
#include <string.h>
#ifdef  __cplusplus
extern "C" {
#endif

unsigned char *base64_encode(unsigned char *str);

unsigned char *bae64_decode(unsigned char *code);

#ifdef  __cplusplus
 }
#endif

#endif
