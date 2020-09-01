#ifndef __HMAC_SHA1_H__
#define __HMAC_SHA1_H__
#ifdef  __cplusplus
extern "C" {
#endif

void aliyun_iot_common_hmac_sha1(const char *msg, int msg_len, char *digest, const char *key, int key_len);
void kkSha1(const char *msg, int msg_len, char *digest, const char *key, int key_len);
#ifdef  __cplusplus
}
#endif

#endif /* __HMAC_SHA1_H__ */
