#include <jni.h>
#include <string>
#include <android/log.h>
#include <sys/time.h>
#include <stdlib.h>
#include "math.h"
#include "md5.h"

#include "hmac_sha1.h"
#include "test.h"
#include "base64.h"

#define  LOG_TAG1    "MD5-JNI"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG1,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG1,__VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG1,__VA_ARGS__)

#define STATIC_MIXBITS_INDEX	111

//public static int EBT_FOR_SIGN = 1;
const unsigned char S_PRIVATE_KEY1[] = "cc16be4b:346c51d";
const unsigned char S_PRIVATE_KEY_NEW[] = "X7EuZCgWwhv2yzN4XOm52QIdTmKn";
const unsigned char eto32_table1[] = "AB56DE3C8L2WF4UVM7JRSGPQYZTXK9HN";

//public static int EBT_FOR_USERPASSWORD = 2;
const unsigned char S_PRIVATE_KEY2[] = "@kK1818$";
const unsigned char eto32_table2[] = "2WF4JZ7XKTC8LSGHUDEPQYVM9R63NAB5";

//PAY ATTENTION: my_bits_disp only is allowed to encode a string whose length is less than 22 charactors
int my_bits_disp(unsigned char * pSrcDestBits, unsigned char nSrcBitsLen,
		unsigned char * pDispBits, unsigned char nDispBitsLen,
		unsigned short nIndex) {
	unsigned int i;
	if (!pSrcDestBits || !pDispBits || (nSrcBitsLen + nDispBitsLen) < 2
			|| (nSrcBitsLen + nDispBitsLen) > 255)
		return -1;

	unsigned char* pTemp = new unsigned char[nSrcBitsLen + nDispBitsLen];
	if (!pTemp)
		return -1;
	for (i = 0; i < (unsigned int) nSrcBitsLen + nDispBitsLen; i++) {
		pTemp[i] = (unsigned char) i;
	}

	unsigned int n = (nSrcBitsLen - 1) / 8 + 1;
	//change pSrcBits
	for (i = 0; i < n; i += 2) {
		*(pSrcDestBits + i) ^= (unsigned char) nIndex;
	}

	//dispatch pDispBits into pSrcBis
	//using nIndex+(nIndex+(13,21,34,55,...))%nSrcBitsLen select insert point.
	unsigned int a = 13, b = 21;
	unsigned int s = nDispBitsLen;
	unsigned char v;
	while (nDispBitsLen) {
		//use a
		n = (nIndex + (nIndex + a) % nSrcBitsLen) % nSrcBitsLen;
		for (i = nSrcBitsLen; i > n; i--) {
			pTemp[i] = pTemp[i - 1];
		}
		pTemp[n] = nSrcBitsLen;
		b = a + b;
		a = b - a;
		nSrcBitsLen++;
		nDispBitsLen--;
	}
	nDispBitsLen = s;
	nSrcBitsLen = nSrcBitsLen - nDispBitsLen;
	unsigned char * pFrom;
	for (i = 0; i < (unsigned int) nSrcBitsLen + nDispBitsLen; i++) {
		if (pTemp[i] >= nSrcBitsLen) {
			pFrom = pDispBits;
			pTemp[i] -= nSrcBitsLen;
		} else {
			pFrom = pSrcDestBits;
		}
		v = *(pFrom + pTemp[i] / 8);
		v >>= (7 - pTemp[i] % 8);
		pTemp[i] = v;
	}
	pFrom = pSrcDestBits;
	v = 0;
	for (i = 0; i < (unsigned int) nSrcBitsLen + nDispBitsLen; i++) {
		v |= (pTemp[i] & 1) << (7 - i % 8);
		if (i % 8 == 7) {
			*(pFrom++) = v;
			v = 0;
		}
	}
	if (i % 8 != 0)
		*(pFrom++) = v;
	delete[] pTemp;
	return nSrcBitsLen + nDispBitsLen;
}


int my_bits_disp_reverse(unsigned char * pSrcDestBits,
		unsigned char nSrcBitsLen, unsigned char * pDispBits,
		unsigned char nDispBitsLen, unsigned short nIndex) {
	unsigned int i;
	unsigned int j;
	if (!pSrcDestBits || !pDispBits || (nSrcBitsLen + nDispBitsLen) < 2
			|| (nSrcBitsLen + nDispBitsLen) > 255)
		return -1;

	unsigned char* pTemp = new unsigned char[nSrcBitsLen + nDispBitsLen];
	if (!pTemp)
		return -1;
	for (i = 0; i < (unsigned int) nSrcBitsLen + nDispBitsLen; i++) {
		pTemp[i] = (unsigned char) i;
	}

	unsigned int n;
	//dispatch pDispBits into pSrcBis
	//using nIndex+(nIndex+(13,21,34,55,...))%nSrcBitsLen select insert point.
	unsigned int a = 13, b = 21;
	unsigned int s = nDispBitsLen;
	unsigned char v;
	while (nDispBitsLen) {
		//use a
		n = (nIndex + (nIndex + a) % nSrcBitsLen) % nSrcBitsLen;
		for (i = nSrcBitsLen; i > n; i--) {
			pTemp[i] = pTemp[i - 1];
		}
		pTemp[n] = nSrcBitsLen;
		b = a + b;
		a = b - a;
		nSrcBitsLen++;
		nDispBitsLen--;
	}
	nDispBitsLen = s;
	nSrcBitsLen = nSrcBitsLen - nDispBitsLen;

	v = 0;
	a = 0;
	for (j = nSrcBitsLen; j < (unsigned int) nDispBitsLen + nSrcBitsLen; j++) {
		for (i = 0; i < (unsigned int) nSrcBitsLen + nDispBitsLen; i++) {
			if (j == pTemp[i]) {
				v |= ((pSrcDestBits[i / 8] >> (7 - i % 8)) & 1) << (7 - a);
				if (a % 8 == 7) {
					*(pDispBits++) = v;
					v = 0;
					a = 0;
				} else
					a++;
				break;
			}
		}
	}
	if (a != 0)
		*(pDispBits++) = v;

	v = 0;
	j = 0;
	for (i = 0; i < (unsigned int) nSrcBitsLen + nDispBitsLen; i++) {
		if (pTemp[i] < nSrcBitsLen) {
			v |= ((pSrcDestBits[i / 8] >> (7 - i % 8)) & 1) << (7 - j % 8);
			if (j % 8 == 7) {
				*(pSrcDestBits + j / 8) = v;
				v = 0;
			}
			j++;
		}
	}
	if (j % 8 != 0)
		*(pSrcDestBits + j / 8) = v;
	n = (nSrcBitsLen - 1) / 8 + 1;
	//change pSrcBits
	for (i = 0; i < n; i += 2) {
		*(pSrcDestBits + i) ^= (unsigned char) nIndex;
	}
	delete[] pTemp;
	return nSrcBitsLen + nDispBitsLen;
}


void encode(unsigned char * in, unsigned int ilen, unsigned char * out,
		unsigned int olen, char* eto32_table) {
	//_ASSERT(in && out);
	int s = 0;
	unsigned int j = 0;
	unsigned char buf[2] = { 0 };
	for (unsigned int i = 0; i < ilen; i++) {
		buf[0] = *(in + i);
		buf[1] = i + 1 < ilen ? *(in + i + 1) : 0;
		buf[0] <<= s;
		buf[0] >>= s; //clear before s
		if (s >= 3) {
			buf[0] = (buf[0] << (s - 3)) | (buf[1] >> (11 - s));
			*(out + j++) = eto32_table[buf[0]];
			s = s - 3;
		} else {
			*(out + j++) = eto32_table[buf[0] >> (8 - s - 5)];
			s += 5;
			i--; //still consume this byte
			//_ASSERT(s<8);
		}
		if (j >= olen)
			break;
	}
}
bool decode(unsigned char * in, unsigned int ilen, unsigned int sb,
		unsigned char * out, unsigned int olen, char* eto32_table) {
	//sb --> 0-4
	memset(out, 0, olen);
	int left = 0; //left --> 0-7
	unsigned char m;

	if (sb >= 5)
		return false;
	unsigned int i = 0;
	unsigned int j = 0;
	while (i < ilen) {
		for (m = 0; m < 32; m++) {
			if (in[i] == eto32_table[m])
				break;
		}
		if (m == 32)
			return false;
		while (sb < 5) {
			if (m & ((unsigned char) 1 << (4 - sb)))
				out[j] |= ((unsigned char) 1 << (7 - left));
			left++;
			if (left == 8) {
				left = 0;
				j++;
				if (j >= olen)
					return true; //false
			}
			sb++;
		}
		i++;
		sb = 0;
	}
	return true;
}


int encodeUserNameAndPassword(const char* namepassword, int len,
		char** ppEncoded, int* pEncodedLen) {
	if (namepassword == NULL || len < 2 || ppEncoded == NULL)
		return -1;
	char *libvar = getenv("MELOTENV");
	if (libvar == NULL) {
		//return -1;
	}
	//12 chars for one section
	int secs = (len / 12 + (len % 12 == 0 ? 0 : 1));
	*ppEncoded = new char[secs * 20]; //every sec needs 32 bytes
	memset(*ppEncoded, 0, secs * 20);
	*pEncodedLen = 0;

	unsigned short mixer = STATIC_MIXBITS_INDEX;
	char* p = *ppEncoded;
	int lenSec = 12;
	for (int i = 0; i < secs; i++) {
		if (i + 1 == secs)
			lenSec = len - i * 12;
		memcpy(p + i * 20, namepassword + i * 12, lenSec);
		int a = my_bits_disp((unsigned char*) (p + i * 20), lenSec * 8,
				(unsigned char*) S_PRIVATE_KEY2, 8 * 8, mixer);
		*pEncodedLen += a / 8;
		mixer = (unsigned char) (*(p + (i + 1) * 20 - 1));
	}

	return 0;
}

extern "C"{

JNIEXPORT jstring JNICALL Java_com_melot_magic_Magic_test(
        JNIEnv* env,
        jobject /* this */) {
    return   env->NewStringUTF((const char *)"hi");
}

JNIEXPORT jstring JNICALL Java_com_melot_magic_Magic_enp(
        JNIEnv *env,
        jobject obj,
        jstring jstr) {
   jstring ret;
   	const char *str = (env)->GetStringUTFChars(jstr, 0);

   	int len = strlen(str);
   	//LOGD("EncodeUserNameAndPassword %s len=%d",str,len);
   	char* pEncoded = NULL;
   	int lenEncoded = 0;
   	int iRet = encodeUserNameAndPassword(str, len, &pEncoded, &lenEncoded); //调用encodeUserNameAndPassword加密成up参数，注意释放pEncoded返回值
   	if (iRet == -1 || pEncoded == NULL) {
   		//LOGE("EncodeUserNameAndPassword err iRet=%d,pEncoded=%x",iRet,pEncoded);
   		return env->NewStringUTF("");
   	} else {
   		int strLen = lenEncoded * 8 / 5 + ((lenEncoded * 8) % 5 != 0 ? 1 : 0);
   		unsigned char* encodedUP = new unsigned char[strLen + 1];
   		encode((unsigned char*) pEncoded, lenEncoded, encodedUP, strLen,
   				(char*) eto32_table2); //将up值按照我们的方式encode成字符串编码
   		encodedUP[strLen] = 0;
   		ret = env->NewStringUTF((const char*) encodedUP);
   	}
   	(env)->ReleaseStringUTFChars(jstr, str);
   	delete[] pEncoded;
   	return ret;
    }

JNIEXPORT jstring JNICALL Java_com_melot_magic_Magic_em5(JNIEnv *env, jobject obj,
    		jstring jstr, jstring jstrup) {
    	jstring ret;
    	const char *str = (env)->GetStringUTFChars(jstr, 0);
    	const char *strup = (env)->GetStringUTFChars(jstrup, 0);
    	char* temp = new char[strlen(str) + strlen(strup) + 16 + 1]; // 测试字符串中加入上面计算出来的up参数，最后的字符串中加入S_PRIVATE_KEY1 => 16 bytes
    	strcpy(temp, str);
    	strcat(temp, (const char*) strup);
    	strcat(temp, (const char*) S_PRIVATE_KEY1);
    	temp[strlen(str) + strlen(strup) + 16] = 0;
    	unsigned char* p = MD5((const unsigned char *) temp, strlen(temp), NULL); //做MD5计算

    	unsigned char encoded[27] = { 0 };
    	encode(p, MD5_DIGEST_LENGTH, encoded, 26, (char*) eto32_table1); //将MD5值按照我们的方式encode成字符串
    	delete[] temp;
    	(env)->ReleaseStringUTFChars(jstr, str);
    	(env)->ReleaseStringUTFChars(jstrup, strup);
    	ret = env->NewStringUTF((const char*) encoded);
    	return ret;
    }

JNIEXPORT jstring JNICALL Java_com_melot_magic_Magic_em5byte(JNIEnv *env, jobject obj,
    		jbyteArray jByteStr, jstring jstrup) {
    	jstring ret;

    	jbyte* byte = (env)->GetByteArrayElements(jByteStr, 0);
    	const char *strup = (env)->GetStringUTFChars(jstrup, 0);

    	int byteLen = (env)->GetArrayLength(jByteStr);
    	char* temp = new char[byteLen + strlen(strup) + 16 + 1]; // 测试字符串中加入上面计算出来的up参数，最后的字符串中加入S_PRIVATE_KEY1 => 16 bytes

    	memcpy(temp, byte, byteLen);
    	temp[byteLen] = 0;
    	strcat(temp, (const char*) strup);
    	strcat(temp, (const char*) S_PRIVATE_KEY1);
    	temp[byteLen + strlen(strup) + 16] = 0;

    	unsigned char* p = MD5((const unsigned char *) temp, strlen(temp), NULL); //做MD5计算

    	unsigned char encoded[27] = { 0 };
    	encode(p, MD5_DIGEST_LENGTH, encoded, 26, (char*) eto32_table1); //将MD5值按照我们的方式encode成字符串

    	delete[] temp;
    	(env)->ReleaseByteArrayElements(jByteStr, byte, 0);
    	(env)->ReleaseStringUTFChars(jstrup, strup);
    	ret = env->NewStringUTF((const char*) encoded);
    	 return ret;
    }

JNIEXPORT jstring JNICALL Java_com_melot_magic_Magic_fire(JNIEnv *env, jobject obj,
    		jstring jstr) {
        jstring ret;
        int i=0;
        int j=0;
        char temp;
        int dataLength=0;
        int dstl=0;
    	const char* key = (const char*)S_PRIVATE_KEY_NEW;
    	const char* data = (const char *)(env)->GetStringUTFChars(jstr, 0);
    	char degest[800] = { 0 };
    	dataLength=strlen((const char*)data);

        kkSha1(data,dataLength,degest,key,strlen(key));
       unsigned char* result= base64_encode((unsigned char*)degest);

        ret = env->NewStringUTF((const char*) result);
    	return ret;
    }

JNIEXPORT jstring JNICALL Java_com_melot_magic_Magic_sign(JNIEnv *env, jobject obj,
        		jstring jstr,jstring jkey) {
            jstring ret;
            int i=0;
            int j=0;
            char temp;
            int dataLength=0;
            int dstl=0;
        	const char* key = (const char *)(env)->GetStringUTFChars(jkey, 0);
        	const char* data = (const char *)(env)->GetStringUTFChars(jstr, 0);
        	char degest[800] = { 0 };
        	dataLength=strlen((const char*)data);

            kkSha1(data,dataLength,degest,key,strlen(key));
           unsigned char* result= base64_encode((unsigned char*)degest);

            ret = env->NewStringUTF((const char*) result);
        	return ret;
        }

}




