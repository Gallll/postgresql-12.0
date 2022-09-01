/*
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright(c) 1994, Regents of the University of California
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "getopt_long.h"

int base64_decode(char *in_str, int in_len, char *out_str);

int main(int argc, char **argv)
{
    int ch;
    char * optstr = "deg";
  
    while ((ch = getopt_long(argc, argv,"deg",NULL,NULL))!=-1)
    {
        switch (ch)
        {
        case 'd':
            {
                printf("enter passwd to decrypt\n");
                char *passwd = (char *)palloc0(1024);
                scanf("%s", passwd);
                char *str = passwd + 4;
                char d_decdata[1024]={0};
                int decode_lenth = base64_decode(str, strlen(str), d_decdata);
                EVP_CIPHER_CTX *ctx;
                unsigned char key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
                unsigned char iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
                int tmplen = 16;
                int declen = 0;
                char decdata[1024] = {0};
                char *encode;
                encode = d_decdata;
                char decode[1024] = {0};
                int ret;
                OpenSSL_add_all_algorithms();
                ctx = EVP_CIPHER_CTX_new();
                ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
                if (ret != 1)
                {
                    printf("EVP_EncryptFinal_ex failed.\n");
                    EVP_CIPHER_CTX_free(ctx);
                }

                ret = EVP_DecryptUpdate(ctx, decdata, &declen, encode, decode_lenth);
                if (ret != 1)
                {
                    printf("EVP_EncryptFinal_ex failed.\n");
                    EVP_CIPHER_CTX_free(ctx);
                }

                ret = EVP_DecryptFinal_ex(ctx, decdata + declen, &tmplen);
                if (ret != 1)
                {
                    printf("EVP_EncryptFinal_ex failed.\n");
                    EVP_CIPHER_CTX_free(ctx);
                }

                declen += tmplen;

                /* check the result */
                // printf("decrypt message: %s.\n", decdata);
                decdata[declen] = '\0';
                printf("password is\n%s\n", decdata);
                return 0;
            }

            break;
        
        default:
            printf("erro option\n");
            return 0;
        }
    }
    
    EVP_CIPHER_CTX *ctx;
    char *base64Encode(const char *buffer, int length);
    printf("请输入密码\n");

    unsigned char key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned char iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    unsigned char encdata[1024] = {0};
    unsigned char decdata[1024] = {0};

    int enclen = 0, tmplen;
    int declen = 0;
    unsigned char msg[1024];
    scanf("%s", msg);
    int ret;
    OpenSSL_add_all_algorithms();
    ctx = EVP_CIPHER_CTX_new();

    /* Encrypt */
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (ret != 1)
    {
        printf("EVP_EncryptInit_ex failed.\n");
        goto end;
    }

    ret = EVP_EncryptUpdate(ctx, encdata, &enclen, msg, strlen(msg));
    if (ret != 1)
    {
        printf("EVP_EncryptUpdate failed.\n");
        goto end;
    }

    ret = EVP_EncryptFinal_ex(ctx, encdata + enclen, &tmplen);
    if (ret != 1)
    {
        printf("EVP_EncryptFinal_ex failed.\n");
        goto end;
    }

    enclen = enclen + tmplen;

    char *encode = base64Encode(encdata, enclen);
    printf("加密密码为####%s\n", encode);
end:

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

// base64 编码
char *base64Encode(const char *buffer, int length)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}
// base64 解码
int base64_decode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    int size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new_mem_buf(in_str, in_len);
    bio = BIO_push(b64, bio);

    size = BIO_read(bio, out_str, in_len);
    out_str[size] = '\0';

    BIO_free_all(bio);
    return size;
}
