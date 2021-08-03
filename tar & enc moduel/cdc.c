#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <glib/gstdio.h>
#include "cdc.h"
#include "rabinchecksum.h"
#include "utils.h"
#include <openssl/md5.h>
#include "encrypt.h"
#include "keystore.h"

#define finger rabin_checksum
#define rolling_finger rabin_rolling_checksum

#define BLOCK_SZ        (1024*1024*1)
#define BLOCK_MIN_SZ    (1024*256)
#define BLOCK_MAX_SZ    (1024*1024*4)
#define BLOCK_WIN_SZ    48

#define NAME_MAX_SZ     4096

#define BIG_FILE_SZ (1 << 30) /* 1GB */
#define BIG_SZ (1 << 26) /* 64MB */

#define BREAK_VALUE     0x0013    ///0x0513

#define READ_SIZE 1024 * 4

#define BYTE_TO_HEX(b)  (((b)>=10)?('a'+b-10):('0'+b))

extern char *enc_buffer; //这里保存加密后的内容
extern int *split; //这里保存分块信息
extern char *hashlist;//这里保存段信息

int file_size2(const char* filename)
{
    struct stat statbuf;
    stat(filename,&statbuf);
    int size=statbuf.st_size;
 
    return size;
}

int write_chunk ( CDCDescriptor *chunk, uint8_t *checksum)
{
    GChecksum *ctx = g_checksum_new (G_CHECKSUM_SHA1);
    gsize len = 20;
    int ret = 0;
    printf("%d\n",chunk->len);
    g_checksum_update (ctx, (unsigned char *)chunk->block_buf, chunk->len);
    g_checksum_get_digest (ctx, checksum, &len);

    ret = do_write_chunk (checksum, chunk->block_buf, chunk->len);
    
    g_checksum_free (ctx);

    return ret;
}

void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[3];
    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 2], szTmp, 2 );
    }
    return;
}

static int init_cdc_file_descriptor (int fd,
                                     uint64_t file_size,
                                     CDCFileDescriptor *file_descr)
{
    int max_block_nr = 0;
    int block_min_sz = 0;

    file_descr->file_size = 0;
    file_descr->block_nr = 0;

    if (file_descr->block_min_sz <= 0)
        file_descr->block_min_sz = BLOCK_MIN_SZ;
    if (file_descr->block_max_sz <= 0)
        file_descr->block_max_sz = BLOCK_MAX_SZ;
    if (file_descr->block_sz <= 0)
        file_descr->block_sz = BLOCK_SZ;

    if (file_descr->write_block == NULL)
        file_descr->write_block = (WriteblockFunc)write_chunk;

    block_min_sz = file_descr->block_min_sz;
    max_block_nr = ((file_size + block_min_sz - 1) / block_min_sz);
    file_descr->blk_sha1s = (uint8_t *)calloc (sizeof(uint8_t),
                                               max_block_nr * CHECKSUM_LENGTH);
    file_descr->max_block_nr = max_block_nr;

    return 0;
}

#define WRITE_CDC_BLOCK(block_sz)                            \
do {                                                         \
    int _block_sz = (block_sz);                              \
    chunk_descr.len = _block_sz;                             \
    chunk_descr.offset = offset;                             \
    ret = file_descr->write_block (&chunk_descr,             \
                                   chunk_descr.checksum);    \
    if (ret < 0) {                                           \
        free (buf);                                          \
        g_warning ("CDC: failed to write chunk.\n");         \
        return -1;                                           \
    }                                                        \
    memcpy (file_descr->blk_sha1s +                          \
            file_descr->block_nr * CHECKSUM_LENGTH,          \
            chunk_descr.checksum, CHECKSUM_LENGTH);          \
    g_checksum_update (file_ctx, chunk_descr.checksum, 20);       \
    file_descr->block_nr++;                                  \
    offset += _block_sz;                                     \
                                                             \
    memmove (buf, buf + _block_sz, tail - _block_sz);        \
    tail = tail - _block_sz;                                 \
    cur = 0;                                                 \
}while(0);

/* content-defined chunking */
int file_chunk_cdc(int fd_src, CDCFileDescriptor *file_descr)
{
    char *buf = NULL;
    MD5_CTX ctx;
    uint32_t buf_sz;
    GChecksum *file_ctx = g_checksum_new (G_CHECKSUM_SHA1);
    CDCDescriptor chunk_descr;
    int ret = 0;
    unsigned char outmd[16];
    char hash[33];

    struct stat st;
    if (fstat (fd_src, &st) < 0) {
        printf ("CDC: failed to stat: %s.\n", strerror(errno));
        ret = -1;
        goto out;
    }
    uint64_t expected_size = st.st_size;
    
    enc_buffer = malloc(expected_size);//为指针分配内存空间，用来储存未加密信息
    readn(fd_src, enc_buffer, expected_size);//将文件内容读入enc_buffer
    MD5_Init(&ctx);
    MD5_Update(&ctx,enc_buffer,expected_size);
    MD5_Final(outmd,&ctx);//计算哈希值用来预判断
    Hex2Str(outmd,hash,16);
    
    // printf("connect to redis...\n");
    // int inhashtable = predict(hash);
    // if(inhashtable){
    //     printf("mainkey matched ok\n");
    //     printf("this file no changed\n");
    //     return -1;
    // }else{
    //     sethash(hash);
    // }

    init_cdc_file_descriptor (fd_src, expected_size, file_descr);
    uint32_t block_min_sz = file_descr->block_min_sz;
    uint32_t block_mask = file_descr->block_sz - 1;

    int fingerprint = 0;
    int offset = 0;
    int tail, cur, rsize,cpy_len;
    int feature = 0;

    buf_sz = file_descr->block_max_sz;
    buf = chunk_descr.block_buf = malloc (buf_sz);
    if (!buf) {
        ret = -1;
        goto out;
    }

    int max_chunk_sum =  expected_size/block_min_sz + 1;
    split = malloc(max_chunk_sum * 4);

    /* buf: a fix-sized buffer.
     * cur: data behind (inclusive) this offset has been scanned.
     *      cur + 1 is the bytes that has been scanned.
     * tail: length of data loaded into memory. buf[tail] is invalid.
     */
    cpy_len = tail = cur = 0;
    while (1) {
        if(expected_size > BIG_FILE_SZ){
            int allchunknum = expected_size/BIG_SZ + 1;
            int lastchunksize = expected_size%BIG_SZ;
            for(int i = 0;i<allchunknum;i++){
                if(i != allchunknum -1){
                    encrypt_chunk(enc_buffer + i * BIG_SZ,BIG_SZ,feature);
                }else{
                    encrypt_chunk(enc_buffer + i * BIG_SZ,lastchunksize,feature);
                }
                if(i = 50){
                    return feature;//超过这个大小测试的机子内存不够了
                }
            }
            break;
        }
        if (tail < block_min_sz) {
            rsize = block_min_sz - tail + READ_SIZE;
        } else {
            rsize = (buf_sz - tail < READ_SIZE) ? (buf_sz - tail) : READ_SIZE;
        }
        ret = (rsize > expected_size - cpy_len) ? expected_size - cpy_len : rsize;
        memcpy(buf + tail, enc_buffer + cpy_len, ret);
        if (ret < 0) {
            printf ("CDC: failed to read: %s.\n", strerror(errno));
            ret = -1;
            goto out;
        }
        cpy_len += ret;
        tail += ret;
        file_descr->file_size += ret;

        if (file_descr->file_size > expected_size) {
            printf ("File size changed while chunking.\n");
            ret = -1;
            goto out;
        }

        /* We've read all the data in this file. Output the block immediately
         * in two cases:
         * 1. The data left in the file is less than block_min_sz;
         * 2. We cannot find the break value until the end of this file.
         */
        if (tail < block_min_sz || cur >= tail) {
            if (tail > 0) {
                if (file_descr->block_nr == file_descr->max_block_nr) {
                    printf ("Block id array is not large enough, bail out.\n");
                    ret = -1;
                    goto out;
                }
                split[file_descr->block_nr] = tail;//保存分块信息
                file_descr->block_nr++;
                //WRITE_CDC_BLOCK (tail);
            }
            break;
        }

        /* 
         * A block is at least of size block_min_sz.
         */
        if (cur < block_min_sz - 1)
            cur = block_min_sz - 1;

        while (cur < tail) {
            fingerprint = (cur == block_min_sz - 1) ?
                finger(buf + cur - BLOCK_WIN_SZ + 1, BLOCK_WIN_SZ) :
                rolling_finger (fingerprint, BLOCK_WIN_SZ, 
                                *(buf+cur-BLOCK_WIN_SZ), *(buf + cur));
            //记录特征值
            if (fingerprint > feature){
                feature = fingerprint;
            }

            /* get a chunk, write block info to chunk file */
            if (((fingerprint & block_mask) ==  ((BREAK_VALUE & block_mask)))
                || cur + 1 >= file_descr->block_max_sz)
            {
                if (file_descr->block_nr == file_descr->max_block_nr) {
                    printf ("Block id array is not large enough, bail out.\n");
                    ret = -1;
                    goto out;
                }
                split[file_descr->block_nr] = cur + 1;//保存分块信息
                memmove (buf, buf + cur + 1, tail - cur - 1);
                tail = tail - cur - 1;
                cur = 0;
                file_descr->block_nr++; 
                //WRITE_CDC_BLOCK (cur + 1);
                break;
            } else {
                cur ++;
            }
        }
    }
    
    /* 加密部分 */
    offset = 0;
    for(int i=0;i<file_descr->block_nr;i++){
        encrypt_chunk(enc_buffer + offset,split[i],feature);//向rsync中定义的指针写入加密内容
        offset += split[i];
    }
    

    // MD5_CTX ctx;
    // unsigned char outmd[16];
    // char filename[33];
    // int chunk_len;
    // int out_cur = 0;
    // char *hash_buf = NULL;
    // char *enc_buf = NULL;
    // char outname[128];

    // hash_buf = malloc(32);
    // 根据分块信息输出块
    // for(int i=0;i<file_descr->block_nr;i++){
    //     //加密块
    //     chunk_len = split[i];
    //     pad_len = 16 - (chunk_len % 16);
    //     enc_buf = malloc(chunk_len + pad_len);
    //     memcpy(enc_buf,out_buf + out_cur,chunk_len); 
    //     enc_buf = encrypt_chunk(enc_buf,chunk_len + pad_len,feature);
    //     //计算哈希值
    //     memcpy(hash_buf,enc_buf,32);//读取块头32字节的内容
    //     MD5_Init(&ctx);
    //     MD5_Update(&ctx,hash_buf,32);
    //     MD5_Final(outmd,&ctx);//计算哈希值做为文件名
    //     Hex2Str(outmd,filename,16);
    //     filename[32] = '\0';
    //     //输出文件
    //     strcpy(outname,temp_path);
    //     strcat(outname,filename);
    //     fp = fopen(outname, "wb");
    //     fwrite(enc_buf,1,chunk_len,fp);
    //     out_cur += chunk_len;
    //     free(enc_buf);
    // }


out:
    free (buf);
    g_checksum_free (file_ctx);

    return feature;
}

void cdc_init ()
{
    rabin_init (BLOCK_WIN_SZ);
}

#define CDC_AVERAGE_BLOCK_SIZE (1 << 16) /* 64KB */
#define CDC_MIN_BLOCK_SIZE (1 << 14) /* 16KB */
#define CDC_MAX_BLOCK_SIZE (1 << 18) /* 256KB */

int cdc_work(int fd_src)
{
    CDCFileDescriptor cdc;
    cdc.block_sz = CDC_AVERAGE_BLOCK_SIZE;
    cdc.block_min_sz = 32;
    cdc.block_max_sz = CDC_MAX_BLOCK_SIZE;
    cdc.write_block = write_chunk;

    return file_chunk_cdc (fd_src, &cdc);
}
