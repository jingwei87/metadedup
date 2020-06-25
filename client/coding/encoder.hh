/*
 *  encoder.hh 
 */

#ifndef __ENCODER_HH__
#define __ENCODER_HH__

//#define ENCODE_ONLY_MODE 1
#include "CDCodec.hh"
#include "CryptoPrimitive.hh"
#include "conf.hh"
#include "DataStruct.hh"
#include "Logger.hh"
#include "MessageQueue.hh"
#include "uploader.hh"

#include <openssl/bn.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <cstdio>
#include <memory>
#include <cstdlib>

#define HASH_SIZE 32
#define KEY_SIZE 32

/* num of total shares in this system. 4 is default(k + 1) */
#define TOTAL_SHARES_NUM 4

/* num of encoder threads */
#define NUM_THREADS 2

/* buffer queue size */
#define QUEUE_SIZE (1024)

/* max share buffer size */
#define SHARE_BUFFER_SIZE (4 * 16 * 1024)

/* object type indicators */
#define FILE_OBJECT 1
#define FILE_HEADER (-9)
#define SHARE_OBJECT (-8)
#define SHARE_END (-27)

class Encoder {
private:

    /*
     * get the next index when looping inside obj->n_ server
     *
     */
    inline int getNextStreamIndex(int &current, int &modulus)
    {
        return (current + 1) % modulus;
    }

    /*
     * Assign the share_header of metadata chunk
     *
     * @param metaChunkUploadObj - the metadata chunk to be sent to uploader
     * @param metaChunkID - the ID of metadata chunk
     * @param counter - count the number of metaNodes
     * @param segID - the ID of segment
     * @param shareID - the ID of current share of a data chunk
     * @param kmCloudIndex - the index of Key Manager Server
     *
     */
    void assignMetaShareHeader(Uploader::ItemMeta_t &metaChunkUploadObj, int &metaChunkID, int &counter, int &segID,
                               int &shareID, short &kmCloudIndex);

    /*
     * Assemble metaNodes into metadata chunks
     *
     * @param metaChunkUploadObj - the metadata chunk to be sent to uploader
     * @param metaChunkBuffer - buffer of mataNodes
     * @param counter - count the number of metaNodes
     *
     */
    void assembleMetadataChunks(Uploader::ItemMeta_t &metaChunkUploadObj, unsigned char *metaChunkBuffer, int &counter);

    /*
     * thread handler for encoding secret into shares
     *
     * @param param - parameters for each thread
     */
    static void *thread_handler(void *param);

    /*
     * thread handler for calculating hash of data shares
     *
     * @param param - parameters for each thread
     */
    static void *thread_handler_hash(void *param);

    /*
     * collect thread for getting share objects in order
     *
     * @param param - parameters for collect thread
     */
    static void *collect(void *param);

public:

    /* threads parameter structure */
    typedef struct {
        int index; // thread number
        Encoder *obj; // encoder object pointer
    } param_encoder;

    /* file head structure */
    typedef struct {
        unsigned char data[SECRET_SIZE];
        int fullNameSize;
        long fileSize;
    } fileHead_t;

    /* secret metadata structure */
    typedef struct {
        unsigned char data[SECRET_SIZE];
        unsigned char key[KEY_SIZE];
        int secretID;
        int secretSize;
        int segID;
        int end;
    } Secret_t;

    /* share metadata structure */
    typedef struct {
        unsigned char data[SHARE_BUFFER_SIZE];
        unsigned char key[KEY_SIZE];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int end;
    } ShareChunk_t;

    /*the entry structure of the recipes of a file*/
    typedef struct {
        char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int segID;
        int shareID;
    } fileRecipeEntry_t;

    /* union header for secret ringbuffer */
    typedef struct {
        union {
            Secret_t secret;
            fileHead_t file_header;
        };
        int type;
        int kmCloudIndex;
    } Secret_Item_t;

    /* the input secret ringbuffer */
    MessageQueue<Chunk_t> **inputbuffer_;

    /* the input secret buffer queue for calculating hashes */
    MessageQueue<Chunk_t> **calc_inputbuffer_;

    /* the output secret buffer queue for calculating hashes */
    MessageQueue<Chunk_t> **calc_outputbuffer_;
    /* thread id array */
    pthread_t tid_[NUM_THREADS + 1];

    /* thread id array */
    pthread_t calc_tid_[NUM_THREADS];

    // crpyto object
    CryptoPrimitive **calc_cryptoObj_;

    /* the total number of clouds */
    int n_;

    /* the total number of KM-assisted server */
    int kmServerCount_;

    /* index for sequentially adding object */
    int nextAddIndex_;

    /* coding object array */
    CDCodec *encodeObj_[NUM_THREADS + 1];

    /* uploader object */
    Uploader *uploadObj_;

    /* crypto object array */
    CryptoPrimitive **cryptoObj_;

    // segment temp

    typedef struct {
        unsigned char shareFP[HASH_SIZE];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } metaNode;

    /*
     * constructor of encoder
     *
     * @param type - convergent dispersal type
     * @param n - total number of shares generated from a secret
     * @param m - reliability degree
     * @param kmServerCount - number of KM-assisted server (n - kmServerCount <=> original n)
     * @param r - confidentiality degree
     * @param securetype - encryption and hash type
     * @param uploaderObj - pointer link to uploader object
     *
     *
     */
    Encoder(int type,
            int n,
            int m,
            int kmServerCount,
            int r,
            int securetype,
            Uploader *uploaderObj);

    /*
     * destructor of encoder
     */
    ~Encoder();

    /*
     * test if it's end of encoding a file
     */
    void indicateEnd();

    /*
     * add function for sequencially add items to each encode buffer
     *
     * @param item - input object
     */
    int add(Chunk_t &item);

    /*
     * collect file header
     *
     * @param header - file header to be collect and send it to Uploader
     *
     */
    void collect_header(FileHeader_t &header);
};

#endif
