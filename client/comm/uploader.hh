/*
 * uploader.hh
 */

#ifndef __UPLOADER_HH__
#define __UPLOADER_HH__

#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "conf.hh"
#include "CDCodec.hh"
#include "CryptoPrimitive.hh"
#include "DataStruct.hh"
#include "Logger.hh"
#include "MessageQueue.hh"
#include "socket.hh"

/* Server Number (may be deleted in later version)*/
#define UPLOAD_SERVER_NUMBER 5

/* upload buffer queue size */
#define UPLOAD_QUEUE_SIZE 2048

/* upload buffer size */
#define UPLOAD_BUFFER_SIZE (4 * 1024 * 1024)

/* fingerprint size */
#define FP_SIZE 32

/* num of upload threads */
/* one thread for one server => 5 thread for 5 servers */
#define UPLOAD_NUM_THREADS 5

/* object type indicators */
#define FILE_HEADER (-9)
#define SHARE_OBJECT (-8)
#define SHARE_END (-27)

// -202 is randomly picked to be recognized easily
#define DATA_SECRET_ID_END_INDICATOR (-202)
// 202 is randomly picked to be recognized easily
// PS: secretID in meta has to be more than 0 since secretID in meta starts from -1 to -unlimited
#define META_SECRET_ID_END_INDICATOR (202)



using namespace std;

/*
 * upload module
 * handle share to its targeting cloud
 *
 */
class Uploader {
private:
    //prime number for compute hash
    long prime_;

    //number of a subset of clouds
    int subset_;

public:
    /* file metadata header structure */
    typedef struct {
        int fullNameSize;
        long fileSize;
        int numOfPastSecrets;
        long sizeOfPastSecrets;
        int numOfComingSecrets;
        long sizeOfComingSecrets;
    } fileShareMDHead_t;

    /* share metadata header structure */
    typedef struct {
        unsigned char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } shareEntry_t;

    typedef struct {
        unsigned char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } shareMDEntry_t;

    /*the entry structure of the recipes of a file*/
    typedef struct {
        char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int segID;
    } fileRecipeEntry_t;

    /* file header object struct for ringbuffer */
    typedef struct {
        fileShareMDHead_t file_header;
        unsigned char data[RING_BUFFER_DATA_SIZE];
    } fileHeaderObj_t;

    /* share header object struct for ringbuffer */
    typedef struct {
        shareEntry_t share_header;
        unsigned char data[RING_BUFFER_DATA_SIZE];
    } shareHeaderObj_t;

    //meta chunk share
    typedef struct {
        shareMDEntry_t share_header;
        unsigned char data[RING_BUFFER_META_SIZE];
    } metaShareHeaderObj_t;

    /* union of objects for unifying ringbuffer objects */
    typedef struct {
        int type;
        union {
            fileHeaderObj_t fileObj;
            shareHeaderObj_t shareObj;
        };
        int kmCloudIndex;
    } Item_t;

    typedef struct {
        int type;
        union {
            fileHeaderObj_t fileObj;
            metaShareHeaderObj_t shareObj;
        };
        int kmCloudIndex;
    } ItemMeta_t;

    /* thread parameter structure */
    typedef struct {
        int cloudIndex;
        Uploader *obj;
    } param_t;

    typedef struct {
        unsigned char shareFP[32];
        unsigned char other[18];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } metaNode;


    //total number of clouds
    int total_;

    /* file header pointer array for modifying header */
    fileShareMDHead_t **headerArray_;

    /* socket array */
    Socket **socketArray_;

    /* metadata buffer */
    char **uploadMetaBuffer_;

    /* container buffer */
    char **uploadContainer_;

    /* container write pointer */
    int *containerWP_;

    /* metadata write pointer */
    int *metaWP_;

    /* indicate the number of shares in a buffer */
    int *numOfShares_;

    /* array for record each share size */
    int **shareSizeArray_;

    /* size of file metadata header */
    int fileMDHeadSize_;

    /* size of share metadata header */
    int shareMDEntrySize_;

    /* thread id array */
    pthread_t tid_[UPLOAD_NUM_THREADS * 2];

    /* record accumulated processed data */
    long long accuData_[UPLOAD_NUM_THREADS * 2];

    /* record accumulated unique data */
    long long accuUnique_[UPLOAD_NUM_THREADS * 2];

    /* uploader ringbuffer array */
    MessageQueue<Chunk_t> **ringBuffer_;
    MessageQueue<ItemMeta_t> **ringBufferMeta_;
    char name_[256];

    /*
     * constructor
     *
     * @param p - input large prime number
     * @param total - input total number of clouds
     * @param subset - input number of clouds to be chosen
     *
     */
    Uploader(int total, int subset, int userID, char *fileName, int nameSize);

    /*
     * destructor
     */
    ~Uploader();

    /*
     * Initiate upload
     *
     * @param cloudIndex - indicate targeting cloud
     * 
     */
    int performUpload(int cloudIndex, bool end);

    /*
     * indicate the end of uploading a file
     * 
     * @return total - total amount of data that input to uploader
     * @return uniq - the amount of unique data that transferred in network
     *
     */
    int indicateEnd(long long *total, long long *uniq);

    /*
     * interface for adding object to ringbuffer
     *
     * @param item - the object to be added
     * @param index - the buffer index
     *
     */
    int add(Chunk_t &item, int index);

    /*
     * interface for adding object to ringbuffer
     *
     * @param item - the object to be added
     * @param index - the buffer index
     *
     */
    int addMeta(ItemMeta_t &item, int index);

    /*
     * procedure for update headers when upload finished
     * 
     * @param cloudIndex - indicating targeting cloud
     *
     *
     *
     */
    int updateHeader(int cloudIndex);

    /*
     * uploader thread handler
     *
     * @param param - input structure
     *
     */
    static void *thread_handler(void *param);

    /*
     * uploader thread handler
     *
     * @param param - input structure
     *
     */
    static void *thread_handler_meta(void *param);


    /*
     * collect file header
     *
     * @param header - file header to be collect in Uploader
     * @param cloudIndex - the index of cloud server
     *
     */
    void collect_header(FileHeader_t &header, int cloudIndex);

private:

    /*
     * copy Chunk_t to Item_t
     *
     * @param output - dest of data structure
     * @param input - src of data structure
     *
     */
    void copy_Chunk_to_Item(Item_t &output, Chunk_t &input);
};

#endif
