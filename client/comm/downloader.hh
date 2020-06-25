/*
 * downloader.hh
 */

#ifndef __DOWNLOADER_HH__
#define __DOWNLOADER_HH__

#include <arpa/inet.h>
#include <cstring>
#include <condition_variable>
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <resolv.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>

#include "conf.hh"
#include "CryptoPrimitive.hh"
#include "DataStruct.hh"
#include "decoder.hh"
#include "Logger.hh"
#include "MessageQueue.hh"
#include "socket.hh"

/* Server Number (may be deleted in later version)*/
#define DOWNLOAD_SERVER_NUMBER 5

/* downloader buffer queue size */
#define DOWNLOAD_QUEUE_SIZE 2048

/* downloader ringbuffer data max size */
// META_BUFFER supports up to 16MB segment size
#define RING_BUFFER_DATA_SIZE (16 * 1024)
#define RING_BUFFER_META_SIZE (1250 * 1024)

/* downloader buffer size */
#define DOWNLOAD_BUFFER_SIZE (4 * 1024 * 1024)


/* fingerprint size*/
#define FP_SIZE 32
#define HASH_SIZE 32

#define MAX_NUMBER_OF_CLOUDS 16

#define END_DOWNLOAD_INDICATOR (-12)
#define FILE_RECIPE_SUCCESS (-111)

/* the size of metalist buffer */
#define METALIST_BUFFER_SIZE (100 << 20) // size: 100MB

/* the indicator of downloading meta_list back from server */
#define RECEIVE_META_LIST (1001)

/* the indicator for "not found" in servers */
#define INODE_NOT_FOUND (-11)

using namespace std;

/*
 * download module
 * handle share to its targeting cloud
 *
 */
class Downloader {
private:

    //total number of clouds
    int total_;

    //number of a subset of clouds
    int subset_;

    //index of downed-server
    int down_server_index_;

    //number of downed-server
    int down_server_num_;

    //count servers to prevent downloadFile starting before finishing downloadFileRecipe
    static int server_mutex_num;

    //mutex for server_mutex_num
    static std::mutex count_mutex;

    //mutex for condition_variable
    std::mutex m_mutex;
    static std::condition_variable cv_mutex;

    // buffer for storing metalist
    std::unique_ptr<std::unique_ptr<unsigned char[]>[]> meta_list_buffer_;

    // count the number in a meta_list
    std::unique_ptr<int[]> count_MetaList_item_;

    /*
     * <Deprecated in KM-assisted version>
     * download file recipe
     *
     * @param recipeName - the name of file recipe
     * @param cloudIndex - the index of server
     */
    static int downloadFileRecipe(std::string &recipeName, int cloudIndex, Downloader *obj);


    /*
     * download meta list from server
     *
     * @param metalist_buffer - the buffer storing meta_list<return>
     * @param socket - socket object for receiving data from server
     *
     * */
    void download_meta_list(unsigned char *metalist_buffer, Socket *socket, int &counter, int cloudIndex);

    /*
     * skip one line from config file
     *
     * @param fp - file pointer to config file
     * @param line - the buffer to store line
     *
     * */
    void skip_config_one_line(FILE *fp, char *line);

    /*
     * assign kShareIDList value
     *
     * @param kShareID - id to be modified
     * @param id - id of MetaList
     *
     * */
    void assign_kShareID_in_list(int &kShareID, int id);

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


    /* file share count struct for download */
    typedef struct {
        long fileSize;
        int numOfShares;
    } shareFileHead_t;

    /*the head structure of the recipes of a file*/
    typedef struct {
        int userID;
        long fileSize;
        int numOfShares;
    } fileRecipeHead_t;

    /*the entry structure of the recipes of a file*/
    typedef struct {
        char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int segID;
        int shareID;
    } fileRecipeEntry_t;

    /* share detail struct for download */
    typedef struct {
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } shareEntry_t;

    /* share metadata header structure */
    typedef struct {
        char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } shareMDEntry_t;

    /* file header object structure for ringbuffer */
    typedef struct {
        shareFileHead_t file_header;
        char data[RING_BUFFER_DATA_SIZE];
    } fileHeaderObj_t;

    /* share header object structure for ringbuffer */
    typedef struct {
        shareEntry_t share_header;
        char data[RING_BUFFER_DATA_SIZE];
    } shareHeaderObj_t;

    /* share header object structure for ringbuffer */
    typedef struct {
        shareMDEntry_t share_header;
        char data[RING_BUFFER_META_SIZE];
    } metaShareHeaderObj_t;

    /* union of objects for unifying ringbuffer objects */
    typedef struct {
        int type;
        union {
            fileHeaderObj_t fileObj;
            shareHeaderObj_t shareObj;
        };
    } Item_t;

    /* union of objects for unifying ringbuffer objects */
    typedef struct {
        int type;
        union {
            fileHeaderObj_t fileObj;
            metaShareHeaderObj_t shareObj;
        };
    } ItemMeta_t;

    /* init object for initiating download */
    typedef struct {
        int type;
        char filename[256];
        int nameSize;
    } init_t;

    /* thread parameter structure */
    typedef struct {
        int cloudIndex;
        int numOfCloud;
        char fileName[256];
        int fileNameLength;
        Downloader *obj;
    } param_t;

    typedef struct {
        unsigned char shareFP[HASH_SIZE];
        unsigned char other[18];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
        int shareID;
    } metaNode;

    typedef struct {
        int id;
        int shareID;
        int end_secretID;
    } MetaList;

    /* file header pointer array for modifying header */
    fileShareMDHead_t **headerArray_;

    /* socket array */
    Socket **socketArray_;

    /* metadata buffer */
    char **downloadMetaBuffer_;

    /* container buffer */
    char **downloadContainer_;

    /* size of file header */
    int fileMDHeadSize_;

    /* size of share header */
    int shareMDEntrySize_;

    /* thread id array */
    pthread_t tid_[DOWNLOAD_SERVER_NUMBER * 2];

    /* decoder object pointer */
    Decoder *decodeObj_;

    /* signal buffer */
    MessageQueue<init_t> **signalBuffer_;

    /* download ringbuffer */
    MessageQueue<Item_t> **ringBuffer_;
    MessageQueue<ItemMeta_t> **ringBufferMeta_;
    char name_[256];

    int *fileSizeCounter;
    int userID_;

    /*
     * constructor
     *
     * @param total - input total number of clouds
     * @param subset - input number of clouds to be chosen
     * @param down_server_index - the index of downed server
     * @param down_server_num - the number of downed servers
     * @param userID - ID of the user who initiate download
     * @param obj - decoder pointer
     * @param fileName - the file name to be downloaded
     * @param nameSize - size of the file name to be downloaded
     */
    Downloader(int total, int subset, int down_server_index, int down_server_num, int userID, Decoder *obj,
               char *fileName, int nameSize);

    /*
     * destructor
     *
     */
    ~Downloader();

    /*
     * test if it's the end of downloading a file
     *
     */
    int indicateEnd();

    /*
     * main procedure for downloading a file
     *
     * @param filename - targeting filename
     * @param namesize - size of filename
     * @param numOfCloud - number of clouds that we download data
     * @param numOfRestoreServer - number of servers at least that we needed to download data
     *
     */
    int downloadFile(char *filename, int namesize, int numOfCloud, int numOfRestoreServer);

    /*
     * pre-download file
     * send file meta-data to tell servers which file to be downloaded, aka, requesting server-side generation of
     * data file recipe from servers
     *
     * @param filename - targeting filename
     * @param nameSize - size of filename
     * @param numOfCloud - number of clouds that we download data
     *
     */
    int preDownloadFile(char *filename, int nameSize, int numOfCloud);

    /*
     * downloader thread handler
     *
     * @param param - input param structure
     *
     */
    static void *thread_handler(void *param);

    /*
     * downloader thread handler for downloading file recipes
     *
     * @param param - input param structure
     *
     */
    static void *thread_handler_meta(void *param);

    /*
     * set the number of downed servers
     *
     * @param num - the number of downed-server
     *
     * */
    void set_down_server_number(int num);

    /*
     * set the index of downed servers
     *
     * @param index - the index of downed-server
     *
     * */
    void set_down_server_index(int index);

    /*
     * Check whether segID < 0, which is abnormal
     *
     * @param item - the item to be checked with segID
     *
     * */
    void error_check_segID(Item_t &item);

    /*
     * extract MetaList from meta_list_buffer_
     *
     * @param metalist_buffer - the buffer storing meta_list
     * @param offset - the offset of reading buffer<return>
     * @param loop_num - count for the total number of extracted from meta_list<return>
     * @param meta_list - for storing MetaList extracted from buffer<return>
     *
     * */
    void extract_meta_list(unsigned char *metalist_buffer, int &offset, int &loop_num,
                           Downloader::MetaList &meta_list);
};

#endif
