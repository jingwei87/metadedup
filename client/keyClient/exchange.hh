#ifndef __EXCHANGE_HH__
#define __EXCHANGE_HH__

#include <bits/stdc++.h>
#include <utility>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <boost/compute/detail/lru_cache.hpp>

#include "ssl.hh"
#include "socket.hh"
#include "conf.hh"
#include "CryptoPrimitive.hh"
#include "DataStruct.hh"
#include "encoder.hh"
#include "Logger.hh"
#include "MessageQueue.hh"

/* init constants */
#define MAX_CMD_LENGTH 65535

#define VAR_SEG 77
#define FIX_SEG 88

#define KEY_BATCH_SIZE 256

/* average: 512K */
//#define MIN_SEGMENT_SIZE (256 * 1024)       //256KB
//#define AVG_SEGMENT_SIZE (512 * 1024)       //512KB
//#define MAX_SEGMENT_SIZE (1 * 1024 * 1024)  //1MB

/* average: 1M */
#define MIN_SEGMENT_SIZE (512 * 1024)       //512KB
#define AVG_SEGMENT_SIZE (1 * 1024 * 1024)  //1MB
#define MAX_SEGMENT_SIZE (2 * 1024 * 1024)  //2MB

/* average: 2M */
//#define MIN_SEGMENT_SIZE (1 * 1024 * 1024)  //1MB
//#define AVG_SEGMENT_SIZE (2 * 1024 * 1024)  //2MB
//#define MAX_SEGMENT_SIZE (4 * 1024 * 1024)  //4MB

/* average: 3M */
//#define MIN_SEGMENT_SIZE (1536 * 1024)      //1.5MB(original:2M)
//#define AVG_SEGMENT_SIZE (3 * 1024 * 1024)  //3MB defaults(original:4M)
//#define MAX_SEGMENT_SIZE (6 * 1024 * 1024)  //6MB(original:8M)

/* average: 4M */
//#define MIN_SEGMENT_SIZE (2 * 1024 * 1024)  //2MB
//#define AVG_SEGMENT_SIZE (4 * 1024 * 1024)  //4MB
//#define MAX_SEGMENT_SIZE (8 * 1024 * 1024)  //8MB

/* average: 8M */
//#define MIN_SEGMENT_SIZE (4 * 1024 * 1024)  //4MB
//#define AVG_SEGMENT_SIZE (8 * 1024 * 1024)  //8MB
//#define MAX_SEGMENT_SIZE (16 * 1024 * 1024) //16MB

/* average: 16M */
//#define MIN_SEGMENT_SIZE (8 * 1024 * 1024)    //8MB
//#define AVG_SEGMENT_SIZE (16 * 1024 * 1024)   //16MB
//#define MAX_SEGMENT_SIZE (32 * 1024 * 1024)   //32MB

#define DIVISOR ((AVG_SEGMENT_SIZE - MIN_SEGMENT_SIZE) / (8 * (2 << 10)))
#define PATTERN (((AVG_SEGMENT_SIZE - MIN_SEGMENT_SIZE) / (8 * (2 << 10))) - 1)

//#define CHUNK_DATA_SIZE (16 * 1024)
#define CHUNK_QUEUE_NUM 1024

/* 5 km server -> 5 send threads */
#define SEND_THREADS 5

/* num of keyExchange threads */
#define KEYEX_NUM_THREADS 2

#define CHARA_MIN_HASH 1007
#define CHARA_CHUNK_HASH 1008

/* KM-assisted version */
#define STATIC_KM_SERVER 2001 // server 0 as default KM server
#define DYNAMIC_KM_SERVER 2002 // all server as KM server

/* LRU cache related */
#define ENABLE_LRU_CACHE 3001 // use LRU cache for exchanging keys
#define DISABLE_LRU_CACHE 3002 // do not use LRU cache for exchanging keys
#define LRU_CACHE_SIZE 1000

#define EXIT_KM_THREAD -202

using namespace std;

class KeyEx {
private:
    // total number of servers
    int serverCount_;
    // total chunk number
    int n_;

    //index of downed-server
    int down_server_index_;

    //number of downed-server
    int down_server_num_;

    // key file object
    BIO *key_;
    // RSA object
    RSA *rsa_;
    // BN ctx
    BN_CTX *ctx_;
    // random number
    BIGNUM *r_;
    // inverse
    BIGNUM *inv_;
    // temp
    BIGNUM *mid_;
    // hash value convert to BN
    BIGNUM *h_;
    // array for record random numbers for each chunk
    BIGNUM **record_;
    // array for SSL structures
    Ssl **sock_;

    //key store ip
    char *ksip_;
    //key store port
    int ksport_;
    //type setting
    int charaType_;
    int segType_;
    int kmServerType_;
    int cacheType_;

    Encoder *encodeObj_;

    // check procedure type: upload | download
    bool uploadFlag;

    /*
     * send end indicator to KM server to exit. Used only for download procedure
     *
     * Only used in destructor in KeyEx
     *
     * */
    bool sendEndIndicator(int cloudNumber);

public:
    // thread handler structure
    typedef struct {
        int index;
        KeyEx *obj;
    } param_keyex;

    // input ring buffer
    MessageQueue<Chunk_t> **inputbuffer_;
    MessageQueue<Chunk_t> **outputbuffer_;

    /* index for sequentially adding object */
    int nextAddIndex_;

    // thread id
    pthread_t tid_;

    /* thread id array */
    pthread_t calc_tid_[KEYEX_NUM_THREADS];
    // crpyto object
    CryptoPrimitive **calc_cryptoObj_;

    // crpyto object
    CryptoPrimitive *cryptoObj_;

    /*
        function : constructor of key exchange
    */
    KeyEx(Encoder *obj, int secureType, std::unique_ptr<KMServerConf[]> kmServerConf, int userID, int charaType,
          int segType, int kmServerType, int cacheType);

    /*
        function : constructor of key exchange for force KM server thread to exit

        Yes, it is necessary!
        Do not delete this constructor unless you make changes about the whole design of this system and understand why
    */
    KeyEx(int cloudNumber, int down_server_index, int down_server_num,
          std::unique_ptr<KMServerConf[]> kmServerConf, int userID, int kmServerType);


    /*
        function : destructor of key exchange
    */
    ~KeyEx();

    /*
        function : read rsa keys from key file
        input : filename (char *)
        output : read success / failure
    */
    void readKeyFile();

    /*
     *  function : add Chunk_t into input Ring Buffer
     *  input : item (Chunk_t struct)
     **/
    void add(Chunk_t &item);

    /*
        function : procedure for print a big number in hex
        input : input(BIGNUM)
        output : display the BIGNUM
    */
    void printBN(BIGNUM *input);

    /*
        function : procedure for print a buffer content
    */
    void printBuf(unsigned char *buff, int size);

    /*
     *  function : procedure for remove blind in returned keys
     *  input :
     *      @param buff - input big number buffer<return>
     *      @param size - input big number size
     *      @param index - the index of recorded random number r
     **/
    void elimination(unsigned char *buff, int size, int index);

    /*
     *  function : procedure for blind hash value
     *  input :
     *      @param hash_buf - input buffer storing hash
     *      @param size - the size of input hash
     *      @param ret_buf - the returned buffer holding blinded hash <return>
     *      @param index - the index of record random number r
     **/
    void decoration(unsigned char *hash_buf, int size, unsigned char *ret_buf, int index);

    /*
     *  function : procedure for verify returned keys
     *  input :
     *      @param original - the original hash value buffer
     *      @param buff - the buffer contains returned blinded key
     *      @param size - the size of hash value
     *  output :
     *      verify pass -> 0, verification fails -> others
     **/
    int verify(unsigned char *original, unsigned char *buff, int size);

    /*
     * function : main procedure for init key generation with key server
     *  input :
     *      @param hash_buf - the buffer holding hash values
     *      @param num - the number of hashes
     *      @param key_buf - the returned buffer contains keys <return>
     *      @param obj - the pointer to crypto object
     *      @param cloudIndex - index of KM server
     * */
    void keyExchange(unsigned char *hash_buf, int num, unsigned char *key_buf, CryptoPrimitive *obj, int cloudIndex);

    /*
     *   function : thread handler with min_hash(Paper: REED)
     *
     *   note : do the main jobs of key manager
     **/
    static void *threadHandlerMinHash(void *param);

    /*
     *   <Deprecated>PS: DOES NOT WORK WITH CURRENT SEGMENT VERSION. Modify this if you want to use this thread
     *
     *   function : thread handler with chunk based hash
     *
     *   note : do the main jobs of key manager
     **/
    static void *threadHandlerChunk(void *param);

    /*
     *   function : determine which server is the key manager server
     **/
    int calculateKMServerIndex(unsigned char *fingerprint, int &modulus);

    /*
     *   function : thread handler for calculating hash value of data
     *
     **/
    static void *thread_handler_hash(void *param);
};

#endif
