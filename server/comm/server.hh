/*
 * server.hh
 */

#ifndef __SERVER_HH__
#define __SERVER_HH__

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "BackendStorer.hh"
#include "DedupCore.hh"
#include "minDedupCore.hh"
#include "Logger.hh"


#define BUFFER_LEN (4 * 1024 * 1024)
#define META_LEN (2 * 1024 * 1024)
#define META (-1)
#define DATA (-2)
#define STAT (-3)
#define DOWNLOAD (-7)
#define UPLOAD_FILE_META (-8)
#define INIT_REQUEST (-9)

#define KEYFILE (-108)
#define KEY_RECIPE (-101)
#define GET_KEY_RECIPE (-102)
#define FILE_RECIPE (-103)

/* key manager starts here */
// client cerificate
#define SSL_CA_CRT "./keys/ca/ca.crt"
// server certificate
#define SSL_SERVER_CRT "./keys/server.crt"
// server key
#define SSL_SERVER_KEY "./keys/private/server.key"
// rsa size 1024 bits
#define RSA_LENGTH 128
// buffer size
#define BUFFER_SIZE (32*1024*1024)
#define HASH_SIZE 32

using namespace std;

class Server {
private:
    //port number
    int dataHostPort_;
    int metaHostPort_;
    int kmHostPort_;

    //server address struct
    struct sockaddr_in dataAddr_;
    struct sockaddr_in metaAddr_;
    struct sockaddr_in kmAddr_;
    //receiving socket
    int dataHostSock_;

    //receiving socket
    int metaHostSock_;

    //receiving socket
    int kmHostSock_;

    //socket size
    socklen_t addrSize_;

    //client socket
    int *dataclientSock_;
    int *metaclientSock_;
    int *kmclientSock_;
    //socket address
    struct sockaddr_in sadr_;

    //thread ID
    pthread_t threadId_;

    // SSL context
    SSL_CTX *ctx_;

    typedef struct {
        Server *obj;
        int *kmclientSocket;
    }km_param;

    static void timerStart(double *t);

    static double timerSplit(const double *t);

    static void *SocketHandlerMeta(void *lp);

    static void *SocketHandlerData(void *lp);

    static void *SocketHandlerKeyManager(void *lp);

    void init_openssl();

    void cleanup_openssl();

    SSL_CTX *create_context();

    void configure_context(SSL_CTX *ctx);

    static bool checkSSLERRStatus(SSL *ssl, int byteCount);

public:
    // SSL connection structure
    SSL *ssl_;

    /*the entry structure of the recipes of a file*/
    typedef struct {
        char shareFP[FP_SIZE];
        int secretID;
        int secretSize;
        int segID;
    } fileRecipeEntry_t;

    /*the head structure of the recipes of a file*/
    typedef struct {
        int userID;
        long fileSize;
        int numOfShares;
    } fileRecipeHead_t;

    typedef struct {
        unsigned char shareFP[HASH_SIZE];
        unsigned char other[18];
        int secretID;
        int secretSize;
        int shareSize;
        int segID;
    } metaNode;

    /*
     * constructor: initialize host socket
     *
     * @param metaPort - meta service port number
     * @param dataPort - data service port number
     * @param kmPort - key manager service port number
     * @param dedupObj - meta dedup object passed in
     * @param minDedupObj - data dedup object passed in
     *
     **/
    Server(int metaPort, int dataPort, int kmPort, DedupCore *dedupObj, minDedupCore *dataDedupObj);

    /*
     * start listen sockets and bind correct thread for coming connection
     *
     **/
    void runReceive();

    ~Server();

    int writeRetrievedFileRecipe(ItemMeta_t &input, int index);

};

#endif
