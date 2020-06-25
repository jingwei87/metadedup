/*
 * server.cc
 */

#include "server.hh"

#include <string.h>
#include <string>
#include <sys/time.h>

#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <err.h>
#include <openssl/err.h>
#include <sysexits.h>
#include <memory>

DedupCore *metaDedupObj_;
minDedupCore *dataDedupObj_;
pthread_mutex_t mutex;

using namespace std;

/*
 * constructor: initialize host socket
 *
 * @param metaPort - meta service port number
 * @param dataPort - data service port number
 * @param dedupObj - meta dedup object passed in
 * @param minDedupObj - data dedup object passed in
 *
 */
Server::Server(int metaPort, int dataPort, int kmPort,
               DedupCore *dedupObj, minDedupCore *dataDedupObj)
{
    /* key manager part of server initialization */
    //initiate ssl functions
    init_openssl();

    ctx_ = create_context();

    configure_context(ctx_);

    //dedup. object
    metaDedupObj_ = dedupObj;
    dataDedupObj_ = dataDedupObj;
    //server port
    dataHostPort_ = dataPort;
    metaHostPort_ = metaPort;
    kmHostPort_ = kmPort;

    //server socket initialization
    dataHostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(dataHostSock_ == -1) {

        printf("Error initializing socket %d\n", errno);
    }

    metaHostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(metaHostSock_ == -1) {

        printf("Error initializing socket %d\n", errno);
    }

    kmHostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(kmHostSock_ == -1) {

        printf("Error initializing socket %d\n", errno);
    }

    //set data socket options
    int *p_int = (int *) malloc(sizeof(int));
    *p_int = 1;

    if((setsockopt(dataHostSock_, SOL_SOCKET, SO_REUSEADDR, (char *) p_int, sizeof(int)) == -1) ||
       (setsockopt(dataHostSock_, SOL_SOCKET, SO_KEEPALIVE, (char *) p_int, sizeof(int)) == -1)) {

        printf("Error setting options %d\n", errno);
        free(p_int);
    }

    //set meta socket options
    *p_int = 1;

    if((setsockopt(metaHostSock_, SOL_SOCKET, SO_REUSEADDR, (char *) p_int, sizeof(int)) == -1) ||
       (setsockopt(metaHostSock_, SOL_SOCKET, SO_KEEPALIVE, (char *) p_int, sizeof(int)) == -1)) {

        printf("Error setting options %d\n", errno);
        free(p_int);
    }

    //set key manager socket options
    *p_int = 1;

    if((setsockopt(kmHostSock_, SOL_SOCKET, SO_REUSEADDR, (char *) p_int, sizeof(int)) == -1) ||
       (setsockopt(kmHostSock_, SOL_SOCKET, SO_KEEPALIVE, (char *) p_int, sizeof(int)) == -1)) {

        printf("Error setting options %d\n", errno);
        free(p_int);
    }

//	free(p_int);
    // TODO: 2020/2/2 Debugging 
    free(p_int);

    /* Data socket */
    //initialize address struct
    dataAddr_.sin_family = AF_INET;
    dataAddr_.sin_port = htons(dataHostPort_);

    memset(&(dataAddr_.sin_zero), 0, 8);
    dataAddr_.sin_addr.s_addr = INADDR_ANY;

    //bind port
    if(bind(dataHostSock_, (sockaddr *) &dataAddr_, sizeof(dataAddr_)) == -1) {
        fprintf(stderr, "Error binding to socket %d\n", errno);
    }

    //start to listen
    if(listen(dataHostSock_, 10) == -1) {
        fprintf(stderr, "Error listening %d\n", errno);
    }

    /* Meta socket */
    metaAddr_.sin_family = AF_INET;
    metaAddr_.sin_port = htons(metaHostPort_);

    memset(&(metaAddr_.sin_zero), 0, 8);
    metaAddr_.sin_addr.s_addr = INADDR_ANY;

    //bind port
    if(bind(metaHostSock_, (sockaddr *) &metaAddr_, sizeof(metaAddr_)) == -1) {
        fprintf(stderr, "Error binding to socket %d\n", errno);
    }

    //start to listen
    if(listen(metaHostSock_, 10) == -1) {
        fprintf(stderr, "Error listening %d\n", errno);
    }

    /* Key manager socket */
    kmAddr_.sin_family = AF_INET;
    kmAddr_.sin_port = htons(kmHostPort_);

    memset(&(kmAddr_.sin_zero), 0, 8);
    kmAddr_.sin_addr.s_addr = INADDR_ANY;

    //bind port
    if(bind(kmHostSock_, (sockaddr *) &kmAddr_, sizeof(kmAddr_)) == -1) {
        fprintf(stderr, "Error binding to socket %d\n", errno);
    }

    //start to listen
    if(listen(kmHostSock_, 10) == -1) {
        fprintf(stderr, "Error listening %d\n", errno);
    }
}

void Server::timerStart(double *t)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *t = (double) tv.tv_sec + (double) tv.tv_usec * 1e-6;
}

double Server::timerSplit(const double *t)
{
    struct timeval tv;
    double cur_t;
    gettimeofday(&tv, NULL);
    cur_t = (double) tv.tv_sec + (double) tv.tv_usec * 1e-6;
    return (cur_t - *t);
}

/*
 * Meta Thread function: each thread maintains a socket from a certain client
 *
 * @param lp - input parameter structure
 *
 */
void *Server::SocketHandlerMeta(void *lp)
{
    //double timer,split,bw;

    //get socket from input param
    int *clientSock = (int *) lp;

    //variable initialization
    int bytecount;
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_LEN);
    char *metaBuffer = (char *) malloc(sizeof(char) * META_LEN);
    bool *statusList = (bool *) malloc(sizeof(bool) * BUFFER_LEN);
    memset(statusList, 0, sizeof(bool) * BUFFER_LEN);
    int metaSize;
    int user = 0;
    int dataSize = 0;
    //get user ID
    if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error recv userID %d\n", errno);
    }
    user = ntohl(*(int *) buffer);
    printf("[Meta] connection from user %d\n", user);

    memset(buffer, 0, BUFFER_LEN);
    int numOfShare = 0;
    int total_numOfShares = 0;

    //initialize hash object
    CryptoPrimitive *hashObj = new CryptoPrimitive(SHA256_TYPE);

    //main loop for recv data package
    while(true) {

        /*recv indicator first*/
        if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
            fprintf(stderr, "Error receiving data %d\n", errno);
        }

        /*if client closes, break loop*/
        if(bytecount == 0) {
            printf("[!>] [Meta] Thread: client closed!! Breaking loops...\n");
            break;
        }

        int indicator = *(int *) buffer;

        /*while metadata recv.ed, perform first stage deduplication*/
        if(indicator == META) {

            /*recv following package size*/
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving data %d\n", errno);
            }

            int packageSize = *(int *) buffer;
            int count = 0;

            /*recv following data*/
            while(count < packageSize) {
                if((bytecount = recv(*clientSock, buffer + count, packageSize - count, 0)) == -1) {
                    fprintf(stderr, "Error receiving data %d\n", errno);
                }
                count += bytecount;
            }

            memcpy(metaBuffer, buffer, count);
            metaSize = count;

            metaDedupObj_->firstStageDedup(user, (unsigned char *) metaBuffer, count, statusList, numOfShare, dataSize);
            total_numOfShares += numOfShare;

            int ind = STAT;
            memcpy(buffer, &ind, sizeof(int));

            /*return the status list*/
            int bytecount;
            if((bytecount = send(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error sending data %d\n", errno);
            }

            memcpy(buffer, &numOfShare, sizeof(int));
            if((bytecount = send(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error sending data %d\n", errno);
            }

            if((bytecount = send(*clientSock, statusList, sizeof(bool) * numOfShare, 0)) == -1) {
                fprintf(stderr, "Error sending data %d\n", errno);
            }
        }

        /*while data recv.ed, perform second stage deduplication*/
        if(indicator == DATA) {

            bool end = false;
            int meta_end_indicator = -1;
            char buffer_indicator[10];
            /* 1. recv meta end indicator */
            if((bytecount = recv(*clientSock, buffer_indicator, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving metaCore end indicator %d\n", errno);
            }
            meta_end_indicator = *(int *) buffer_indicator;
            if(meta_end_indicator == METACORE_END) {
                /* metaDedupCore meets ending */
                end = true;
                printf("[Meta] <Data> End indicator = %d\n\n", end);
            }

            /* 2. recv following package size */
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving data %d\n", errno);
            }

            int packageSize = *(int *) buffer;
            int count = 0;

            /* 3. recv following data */
            while(count < packageSize) {
                if((bytecount = recv(*clientSock, buffer + count, packageSize - count, 0)) == -1) {
                    fprintf(stderr, "Error receiving data %d\n", errno);
                }
                count += bytecount;
            }

            printf("[Meta] <Upload:Data> total shares = %d\n\n", total_numOfShares);
            metaDedupObj_->secondStageDedup(user, (unsigned char *) metaBuffer, metaSize, statusList,
                                            (unsigned char *) buffer, hashObj, end);
        }

        /*while download request recv.ed, perform restore and write file recipe*/
        if(indicator == INIT_REQUEST) {

            pthread_mutex_lock(&mutex);

            /* 1. receive the special indicator for restoring */
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving size! Error code: %d\n", errno);
            }
            int special_indicator = *(int *) buffer;
            if(special_indicator == LAST_SHARE_SERVER) {
                // Tell meta to set shareID as -1
                metaDedupObj_->set_last_share_special_flag(true);
                // Tell data to discard original share and set a placeholder
                dataDedupObj_->set_last_share_special_flag(true);
            }

            /* 2. receive encoded filename size */
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving data %d\n", errno);
            }

            int packageSize = *(int *) buffer;
            printf("[!>] [INIT_REQUEST] package size: %d\n", packageSize);
            int count = 0;

            /* 3. receive encoded filename */
            while(count < packageSize) {
                if((bytecount = recv(*clientSock, buffer + count, packageSize - count, 0)) == -1) {
                    fprintf(stderr, "Error receiving data %d\n", errno);
                }
                count += bytecount;
            }

            printf("[!>] [INIT_REQUEST] Received package size: %d\n", count);
            std::string fullFileName;
            fullFileName.assign(buffer, count);
            printf("[!>] [INIT_REQUEST] hex encoded file name: ");
            Logger::printHexValue(reinterpret_cast<const unsigned char *>(fullFileName.c_str()), fullFileName.length());
            printf("\n");

            /* 4. get plain file name size for file recipe */
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving data %d\n", errno);
            }
            int nameSize = *(int *) buffer;

            /* 5. get plain file name for file recipe */
            char nameBuffer[nameSize + 1];
            if((bytecount = recv(*clientSock, nameBuffer, nameSize, 0)) == -1) {

                fprintf(stderr, "Error receiving data %d\n", errno);
            }

            nameBuffer[nameSize] = '\0';
            int id = 0;
            while(nameBuffer[id] != '\0') {
                id++;
                if(nameBuffer[id] == '/') {
                    nameBuffer[id] = '_';
                }
            }

            printf("[!>] [INIT_REQUEST] downloaded file name from socket: %s\n", nameBuffer);
            /* create a new cipher file */
            char fileRecipeName[256];
            sprintf(fileRecipeName, "meta/RecipeFiles/%s.recipe", nameBuffer);

            metaDedupObj_->restoreShareFileAndWriteFileRecipe(user, fullFileName, fileRecipeName, 0, *clientSock,
                                                              hashObj);
            pthread_mutex_unlock(&mutex);
            break;
        }
    }
    delete hashObj;
    printf("[!>] [Meta] Thread Exiting...\n");
    printf("[!>] [Meta] Current Time: ");
    Logger::printCurrentTime();
    printf("\n");
    printf("[!>] =======================\n\n");
    free(buffer);
    free(statusList);
    free(metaBuffer);
    free(clientSock);
    return 0;
}

/*
 * Data Thread function: each thread maintains a socket from a certain client
 *
 * @param lp - input parameter structure
 *
 */
void *Server::SocketHandlerData(void *lp)
{
    //get socket from input param
    int *clientSock = (int *) lp;

    //variable initialization
    int bytecount;
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_LEN);
    char *metaBuffer = (char *) malloc(sizeof(char) * META_LEN);
    bool *statusList = (bool *) malloc(sizeof(bool) * BUFFER_LEN);
    memset(statusList, 0, sizeof(bool) * BUFFER_LEN);
    int metaSize;
    int user = 0;
    int dataSize = 0;
    //get user ID
    if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error receiving userID %d\n", errno);
    }
    user = ntohl(*(int *) buffer);
    printf("[Data] connection from user %d\n", user);

    memset(buffer, 0, BUFFER_LEN);
    int numOfShare = 0;

    //initialize hash object
    CryptoPrimitive *hashObj = new CryptoPrimitive(SHA256_TYPE);

    //main loop for recv data package
    while(true) {

        /*recv indicator first*/
        if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
            fprintf(stderr, "Error receiving indicator! Error code: %d\n", errno);
        }

        /*if client closes, break loop*/
        if(bytecount == 0) {
            printf("[!>] [Data] byteCount = %d -> Thread: client closed!! Breaking loops...\n", bytecount);
            break;
        }

        int indicator = *(int *) buffer;
        /*while metadata recv.ed, perform first stage deduplication*/
        if(indicator == META) {

            /*recv following package size*/
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving data %d\n", errno);
            }

            int packageSize = *(int *) buffer;
            int count = 0;

            /*recv following data*/
            while(count < packageSize) {
                if((bytecount = recv(*clientSock, buffer + count, packageSize - count, 0)) == -1) {
                    fprintf(stderr, "Error receiving data %d\n", errno);
                }
                count += bytecount;
            }

            memcpy(metaBuffer, buffer, count);
            metaSize = count;
            dataDedupObj_->firstStageDedup(user, (unsigned char *) metaBuffer, count, statusList, numOfShare, dataSize);

            int ind = STAT;
            memcpy(buffer, &ind, sizeof(int));

            /*return the status list*/
            int bytecount;
            if((bytecount = send(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error sending data %d\n", errno);
            }

            memcpy(buffer, &numOfShare, sizeof(int));
            if((bytecount = send(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error sending data %d\n", errno);
            }

            if((bytecount = send(*clientSock, statusList, sizeof(bool) * numOfShare, 0)) == -1) {
                fprintf(stderr, "Error sending data %d\n", errno);
            }
        }

        /*while data recv.ed, perform second stage deduplication*/
        if(indicator == DATA) {

            /*recv following package size*/

            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving data %d\n", errno);
            }

            int packageSize = *(int *) buffer;
            int count = 0;

            /*recv following data*/
            while(count < packageSize) {
                if((bytecount = recv(*clientSock, buffer + count, packageSize - count, 0)) == -1) {
                    fprintf(stderr, "Error receiving data %d\n", errno);
                }
                count += bytecount;
            }

            dataDedupObj_->secondStageDedup(user, (unsigned char *) metaBuffer, metaSize, statusList,
                                            (unsigned char *) buffer, hashObj);
        }

        /*while download request recv.ed, perform restore*/
        if(indicator == DOWNLOAD) {

            /*1. receive following package size*/
            if((bytecount = recv(*clientSock, buffer, sizeof(int), 0)) == -1) {
                fprintf(stderr, "Error receiving size! Error code: %d\n", errno);
            }

            int packageSize = *(int *) buffer;

            int count = 0;
            /*2. receive following data*/
            while(count < packageSize) {
                if((bytecount = recv(*clientSock, buffer + count, packageSize - count, 0)) == -1) {
                    fprintf(stderr, "Error receiving package data! Error code: %d\n", errno);
                }
                count += bytecount;
            }
            buffer[packageSize] = '\0';
            int id = 0;
            while(buffer[id] != '\0') {
                id++;
                if(buffer[id] == '/') {
                    buffer[id] = '_';
                }
            }
            char name[256];

            sprintf(name, "meta/RecipeFiles/%s", buffer);
            std::string fullFileName(name);

            pthread_mutex_lock(&mutex);
            dataDedupObj_->restoreShareFile(user, fullFileName, 0, *clientSock, hashObj);
            pthread_mutex_unlock(&mutex);
            break;
        }
    }

    delete hashObj;
    printf("[!>] [Data] Thread Exiting...\n");
    printf("[!>] [Data] Current Time: ");
    Logger::printCurrentTime();
    printf("\n");
    printf("[!>] =======================\n\n");
    free(buffer);
    free(statusList);
    free(metaBuffer);
    free(clientSock);
    return 0;
}


/*
 * Key Manager Thread function: each thread maintains a socket from a certain client
 *
 * @param lp - input parameter structure
 */
void *Server::SocketHandlerKeyManager(void *lp)
{
    auto *temp = (km_param *) lp;
    int *clientSock = temp->kmclientSocket;

    printf("\n[KM] KeyServer::SocketHandler ===>\n");
    //double timer,split,bw;
    //get socket from input param
    SSL *ssl = temp->obj->ssl_;
    delete temp;

    //variable initialization
    int bytecount;
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_SIZE + sizeof(int));
    char *output = (char *) malloc(sizeof(char) * BUFFER_SIZE + sizeof(int));
    /* read userID from client */
    if((bytecount = SSL_read(ssl, buffer, sizeof(int))) == -1) {

        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error SSL_read! Error code: %d\n", errno);
    }
    printf("[!>] [SSL:Receive UserID] bytecount: %d\n", bytecount);
    int user = ntohl(*(int *) buffer);
    printf("connection from user %d\n", user);
    // RSA structure
    RSA *rsa = RSA_new();
    BIO *key = BIO_new_file("./keys/private.pem", "r");
    PEM_read_bio_RSAPrivateKey(key, &rsa, NULL, NULL);
    // Big number init
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *ret = BN_new();
    // read the server private key
    while(true) {

        // recv the number count of data
        if((bytecount = SSL_read(ssl, buffer, sizeof(int))) == -1) {

            ERR_print_errors_fp(stderr);
            fprintf(stderr, "[SSL_read] No count of data received!\n");
        }
        /*if client closes, break loop*/
        if(bytecount == 0) {
            printf("[!>] [KM] Thread: client closed!! Breaking loops...\n");
            break;
        }

        if(!checkSSLERRStatus(ssl, bytecount)) {
            printf("[!>] [SSL Error] Abort operation! Resetting...\n");
            break;
        }
        // prepare to recv data itself
        int num, total;
        memcpy(&num, buffer, sizeof(int));

        /* Exit thread when client downloading files. `-202` is set in client::KeyEx::sendEndIndicator */
        if(num == -202) {
            printf("[!>] [KM] client download -> Thread: client closed!! Breaking loops...\n");
            break;
        }

        total = 0;
        // recv data (blinded hash, 1024bits values)
        while(total < num * RSA_LENGTH) {

            if((bytecount = SSL_read(ssl, buffer + sizeof(int) + total, num * RSA_LENGTH - total)) == -1) {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Error SSL_read data(blinded hash, 1024bits values)! Error code: %d\n", errno);
                exit(-1);
            }
            total += bytecount;
        }

        // main loop for computing keys
        double timer, split;
        timerStart(&timer);
        for(int i = 0; i < num; i++) {

            // hash x r^e to BN
            BN_bin2bn((unsigned char *) (buffer + sizeof(int) + i * RSA_LENGTH), RSA_LENGTH, ret);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            const BIGNUM *n;
            const BIGNUM *d;
            RSA_get0_key(rsa, &n, nullptr, &d);
            // compute (Hash x r^e)^d mod n
            BN_mod_exp(ret, ret, d, n, ctx);
#else
            // compute (Hash x r^e)^d mod n
            BN_mod_exp(ret, ret, rsa->d, rsa->n, ctx);
#endif
            memset(output + sizeof(int) + i * RSA_LENGTH, 0, RSA_LENGTH);
            BN_bn2bin(ret, (unsigned char *) output + sizeof(int) + i * RSA_LENGTH + (RSA_LENGTH - BN_num_bytes(ret)));
            //BN_bn2bin(ret,(unsigned char*)output+sizeof(int)+i*32);
        }
        split = timerSplit(&timer);
        // send back the result
        total = 0;
        while(total < num * RSA_LENGTH) {

            if((bytecount = SSL_write(ssl, output + sizeof(int) + total, num * RSA_LENGTH - total)) <= 0) {

                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Error SSL_write result back to client! Error code: %d\n", errno);
                exit(-1);
            }
            total += bytecount;
        }
    }
    BN_CTX_free(ctx);
    BN_clear_free(ret);
    printf("[!>] [KM] Thread Exiting...\n");
    printf("[!>] [KM] Current Time: ");
    Logger::printCurrentTime();
    printf("\n");
    printf("[!>] =======================\n\n");
    //clean up
    BIO_free_all(key);
    RSA_free(rsa);
    SSL_free(ssl);
    free(buffer);
    free(output);
    free(clientSock);
    return 0;
}

/*
 * start linsten sockets and bind correct thread for coming connection
 *
 */
void Server::runReceive()
{

    addrSize_ = sizeof(sockaddr_in);
    pthread_mutex_init(&mutex, NULL);
    //create a thread whenever a client connects
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while(true) {

        printf("[!>] Server::runReceive ===>\n");
        printf("[!>] runReceive: waiting for a connection\n");
        dataclientSock_ = (int *) malloc(sizeof(int));
        metaclientSock_ = (int *) malloc(sizeof(int));
        kmclientSock_ = (int *) malloc(sizeof(int));

        /* Data Client Socket  */
        if((*dataclientSock_ = accept(dataHostSock_, (sockaddr *) &sadr_, &addrSize_)) != -1) {

            printf("\n[!>] [Data] <Server::runReceive> Received data connection===>\n");
            printf("\n[!>] [Data] Received data connection from %s\n", inet_ntoa(sadr_.sin_addr));
            pthread_create(&threadId_, 0, &SocketHandlerData, (void *) dataclientSock_);

            pthread_detach(threadId_);

        } else {

            fprintf(stderr, "[Data] Error accepting %d\n", errno);
        }

        /* Meta Client Socket  */
        if((*metaclientSock_ = accept(metaHostSock_, (sockaddr *) &sadr_, &addrSize_)) != -1) {

            printf("\n[!>] [Meta] <Server::runReceive> Received meta connection===>\n");
            printf("\n[!>] [Meta] Received meta connection from %s\n", inet_ntoa(sadr_.sin_addr));
            pthread_create(&threadId_, 0, &SocketHandlerMeta, (void *) metaclientSock_);

            pthread_detach(threadId_);

        } else {

            fprintf(stderr, "[Meta] Error accepting %d\n", errno);
        }

        /* Key Manager Client Socket  */
        if((*kmclientSock_ = accept(kmHostSock_, (sockaddr *) &sadr_, &addrSize_)) != -1) {

            printf("\n[!>] [KM] <Server::runReceive> Received km connection===>\n");
            printf("\n[!>] [KM] Received km connection from %s\n", inet_ntoa(sadr_.sin_addr));

            // SSL verify
            ssl_ = SSL_new(ctx_);
            SSL_set_fd(ssl_, *kmclientSock_);
            if(SSL_accept(ssl_) <= 0) {
                ERR_print_errors_fp(stderr);
            }
            auto *temp = new km_param;
            temp->obj = this;
            temp->kmclientSocket = kmclientSock_;
            pthread_create(&threadId_, 0, &SocketHandlerKeyManager, (void *) temp);

            pthread_detach(threadId_);

        } else {

            fprintf(stderr, "[KM] Error accepting %d\n", errno);
        }
    }

#pragma clang diagnostic pop
    pthread_mutex_destroy(&mutex);
}

/*
 *  Destructor of Server
 * */
Server::~Server()
{

    SSL_free(ssl_);
    SSL_CTX_free(ctx_);
    cleanup_openssl();
}

void Server::init_openssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void Server::cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *Server::create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
//	method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if(!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void Server::configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if(SSL_CTX_use_certificate_file(ctx, "./keys/mycert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "./keys/mycert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

bool Server::checkSSLERRStatus(SSL *ssl, int byteCount)
{
    int sslError = SSL_get_error(ssl, byteCount);
    switch(sslError) {
        case SSL_ERROR_WANT_READ:
            /* Wait for data to be sslErrorad */
            printf("Error: SSL_ERROR_WANT_READ\n");
            return false;
            break;
        case SSL_ERROR_WANT_WRITE:
            /* Write data to continue */
            printf("Error: SSL_ERROR_WANT_WRITE\n");
            return false;
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            /* The TLS/SSL I/O function should be called again later */
            printf("Error: SSL_ERROR_WANT_X509_LOOKUP\n");
            return false;
            break;
        case SSL_ERROR_SYSCALL:
            /* Hard error */
            printf("Info | Error: client has disconnected!!\n");
            return false;
            break;
        case SSL_ERROR_SSL:
            printf("Error: SSL_ERROR_SSL\n");
            return false;
            break;
        case SSL_ERROR_ZERO_RETURN:
            /* Same as error */
            printf("Error: SSL_ERROR_ZERO_RETURN\n");
            return false;
            break;
        default:
            return true;
    }
}

/*
 * rebuild file recipe by downloaded metadata chunk & keyRecipe
 *
 * @param input - metadata chunk object
 * @param index - cloud id that metadata chunk download
 *
 */
int Server::writeRetrievedFileRecipe(ItemMeta_t &input, int index)
{

    char nameBuffer[256];
    memset(nameBuffer, 0, 256);
    sprintf(nameBuffer, "share-%d.recipe", index);
    string writeName(nameBuffer);

    /* -n = ~n + 1 */
    int metaChunkID = ~input.shareObj.share_header.secretID + 1;

    memset(nameBuffer, 0, 256);

    FILE *fp = fopen(writeName.c_str(), "ab+");
    if(fp == NULL) {
        printf("can't open recipe file %s\n", writeName.c_str());
        return 0;
    } else {
        fseek(fp, 0, SEEK_END);
        int nodeNumber = input.shareObj.share_header.shareSize / sizeof(metaNode);
        unique_ptr<int[]> fileSizeCounter(new int[5]);
        for(int i = 0; i < nodeNumber; i++) {

            metaNode newNode;
            memcpy(&newNode, input.shareObj.data + i * sizeof(metaNode), sizeof(metaNode));
            fileRecipeEntry_t writeEntryNode;
            memcpy(writeEntryNode.shareFP, newNode.shareFP, FP_SIZE);
            writeEntryNode.secretID = newNode.secretID;
            writeEntryNode.secretSize = newNode.secretSize;
            writeEntryNode.segID = newNode.segID;
            fileSizeCounter[index] += newNode.secretSize;
            fwrite(&writeEntryNode, sizeof(fileRecipeEntry_t), 1, fp);
        }
        fclose(fp);

        return 1;
    }
    return 1;
}
