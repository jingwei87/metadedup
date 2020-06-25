#include "ssl.hh"

using namespace std;

/*
 * constructor: initialize sock structure and connect
 *
 * @param ip - server ip address
 * @param port - port number
 */
Ssl::Ssl(char *ip, int port, int userID)
{

    /* get port and ip */
    hostPort_ = port;
    hostName_ = ip;
    int err;

    SSL_library_init();
    ctx_ = InitCTX();

    /* initializing socket object */
    hostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(hostSock_ == -1) {
        printf("Error initializing socket %d\n", errno);
    }
    int *p_int = (int *) malloc(sizeof(int));
    *p_int = 1;

    /* set socket options */
    if(
            (setsockopt(hostSock_,
                        SOL_SOCKET,
                        SO_REUSEADDR,
                        (char *) p_int,
                        sizeof(int)) == -1) ||
            (setsockopt(hostSock_,
                        SOL_SOCKET,
                        SO_KEEPALIVE,
                        (char *) p_int,
                        sizeof(int)) == -1)
            ) {
        printf("Error setting options %d\n", errno);
        free(p_int);
        return;
    }
    free(p_int);

    /* set socket address */
    myAddr_.sin_family = AF_INET;
    myAddr_.sin_port = htons(port);
    memset(&(myAddr_.sin_zero), 0, 8);
    myAddr_.sin_addr.s_addr = inet_addr(ip);

    /* trying to connect socket */
    if(connect(hostSock_, (struct sockaddr *) &myAddr_, sizeof(myAddr_)) == -1) {
        if((err = errno) != EINPROGRESS) {
            fprintf(stderr, "Error connecting socket %d\n", errno);
        }
    }

    ssl_ = SSL_new(ctx_);
    SSL_set_fd(ssl_, hostSock_);

    if(SSL_connect(ssl_) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("[!>] SSL_connect Error! \n");
        exit(-3);
    }
    // ShowCerts(ssl_);
    /* prepare user ID and send it to server */
    int netorder = htonl(userID);
    int bytecount;
    if((bytecount = SSL_write(ssl_, &netorder, sizeof(int))) == -1) {
        fprintf(stderr, "Error sending userID %d\n", errno);
    }
    printf("[!>] Sent userID successfully! \n");
}

/*
 * @ destructor
 */
Ssl::~Ssl()
{
    SSL_free(ssl_);
    SSL_CTX_free(ctx_);
    close(hostSock_);
}

void Ssl::closeConn()
{
    int last = -7;
    genericSend((char *) &last, sizeof(int));
}

/*
 * basic send function
 * 
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 */
int Ssl::genericSend(char *raw, int rawSize)
{

    int bytecount;
    int total = 0;
    while(total < rawSize) {
        if((bytecount = SSL_write(ssl_, raw + total, rawSize - total)) == -1) {

            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Error sending data %d\n", errno);
            return -1;
        }
        total += bytecount;
    }
    return total;
}

/*
 *
 * @param raw - raw data buffer
 * @param rawSize - the size of data to be downloaded
 * @return raw
 */
int Ssl::genericDownload(char *raw, int rawSize)
{

    int bytecount;
    int total = 0;
    while(total < rawSize) {
        if((bytecount = SSL_read(ssl_, raw + total, rawSize - total)) == -1) {
            fprintf(stderr, "Error receiving data %d\n", errno);
            return -1;
        }
        total += bytecount;
    }
    return 0;
}

/*
 * initiate downloading a file
 *
 * @param filename - the full name of the targeting file
 * @param namesize - the size of the file path
 *
 *
 */
int Ssl::initDownload(char *filename, int namesize)
{

    int indicator = INIT_DOWNLOAD;

    memcpy(buffer_, &indicator, sizeof(int));
    memcpy(buffer_ + sizeof(int), &namesize, sizeof(int));
    memcpy(buffer_ + 2 * sizeof(int), filename, namesize);
    genericSend(buffer_, sizeof(int) * 2 + namesize);

    return 0;
}

/*
 * download a chunk of data
 *
 * @param raw - the returned raw data chunk
 * @param retSize - the size of returned data chunk
 * @return raw 
 * @return retSize
 */
int Ssl::downloadChunk(char *raw, int *retSize)
{

    int bytecount;

    char *buffer = (char *) malloc(sizeof(char) * SOCKET_BUFFER_SIZE);
    if((bytecount = SSL_read(ssl_, buffer, sizeof(int))) == -1) {

        fprintf(stderr, "Error receiving data %d\n", errno);
    }
    if((bytecount = SSL_read(ssl_, buffer, sizeof(int))) == -1) {

        fprintf(stderr, "Error receiving data %d\n", errno);
        return -1;
    }
    *retSize = *(int *) buffer;

    genericDownload(raw, *retSize);
    return 0;
}

SSL_CTX *Ssl::InitCTX()
{
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    auto method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);   /* Create new context */
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void Ssl::ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if(cert != NULL) {
        printf("Server Info: %s:%d\n", hostName_, hostPort_);
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else
        printf("Info: No client certificates configured.\n");
}
