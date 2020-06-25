#include "socket.hh"

/*
 * constructor: initialize sock structure and connect
 *
 * @param ip - server ip address
 * @param port - port number
 */
Socket::Socket(char *ip, int port, int userID)
{

    /* get port and ip */
    hostPort_ = port;
    hostName_ = ip;
    int err;

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
                        sizeof(int))
             == -1)
            || (setsockopt(hostSock_,
                           SOL_SOCKET,
                           SO_KEEPALIVE,
                           (char *) p_int,
                           sizeof(int))
                == -1)) {
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
            printf("[!>] Error here!!!\n");
            fprintf(stderr, "Error connecting socket %d\n", errno);
        }
    }

    /* prepare user ID and send it to server */
    int netorder = htonl(userID);
    int bytecount;
    if((bytecount = send(hostSock_, &netorder, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending userID %d\n", errno);
    }
}

/*
 * @ destructor
 */
Socket::~Socket()
{
    close(hostSock_);
}

/*
 * basic send function
 * 
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 */
int Socket::genericSend(char *raw, int rawSize)
{

    int bytecount;
    int total = 0;
    while(total < rawSize) {
        if((bytecount = send(hostSock_, raw + total, rawSize - total, 0)) == -1) {
            fprintf(stderr, "Error sending data %d\n", errno);
            return -1;
        }
        total += bytecount;
    }
    return total;
}

/*
 * file meta-data send function
 *
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 *
 */
int Socket::sendFileMeta(char *filename, int namesize)
{
    /* SEND_FILE_META<client> = FILE_META<server> */
    int indicator = SEND_FILE_META;

    int bytecount;
    if((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending indicator! Error code: %d\n", errno);
        return -1;
    }

    if((bytecount = send(hostSock_, &namesize, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending nameSize! Error code: %d\n", errno);
        return -1;
    }

    if((bytecount = send(hostSock_, filename, namesize, 0)) == -1) {
        fprintf(stderr, "Error sending file name! Error code: %d\n", errno);
        return -1;
    }

    return 0;
}

/*
 * metadata send function
 *
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 *
 */
int Socket::sendMeta(char *raw, int rawSize)
{
    int indicator = SEND_META;

    int bytecount;
    if((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    if((bytecount = send(hostSock_, &rawSize, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    genericSend(raw, rawSize);
    return 0;
}

/*
 * data send function
 *
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 *
 */
int Socket::sendData(char *raw, int rawSize, bool metaType, bool end)
{

    int meta_indicator = METACORE_NOT_END;
    if(end) {
        meta_indicator = METACORE_END;
    }

    int indicator = SEND_DATA;
    int bytecount;

    if((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    if(metaType) {
        // send end indicator to metaCore since metaDedupCore receive different size
        if((bytecount = send(hostSock_, &meta_indicator, sizeof(int), 0)) == -1) {
            fprintf(stderr, "Error sending meta_indicator %d\n", errno);
            return -1;
        }
    }

    if((bytecount = send(hostSock_, &rawSize, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    genericSend(raw, rawSize);
    return 0;
}

/*
 * data download function
 *
 * @param raw - raw data buffer <return>
 * @param rawSize - the size of data to be downloaded
 */
int Socket::genericDownload(char *raw, int rawSize)
{

    int bytecount;
    int total = 0;
    while(total < rawSize) {
        if((bytecount = recv(hostSock_, raw + total, rawSize - total, 0)) == -1) {
            fprintf(stderr, "Error receiving data %d\n", errno);
            return -1;
        }
        total += bytecount;
    }
    return total;
}

/*
 * status recv function
 *
 * @param statusList - return int list
 * @param num - num of returned indicator
 *
 * @return statusList
 */
int Socket::getStatus(bool *statusList, int *num)
{

    int bytecount;
    int indicator = 0;

    if((bytecount = recv(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }
    if(indicator != GET_STAT) {
        fprintf(stderr, "Status wrong %d\n", errno);
        return -1;
    }
    if((bytecount = recv(hostSock_, num, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    genericDownload((char *) statusList, sizeof(bool) * (*num));
    return 0;
}

/*
 * initiate downloading a file
 *
 * @param filename - the full name of the targeting file
 * @param namesize - the size of the file path
 *
 */
int Socket::initDownload(char *filename, int namesize)
{
    /* INIT_DOWNLOAD<client> = DOWNLOAD<server> */
    int indicator = INIT_DOWNLOAD;

    int bytecount;
    if((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending indicator! Error code: %d\n", errno);
        return -1;
    }

    if((bytecount = send(hostSock_, &namesize, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending nameSize! Error code: %d\n", errno);
        return -1;
    }

    if((bytecount = send(hostSock_, filename, namesize, 0)) == -1) {
        fprintf(stderr, "Error sending file name! Error code: %d\n", errno);
        return -1;
    }


    return 0;
}

/*
 * initiate downloading a file and send original filename and filename length
 *  for server-side generated file recipe use
 *
 * @param filename - the full name of the targeting file
 * @param namesize - the size of the file path
 * @param plainFileName - the plain text of file name
 * @param plainFileNameLength - the length of plain text of file name
 * @param special_indicator - indicator for special server which has the 4-th shares and it is enough(no need to
 *                            send back to client)
 *
 *
 */
int Socket::initDownloadWithFileMeta(char *filename, int namesize, const char *plainFilename, int plainFilenameLength,
                                     bool special_indicator)
{
    int indicator = INIT_META_REQUEST;

    int bytecount;
    if((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    if(special_indicator) {
        int last_share_server_indicator = LAST_SHARE_SERVER;
        if((bytecount = send(hostSock_, &last_share_server_indicator, sizeof(int), 0)) == -1) {
            fprintf(stderr, "Error sending special indicator! Error code: %d\n", errno);
            return -1;
        }
    } else {
        int not_special_indicator = NOT_LAST_SHARE_SERVER;
        if((bytecount = send(hostSock_, &not_special_indicator, sizeof(int), 0)) == -1) {
            fprintf(stderr, "Error sending special indicator! Error code: %d\n", errno);
            return -1;
        }
    }

    if((bytecount = send(hostSock_, &namesize, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    if((bytecount = send(hostSock_, filename, namesize, 0)) == -1) {
        fprintf(stderr, "Error sending data %d\n", errno);
        return -1;
    }

    /* send length of plain file name to be downloaded */
    genericSend((char *) &plainFilenameLength, sizeof(int));

    /* send plain file name to be downloaded */
    genericSend(const_cast<char *>(plainFilename), plainFilenameLength);

    return 0;
}


/*
 * download a chunk of data
 *
 * @param raw - the returned raw data chunk <return>
 * @param retSize - the size of returned data chunk <return>
 * @param end - indicate the end of loop
 */
int Socket::downloadChunk(char *raw, int *retSize, int &end)
{
    int indicator;

    /* receive indicator: -5(dafult value) */
    int bytecount;
    if((bytecount = recv(hostSock_, &indicator, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error receiving indicator! Error code: %d\n", errno);
        return -1;
    }

    /* `NO_DATA_CHUNKS_FOUND` means empty data chunks and exit */
    if(ntohl(indicator) == NO_DATA_CHUNKS_FOUND) {
        *retSize = 0;
        printf("[Socket] [downloadChunk] Indicator = -6! Empty data chunks. Exiting...\n");
        return -2;
    }

    /* `END_OF_DATA_CHUNKS` means less chunks received than expected but this is normal and retSize is not 0*/
    if(ntohl(indicator) == END_OF_DATA_CHUNKS) {
        end = 1;
    }

    /* indicator = `-7` also use codes below */
    /* receive data size */
    int size;
    if((bytecount = recv(hostSock_, &size, sizeof(int), 0)) == -1) {
        fprintf(stderr, "Error receiving size! Error code: %d\n", errno);
        return -1;
    }
    *retSize = ntohl(size);

    /* download data according to data size */
    genericDownload(raw, *retSize);

    return 0;
}
