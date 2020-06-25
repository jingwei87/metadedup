/*
 * socket.hh
 */

#ifndef __SOCKET_HH__
#define __SOCKET_HH__

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

/* action indicators */
#define SEND_META (-1)
#define SEND_DATA (-2)
#define SEND_FILE_META (-8)
#define GET_STAT (-3)
#define INIT_DOWNLOAD (-7)
#define INIT_META_REQUEST (-9)
#define NO_DATA_CHUNKS_FOUND (-6)
#define END_OF_DATA_CHUNKS (-51)
#define LAST_SHARE_SERVER (-909)
#define NOT_LAST_SHARE_SERVER (909)
/* the indicator of sending meta_list back to client */
#define METACORE_NOT_END (-707)
#define METACORE_END (707)

class Socket {
private:
public:
    /* port number */
    int hostPort_;

    /* ip address */
    char *hostName_;

    /* address structure */
    struct sockaddr_in myAddr_;

    /* host socket */
    int hostSock_;

    /*
     * constructor: initialize sock structure and connect
     *
     * @param ip - server ip address
     * @param port - port number
     */
    Socket(char *ip, int port, int userID);

    /*
     * @ destructor
     */
    ~Socket();

    /*
     * basic send function
     * 
     * @param raw - raw data buffer_
     * @param rawSize - size of raw data
     */
    int genericSend(char *raw, int rawSize);

    /*
     * file meta-data send function
     *
     * @param raw - raw data buffer_
     * @param rawSize - size of raw data
     *
     */
    int sendFileMeta(char *raw, int rawSize);

    /*
     * metadata send function
     *
     * @param raw - raw data buffer_
     * @param rawSize - size of raw data
     *
     */
    int sendMeta(char *raw, int rawSize);

    /*
     * data send function
     *
     * @param raw - raw data buffer_
     * @param rawSize - size of raw data
     *
     */
    int sendData(char *raw, int rawSize, bool metaType, bool end);

    /*
     * status recv function
     *
     * @param statusList - return int list
     * @param num - num of returned indicator
     *
     * @return statusList
     */
    int getStatus(bool *statusList, int *num);

    /*
     * initiate downloading a file
     *
     * @param filename - the full name of the targeting file
     * @param nameSize - the size of the file path
     *
     *
     */
    int initDownload(char *filename, int namesize);

    /*
     * initiate downloading a file and send file name with length
     *
     * @param filename - the full name of the targeting file
     * @param nameSize - the size of the file path
     *
     *
     */
    int initDownloadWithFileMeta(char *filename, int namesize, const char *plainFilename, int plainFilenameLength,
                                 bool special_indicator);

    /*
     * download a chunk of data
     *
     * @param raw - the returned raw data chunk <return>
     * @param retSize - the size of returned data chunk <return>
     * @param end - indicate the end of loop
     */
    int downloadChunk(char *raw, int *retSize, int &end);

    /*
     * data download function
     *
     * @param raw - raw data buffer <return>
     * @param rawSize - the size of data to be downloaded
     */
    int genericDownload(char *raw, int rawSize);
};

#endif
