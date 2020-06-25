/*
 * downloader.cc
 */

#include "downloader.hh"

using namespace std;

int Downloader::server_mutex_num;
std::mutex Downloader::count_mutex;
std::condition_variable Downloader::cv_mutex;

/*
 * downloader thread handler
 * 
 * @param param - input param structure
 *
 */
void *Downloader::thread_handler(void *param)
{

    /* parse parameters*/
    param_t *temp_param = (param_t *) param;
    int cloudIndex = temp_param->cloudIndex;
    int numOfCloud = temp_param->numOfCloud;
    Downloader *obj = temp_param->obj;
    free(temp_param);

    /* get the download initiate signal */
    init_t signal;
    while(obj->signalBuffer_[cloudIndex]->is_empty());
    obj->signalBuffer_[cloudIndex]->pop(signal);

    /* get filename & name size*/
    char *filename = signal.filename;
    int nameSize = signal.nameSize;
    int retSize;
    int index = 0;
    int end = 0;

    // set bool value for sending special indicator to server to not sending the 4-th shares of data chunks
    obj->socketArray_[cloudIndex]->initDownload(filename, nameSize);
    printf("[Data] [download] <%d> Start to download Chunk\n", cloudIndex);
    /* start to download data into container */
    obj->socketArray_[cloudIndex]->downloadChunk(obj->downloadContainer_[cloudIndex], &retSize, end);
    printf("[Data] [download] <%d> retSize = %d\n", cloudIndex, retSize);

    Item_t headerObj;
    /* if no data chunk found in server, exiting... */
    if(retSize == 0) {
        printf("[Data] [download] <%d> No data chunks found. Exiting thread...\n", cloudIndex);
        /* fake header data to tell Downloader::downloadFile to exit normally */
        headerObj.type = -1;
        /* add fake header object into ringbuffer */
        obj->ringBuffer_[cloudIndex - DOWNLOAD_SERVER_NUMBER]->push(headerObj);

        return nullptr;
    }

    /* get the header */
    auto *header = (shareFileHead_t *) obj->downloadContainer_[cloudIndex];

    /* parse the header object */
    headerObj.type = 0;
    memcpy(&(headerObj.fileObj.file_header), header, sizeof(shareFileHead_t));
    index = sizeof(shareFileHead_t);

    /* add the header object into ringbuffer */
    obj->ringBuffer_[cloudIndex - DOWNLOAD_SERVER_NUMBER]->push(headerObj);
    /* main loop to get data */
    int count = 0;
    int numOfChunk = header->numOfShares;
    if(retSize - sizeof(shareFileHead_t) == 0) {
        printf("[Data] [download] <%d> no need to download this chunk from this server. Exiting thread...\n",
               cloudIndex);
        pthread_exit(0);
    }

    printf("[Data] [download] <%d> numOfChunk = %d in this server\n", cloudIndex, numOfChunk);

    double download_chunk_time = 0;

    while(true) {

        /* if the current container has been proceed, download next container */
        if(index == retSize) {
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
            obj->socketArray_[cloudIndex]->downloadChunk(obj->downloadContainer_[cloudIndex], &retSize, end);
#ifdef BREAKDOWN_ENABLED
            }, download_chunk_time);
#endif
            index = 0;
            if(retSize == 0) {
                printf("\n[Downloader] [Data-Thread] <%d> no more data from container!!\n\n", cloudIndex);
                break;
            }
        }

        /* get the share object */
        auto *temp = (shareEntry_t *) (obj->downloadContainer_[cloudIndex] + index);
        int shareSize = temp->shareSize;

        index += sizeof(shareEntry_t);

        /* parse the share object */
        Item_t output;
        output.type = 1;
        memcpy(&(output.shareObj.share_header), temp, sizeof(shareEntry_t));
        memcpy(output.shareObj.data, obj->downloadContainer_[cloudIndex] + index, shareSize);

        index += shareSize;

        /* add the share object to ringbuffer */
        obj->ringBuffer_[cloudIndex - DOWNLOAD_SERVER_NUMBER]->push(output);
        count++;
        if(end == 1 && index == retSize) {
            printf("\n[Downloader] [Data-Thread] <%d> All container data processed!!(%d chunks downloaded)\n\n",
                   cloudIndex, count);
            break;
        }
        if(count == numOfChunk) {
            printf("\n[Downloader] [Data-Thread] <%d> Finish downloading all numOfChunk(%d)\n\n", cloudIndex,
                   numOfChunk);
            break;
        }
    }

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Downloader] <data:%d> chunk_download time: is /%lf/ s\n", cloudIndex, download_chunk_time);
    printf("[Time]===================\n\n");
#endif
    pthread_exit(0);
}

/*
 * downloader thread handler for downloading file recipes
 * 
 * @param param - input param structure
 *
 */
void *Downloader::thread_handler_meta(void *param)
{

    /* parse parameters*/
    auto *temp = (param_t *) param;
    int cloudIndex = temp->cloudIndex;
    Downloader *obj = temp->obj;
    int numOfCloud = temp->numOfCloud;
    string plainFileName = temp->fileName;
    int plainFileNameLength = temp->fileNameLength;
    free(temp);

    double meta_handling_download_time = 0;

    /* get the download initiate signal */
    init_t signal;
    // wait for data coming
    while(obj->signalBuffer_[cloudIndex]->is_empty());
    obj->signalBuffer_[cloudIndex]->pop(signal);

    /* get filename & name size*/
    char *filename = signal.filename;
    int namesize = signal.nameSize;

    char buffer[256]{};

    /*
     * when `down_server_index_ = 2`, and `kmServerID = 2`,
     * in this case, `server[1]` should discard shares when `shareID = 3`
     *
     * But server itself do not know its own server index, so client has to send special indicator to tell server
     * to discard shares when `shareID = 3`
     *
     * Q: Why are we doing this?
     * A: 1. You may draw a table. You may find out only the server who decides to discard shareID is the one where
     *       the last shares of data chunks stores.
     *    2. This method could accelerate downloading speed and discard the 4-th shares for restoring in current scheme
     * */
    int last_share_server_ID =
            (obj->down_server_index_ - obj->down_server_num_ + DOWNLOAD_SERVER_NUMBER) % DOWNLOAD_SERVER_NUMBER;

    /* initiate download request */
    obj->socketArray_[cloudIndex]->initDownloadWithFileMeta(filename, namesize,
                                                            plainFileName.c_str(), plainFileNameLength,
                                                            last_share_server_ID == cloudIndex);

#ifdef BREAKDOWN_ENABLED
    Logger::measure_time([&]() {
#endif
    obj->download_meta_list(obj->meta_list_buffer_[cloudIndex].get(), obj->socketArray_[cloudIndex],
                            obj->count_MetaList_item_[cloudIndex], cloudIndex);


    int indicator = 0;
    obj->socketArray_[cloudIndex]->genericDownload(buffer, sizeof(int));
    memcpy(&indicator, buffer, sizeof(int));
    if(indicator == END_DOWNLOAD_INDICATOR) {
        printf("[Download] <%d> indicator = %d! No meta data found!\n", cloudIndex, indicator);
        printf("[Download] \tFile may not exist in this server!\n");
    }
    if(indicator != FILE_RECIPE_SUCCESS && indicator != END_DOWNLOAD_INDICATOR) {
        printf("[Download] File recipe indicator error!! indicator = %d\n", indicator);
        exit(-1);
    }

    /* notify Downloader::downloadFile to proceed,
     * which is used for preventing server blocked by minDedupCore and DedupCore at the same time*/
    std::lock_guard<std::mutex> lock(count_mutex);
    --server_mutex_num;
    printf("[Download] <%d> server_mutex_num = %d\n", cloudIndex, server_mutex_num);
    if(server_mutex_num == 0) {
        cv_mutex.notify_one();
    }
    printf("[Download] <%d> Server finished generating file recipes\n", cloudIndex);
#ifdef BREAKDOWN_ENABLED
    }, meta_handling_download_time);
#endif

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Downloader] <meta:%d> metadata_handling time: is /%lf/ s\n", cloudIndex, meta_handling_download_time);
    printf("[Time]===================\n\n");
#endif

    pthread_exit(0);
}

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
Downloader::Downloader(int total, int subset, int down_server_index, int down_server_num, int userID, Decoder *obj,
                       char *fileName, int nameSize)
{
    /* set private variables */
    total_ = total * 2;
    subset_ = subset;
    decodeObj_ = obj;
    memcpy(name_, fileName, nameSize);
    userID_ = userID;
    down_server_index_ = down_server_index;
    down_server_num_ = down_server_num;
    server_mutex_num = total - down_server_num;

    /* initialization */
    ringBuffer_ = (MessageQueue<Item_t> **) malloc(sizeof(MessageQueue<Item_t> *) * total);
    ringBufferMeta_ = (MessageQueue<ItemMeta_t> **) malloc(sizeof(MessageQueue<ItemMeta_t> *) * total);
    signalBuffer_ = (MessageQueue<init_t> **) malloc(sizeof(MessageQueue<init_t> *) * total_);
    downloadMetaBuffer_ = (char **) malloc(sizeof(char *) * total_);
    downloadContainer_ = (char **) malloc(sizeof(char *) * total_);
    socketArray_ = (Socket **) malloc(sizeof(Socket *) * total_);
    headerArray_ = (fileShareMDHead_t **) malloc(sizeof(fileShareMDHead_t *) * total_);
    fileSizeCounter = (int *) malloc(sizeof(int) * total);
    meta_list_buffer_ = std::make_unique<std::unique_ptr<unsigned char[]>[]>(total);
    count_MetaList_item_ = std::make_unique<int[]>(total);

    /* open config file */
    FILE *fp = fopen("./config", "rb");
    char line[225];
    const char ch[2] = ":";

    /* initialization loop */
    for(int i = 0; i < total; i++) {
        if(i == down_server_index) {
            // skip downed-server
            this->skip_config_one_line(fp, line);
            continue;
        }
        signalBuffer_[i] = new MessageQueue<init_t>(DOWNLOAD_QUEUE_SIZE);
        ringBufferMeta_[i] = new MessageQueue<ItemMeta_t>(DOWNLOAD_QUEUE_SIZE);
        downloadMetaBuffer_[i] = (char *) malloc(sizeof(char) * DOWNLOAD_BUFFER_SIZE);
        downloadContainer_[i] = (char *) malloc(sizeof(char) * DOWNLOAD_BUFFER_SIZE);
        meta_list_buffer_[i] = std::make_unique<unsigned char[]>(METALIST_BUFFER_SIZE);

        /* create threads */
        param_t *param = (param_t *) malloc(sizeof(param_t)); // thread's parameter
        param->cloudIndex = i;
        param->numOfCloud = subset_;
        param->obj = this;
        memcpy(param->fileName, fileName, nameSize);
        param->fileNameLength = nameSize;
        pthread_create(&tid_[i], 0, &thread_handler_meta, (void *) param);
        /* get config parameters */
        int ret = fscanf(fp, "%s", line);
        if(ret == 0)
            printf("fail to load config file\n");
        char *token = strtok(line, ch);
        char *ip = token;
        token = strtok(NULL, ch);
        int port = atoi(token);

        /* create sockets */
        socketArray_[i] = new Socket(ip, port, userID);
    }
    for(int i = total; i < total_; i++) {
        if(i == (down_server_index + DOWNLOAD_SERVER_NUMBER)) {
            // skip downed-server
            this->skip_config_one_line(fp, line);
            continue;
        }
        signalBuffer_[i] = new MessageQueue<init_t>(DOWNLOAD_QUEUE_SIZE);
        ringBuffer_[i - total] = new MessageQueue<Item_t>(DOWNLOAD_QUEUE_SIZE);
        downloadMetaBuffer_[i] = (char *) malloc(sizeof(char) * DOWNLOAD_BUFFER_SIZE);
        downloadContainer_[i] = (char *) malloc(sizeof(char) * DOWNLOAD_BUFFER_SIZE);

        /* create threads */
        param_t *param = (param_t *) malloc(sizeof(param_t)); // thread's parameter
        param->cloudIndex = i;
        param->numOfCloud = subset_;
        param->obj = this;
        pthread_create(&tid_[i], 0, &thread_handler, (void *) param);
        /* get config parameters */
        int ret = fscanf(fp, "%s", line);
        if(ret == 0)
            printf("fail to load config file\n");
        char *token = strtok(line, ch);
        char *ip = token;
        token = strtok(NULL, ch);
        int port = atoi(token);

        /* create sockets */
        socketArray_[i] = new Socket(ip, port, userID);
    }
    fclose(fp);
    fileMDHeadSize_ = sizeof(fileShareMDHead_t);
    shareMDEntrySize_ = sizeof(shareMDEntry_t);
}

/*
 * destructor
 *
 */
Downloader::~Downloader()
{
    for(int i = 0; i < total_; i++) {
        if(i == down_server_index_ || i == (down_server_index_ + DOWNLOAD_SERVER_NUMBER)) {
            continue;
        }
        delete signalBuffer_[i];
        free(downloadMetaBuffer_[i]);
        free(downloadContainer_[i]);
        delete socketArray_[i];
    }
    for(int i = 0; i < total_ / 2; i++) {
        if(i == down_server_index_) {
            continue;
        }
        delete ringBufferMeta_[i];
        delete ringBuffer_[i];
    }

    free(signalBuffer_);
    free(ringBuffer_);
    free(ringBufferMeta_);
    free(headerArray_);
    free(socketArray_);
    free(downloadContainer_);
    free(downloadMetaBuffer_);
    free(fileSizeCounter);
}

/*
 * main procedure for downloading a file
 *
 * @param filename - targeting filename
 * @param namesize - size of filename
 * @param numOfCloud - number of clouds that we download data
 * @param numOfRestoreServer - number of servers at least that we needed to download data
 *
 */
int Downloader::downloadFile(char *filename, int namesize, int numOfCloud, int numOfRestoreServer)
{

    /* temp share buffer for assemble the ring buffer data chunks*/
    unsigned char *shareBuffer;
    shareBuffer = (unsigned char *) malloc(sizeof(unsigned char) * RING_BUFFER_DATA_SIZE * MAX_NUMBER_OF_CLOUDS);

    char buffer[256];

    printf("[Download] [downloadFile] Wait for finishing...\n");
    /* wait for Downloader::preDownloadFile to finish */
    std::unique_lock<std::mutex> locker(m_mutex);
    cv_mutex.wait(locker);
    printf("\n[Download] [downloadFile] Start to send signal to thread_handler\n");

    /* add init object for download */
    init_t input;

    for(int i = total_ / 2; i < total_; i++) {
        if(i == (down_server_index_ + DOWNLOAD_SERVER_NUMBER)) {
            // skip downed-server
            continue;
        }

        input.type = 1;
        //copy the corresponding share as file name
        memset(buffer, 0, 256);
        sprintf(buffer, "%s.recipe", name_);

        string uploadRecipeFileName(buffer);
        input.nameSize = uploadRecipeFileName.length();
        memcpy(&input.filename, uploadRecipeFileName.c_str(), input.nameSize);
        signalBuffer_[i]->push(input);
    }
    printf("data download thread start\n");

    /* get the header object from buffer */
    Item_t headerObj[this->total_ / 2];
    auto numOfShares = std::make_unique<int[]>(total_ / 2);

    /* used for skipping specific server, which is no data chunks found */
    /* for a small file, only one server with no data chunks at most */
    int fakeIndex = -1;
    for(int i = 0; i < total_ / 2; i++) {
        if(i == down_server_index_) {
            // skip downed-server
            continue;
        }
        while(ringBuffer_[i]->is_empty());
        ringBuffer_[i]->pop(headerObj[i]);
        if(headerObj[i].type == -1) {
            /* if it's fake headerObj, skip */
            fakeIndex = i;
            printf("[Data] <%d> fakeIndex = %d\n", i, fakeIndex);
        }
        numOfShares[i] = headerObj[i].fileObj.file_header.numOfShares;
        printf("[Data] [downloadFile] %d's header extracted\n", i + total_ / 2);
    }

    /* parse header object, tell decoder the total number of secret */
    shareFileHead_t *header;
    for(int i = 0; i < this->total_ / 2; ++i) {
        if(headerObj[i].type != -1 && i != this->down_server_index_) {
            // only get valid data from one time under complex situation then break
            header = &(headerObj[i].fileObj.file_header);
            break;
        }
    }
    long fileSize = header->fileSize;
    decodeObj_->setFileSize(fileSize);
    printf("fileSize = %ld\n", fileSize);

    /* proceed each secret */
    int count = 0;
    long countSize = 0;
    auto countShares = std::make_unique<int[]>(total_ / 2);
    auto meta_list_array = std::make_unique<MetaList[]>(total_ / 2);

    auto meta_list_loop_num = std::make_unique<int[]>(total_ / 2);
    auto meta_list_offset = std::make_unique<int[]>(total_ / 2);
    auto chunk_num_in_meta_chunk = std::make_unique<int[]>(total_ / 2);
    auto segID = std::make_unique<int[]>(total_ / 2);
    std::vector<int> kShareIDList(numOfRestoreServer);
    for(int i = 0; i < total_ / 2; ++i) {
        if(i == this->down_server_index_) {
            // skip downed-server
            continue;
        }
        segID[i] = -1;
        meta_list_loop_num[i] = 0;
        meta_list_offset[i] = sizeof(int);
    }

    int secretID = 0;

    double assemble_time = 0;

    while(countSize < fileSize) {
        int secretSize = 0;
        int shareSize = 0;
        int shareBufferIndex = 0;
        // skip current chunk once reached k shares
        int share_num = 0;
        if(!TRACE_DRIVEN_FSL_ENABLED) {
            if(count % 10000 == 0) {
                // print message to tell users the program is still working
                printf("\n==============  ID = %d\n", count);
            }
        }
        int extract_num = 0;
        int shareID = 0;

        for(int i = 0; i < total_ / 2; i++) {
            if(i == this->down_server_index_ || i == fakeIndex) {
                // 1. skip downed server
                // 2. skip the remaining precess when fake header encountered
                continue;
            }

            if(meta_list_loop_num[i] == this->count_MetaList_item_[i] && secretID > meta_list_array[i].end_secretID) {
                // already extracted all metalist, no more data shares on server[i], skip
                continue;
            }

            Item_t output;

            ringBuffer_[i]->read(output);
            this->error_check_segID(output);

            if(output.shareObj.share_header.secretID != secretID) {
                // not the right time to extract from this server, then skip item from this server
                continue;
            }

#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
            if(output.shareObj.share_header.segID != segID[i]) {
                this->extract_meta_list(this->meta_list_buffer_[i].get(), meta_list_offset[i], meta_list_loop_num[i],
                                        meta_list_array[i]);
                segID[i] = meta_list_array[i].id;
            }

#ifdef BREAKDOWN_ENABLED
            }, assemble_time);
#endif
            if(!ringBuffer_[i]->pop(output)){
                continue;
            }

            if(output.shareObj.share_header.shareID == -1) {
                // skip the placeholder of data shares
                continue;
            }

#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
            this->assign_kShareID_in_list(kShareIDList[shareBufferIndex], meta_list_array[i].shareID);

            ++countShares[i];
            ++extract_num;
            secretSize = output.shareObj.share_header.secretSize;
            shareSize = output.shareObj.share_header.shareSize;
            secretID = output.shareObj.share_header.secretID;
            shareID = output.shareObj.share_header.shareID;
            if(shareID < 0) {
                printf("[DownloadFile] shareID = %d!! Exiting...", shareID);
                exit(-1);
            }

            ++share_num;

            memcpy(shareBuffer + shareBufferIndex * shareSize, output.shareObj.data, shareSize);
            shareBufferIndex++;
#ifdef BREAKDOWN_ENABLED
            }, assemble_time);
#endif
        }
        countSize += secretSize;
        if(!TRACE_DRIVEN_FSL_ENABLED) {
            if(count % 10000 == 0 && count != 0) {
                printf("[Data] [DownloadFile] 3000 chunks downloaded\n");
            }
        }

        /* add the share buffer to the decoder ringbuffer */
        Decoder::ShareChunk_t package;
#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        package.secretSize = secretSize;
        package.shareSize = shareSize;
        package.secretID = secretID;

        // update kShareIDList for this data chunk
        for(int j = 0; j < kShareIDList.size(); ++j) {
            package.kShareIDList[j] = kShareIDList[j];
        }

        memcpy(&(package.data), shareBuffer, numOfRestoreServer * shareSize);
#ifdef BREAKDOWN_ENABLED
        }, assemble_time);
#endif
        decodeObj_->add(&package, count % DECODE_NUM_THREADS);
        // pre-assign what the next secretID is
        ++secretID;
        count++;
    }
    for(int i = 0; i < DECODE_NUM_THREADS; ++i) {
        decodeObj_->inputbuffer_[i]->set_job_done();
    }

    free(shareBuffer);
    printf("download over!\n");

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Downloader] <downloadFile> assemble time: is /%lf/ s\n", assemble_time);
    printf("[Time]===================\n\n");
#endif
    return 0;
}

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
int Downloader::preDownloadFile(char *filename, int nameSize, int numOfCloud)
{
    /* if nameSize of file is 1, at least make sure it could fit encoded file name length (i.e., 32)  */
    unsigned char tmp[nameSize * 32];
    int tmp_s;

    // encode the filepath
    unsigned char key[KEY_SIZE];
    memset(key, 0, KEY_SIZE);
    decodeObj_->decodeObj_[DECODE_NUM_THREADS]->encoding((unsigned char *) filename, nameSize, tmp, &(tmp_s), key,
                                                         true);

    printf("\n");
    printf("[preDownloadFile] filename before encoding: %s\n", filename);
    printf("[preDownloadFile] filename size before encoding: %d\n", nameSize);
    printf("[preDownloadFile] hex encoded file name: ");
    Logger::printHexValue(tmp, numOfCloud * 32);
    printf("\n");
    printf("[preDownloadFile] encoded file name size: %d\n", tmp_s);

    /* add init object for download */
    init_t input;
    for(int i = 0; i < numOfCloud; i++) {
        if(i == this->down_server_index_) {
            // skip downed-server
            continue;
        }
        input.type = 1;

        //copy the corresponding share as file name
        memcpy(&input.filename, tmp + i * tmp_s, tmp_s);
        input.nameSize = tmp_s;
        signalBuffer_[i]->push(input);
    }

    printf("pre - download over!\n");

    return 1;
}

/*
 * test if it's the end of downloading a file
 *
 */
int Downloader::indicateEnd()
{
    for(int i = 0; i < total_; i++) {
        if(i == this->down_server_index_ || i == (this->down_server_index_ + this->total_ / 2)) {
            continue;
        }
        /* trying to join all threads */
        pthread_join(tid_[i], NULL);
    }
    return 1;
}


/*
 * download meta list from server
 *
 * @param metalist_buffer - the buffer storing meta_list<return>
 * @param socket - socket object for receiving data from server
 * @param counter - count the number of meta_list in meta_list_buffer
 *
 * */
void Downloader::download_meta_list(unsigned char *metalist_buffer, Socket *socket, int &counter, int cloudIndex)
{
    auto buffer = std::make_unique<char[]>(256);

    // 1. receive indicator
    int indicator = 0;
    socket->genericDownload(buffer.get(), sizeof(int));
    memcpy(&indicator, buffer.get(), sizeof(int));

    if(indicator == INODE_NOT_FOUND) {
        printf("[download_meta_list] Not found in server:%d\n", cloudIndex);
        exit(-1);
    }

    if(indicator != RECEIVE_META_LIST) {
        printf("[download_meta_list] Not correct indicator for downloading metalist\n");
        exit(-1);
    }

    // 2. receive totalSize
    int totalSize = 0;

    socket->genericDownload(buffer.get(), sizeof(int));
    memcpy(&totalSize, buffer.get(), sizeof(int));

    // 3. receive metalist_buffer
    socket->genericDownload((char *) metalist_buffer, totalSize);
    memcpy(&counter, metalist_buffer, sizeof(int));
}

/*
 * set the number of downed servers
 *
 * @param num - the number of downed-server
 *
 * */
void Downloader::set_down_server_number(int num)
{
    this->down_server_num_ = num;
}

/*
 * set the index of downed servers
 *
 * @param index - the index of downed-server
 *
 * */
void Downloader::set_down_server_index(int index)
{
    this->down_server_index_ = index;
}

/*
 * skip one line from config file
 *
 * @param fp - file pointer to config file
 * @param line - the buffer to store line
 *
 * */
void Downloader::skip_config_one_line(FILE *fp, char *line)
{
    int ret = fscanf(fp, "%s", line);
    if(ret == 0)
        printf("fail to load config file\n");
}

/*
 * Check whether segID < 0, which is abnormal
 *
 * @param item - the item to be checked with segID
 *
 * */
void Downloader::error_check_segID(Item_t &item)
{
    int segID = item.shareObj.share_header.segID;
    if(segID < 0) {
        printf("\n[downloadFile] Bad segID encountered!! Checking THIS!!! Exiting...\n");
        printf("Bad data item info:\n");
        printf("\tsecretID: %d\n", item.shareObj.share_header.secretID);
        printf("\tsecretSize: %d\n", item.shareObj.share_header.secretSize);
        printf("\tshareSize: %d\n", item.shareObj.share_header.shareSize);
        printf("\tsegID: %d\n", item.shareObj.share_header.segID);
        exit(-2);
    }
}

/*
 * extract MetaList from meta_list_buffer_
 *
 * @param metalist_buffer - the buffer storing meta_list
 * @param offset - the offset of reading buffer<return>
 * @param loop_num - count for the total number of extracted from meta_list<return>
 * @param meta_list - for storing MetaList extracted from buffer<return>
 *
 * */
void Downloader::extract_meta_list(unsigned char *metalist_buffer, int &offset, int &loop_num,
                                   Downloader::MetaList &meta_list)
{
    memcpy(&meta_list, metalist_buffer + offset, sizeof(MetaList));
    offset += sizeof(MetaList);
    ++loop_num;
}

/*
 * assign kShareIDList value
 *
 * @param kShareID - id to be modified
 * @param id - id of MetaList
 *
 * */
void Downloader::assign_kShareID_in_list(int &kShareID, int id)
{
    if(id != -1) {
        kShareID = id;
    }
}
