/*
 * uploader.cc
 */

#include "uploader.hh"

using namespace std;

/*
 * uploader thread handler
 *
 * @param param - input structure
 *
 */
void *Uploader::thread_handler(void *param)
{
    /* get input parameters */
    param_t *temp = (param_t *) param;
    int cloudIndex = temp->cloudIndex;
    Uploader *obj = temp->obj;
    free(temp);

    Chunk_t tmp;
    Item_t output;

    // Add time
    double perform_upload_time = 0;
    double recipe_handling_time = 0;

    /* main loop for uploader, end when indicator recv.ed */
    while(true) {
        if(obj->ringBuffer_[cloudIndex - UPLOAD_SERVER_NUMBER]->done_ &&
           obj->ringBuffer_[cloudIndex - UPLOAD_SERVER_NUMBER]->is_empty()) {
            // thread finished its mission, exit
            break;
        }

        /* get object from ringbuffer */
        if(!obj->ringBuffer_[cloudIndex - UPLOAD_SERVER_NUMBER]->pop(tmp)) {
            continue;
        }

        obj->copy_Chunk_to_Item(output, tmp);

        /* fake data -> exit thread */
        if(output.kmCloudIndex == cloudIndex - UPLOAD_SERVER_NUMBER && output.type == SHARE_END
           && output.shareObj.share_header.secretID == 0) {
            printf("[Uploader] [Data] <%d> secretID = %d\n", cloudIndex, output.shareObj.share_header.secretID);
            printf("[Uploader] [Data] <%d> fake data detected!! Exiting thread!!\n", cloudIndex);
            pthread_exit(NULL);
        }

        if(output.shareObj.share_header.secretID == DATA_SECRET_ID_END_INDICATOR) {
            /* IF it's SHARE_END and KM server,
             * then this fake data comes from other server(Encoder::collect) to perform uploading properly */
            printf("[Uploader] [Data] <%d> Share End and Upload remaining data to KM server\n", cloudIndex);
            printf("[Uploader] [Data] <%d> item info:\n", cloudIndex);
            printf("[Uploader] [Data] <%d> \tsecretID: %d\n", cloudIndex,
                   output.shareObj.share_header.secretID);
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
                obj->performUpload(cloudIndex, false);
#ifdef BREAKDOWN_ENABLED
            }, perform_upload_time);
#endif
            printf("[Uploader] [Data] <%d> Data uploaded!!\n", cloudIndex);
            break;
        }
        /* IF this is share object */
        int shareSize = output.shareObj.share_header.shareSize;

        /* see if the container buffer can hold the coming share, if not then perform upload */
        if(shareSize + obj->containerWP_[cloudIndex] > UPLOAD_BUFFER_SIZE) {
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
                obj->performUpload(cloudIndex, false);
#ifdef BREAKDOWN_ENABLED
            }, perform_upload_time);
#endif
            obj->updateHeader(cloudIndex);
        }

#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        /* copy share header into metabuffer */
        memcpy(obj->uploadMetaBuffer_[cloudIndex] + obj->metaWP_[cloudIndex], &(output.shareObj.share_header),
               obj->shareMDEntrySize_);

        shareEntry_t shareHeader;
        memcpy(&shareHeader, obj->uploadMetaBuffer_[cloudIndex] + obj->metaWP_[cloudIndex],
               obj->shareMDEntrySize_);

        obj->metaWP_[cloudIndex] += obj->shareMDEntrySize_;

        /* copy share data into container buffer */
        memcpy(obj->uploadContainer_[cloudIndex] + obj->containerWP_[cloudIndex], output.shareObj.data,
               shareSize);
        obj->containerWP_[cloudIndex] += shareSize;

        // record share size
        obj->shareSizeArray_[cloudIndex][obj->numOfShares_[cloudIndex]] = shareSize;
        obj->numOfShares_[cloudIndex]++;

        /* update file header pointer */
        obj->headerArray_[cloudIndex]->numOfComingSecrets += 1;
        obj->headerArray_[cloudIndex]->sizeOfComingSecrets += output.shareObj.share_header.secretSize;

#ifdef BREAKDOWN_ENABLED
        }, recipe_handling_time);
#endif
        /* IF this is the last share object, perform upload and exit thread */
        if(output.type == SHARE_END) {
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
                obj->performUpload(cloudIndex, false);
#ifdef BREAKDOWN_ENABLED
            }, perform_upload_time);
#endif
            printf("[Uploader] <Data:%d> SHARE_END\n", cloudIndex);
        }
    }

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Uploader] <data:%d> perform_upload time: is /%lf/ s\n", cloudIndex, perform_upload_time);
    fprintf(stderr, "[Time] [Uploader] <data:%d> recipe_handling time: is /%lf/ s\n", cloudIndex, recipe_handling_time);
    printf("[Time]===================\n\n");
#endif
    pthread_exit(NULL);
}

/*
 * uploader thread handler
 *
 * @param param - input structure
 *
 */
void *Uploader::thread_handler_meta(void *param)
{
    /* get input parameters */
    param_t *temp = (param_t *) param;
    int cloudIndex = temp->cloudIndex;
    Uploader *obj = temp->obj;
    free(temp);

    int total_chunks = 0;

    ItemMeta_t output;

    // Add time
    double perform_upload_time = 0;
    double recipe_handling_time = 0;

    /* main loop for uploader, end when indicator recv.ed */
    while(true) {
        if(obj->ringBufferMeta_[cloudIndex]->done_ && obj->ringBufferMeta_[cloudIndex]->is_empty()) {
            // thread finished its mission, exit
            break;
        }

        /* get object from ringbuffer */
        if(!obj->ringBufferMeta_[cloudIndex]->pop(output)) {
            continue;
        }

        /* fake data -> exit thread */
        if(output.kmCloudIndex == cloudIndex && output.type == SHARE_END
           && output.shareObj.share_header.secretID == 0) {
            printf("[Uploader] [Meta] <%d> secretID = %d\n", cloudIndex, output.shareObj.share_header.secretID);
            printf("[Uploader] [Meta] <%d> fake data detected!! Exiting thread!!\n", cloudIndex);
            pthread_exit(NULL);
        }


        if(output.shareObj.share_header.secretID == META_SECRET_ID_END_INDICATOR) {
            /* IF it's SHARE_END and KM server,
             * then this fake data comes from other server(Encoder::collect) to perform uploading properly */
            printf("[Uploader] [Meta] <%d> Share End and Upload remaining data to KM server\n", cloudIndex);
            printf("[Uploader] [Meta] <%d> item info:\n", cloudIndex);
            printf("[Uploader] [Meta] <%d> \tsecretID: %d\n", cloudIndex,
                   output.shareObj.share_header.secretID);
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
                obj->performUpload(cloudIndex, true);
#ifdef BREAKDOWN_ENABLED
            }, perform_upload_time);
#endif
            printf("[Uploader] <meta:%d> total_chunks: %d\n", cloudIndex, total_chunks);
            printf("[Uploader] <meta:%d> Data uploaded!! END!\n", cloudIndex);
            break;
        }

        /* IF this is share object */
        int shareSize = output.shareObj.share_header.shareSize;

        /* see if the container buffer can hold the coming share, if not then perform upload */
        if(shareSize + obj->containerWP_[cloudIndex] > UPLOAD_BUFFER_SIZE) {
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
                obj->performUpload(cloudIndex, false);
#ifdef BREAKDOWN_ENABLED
            }, perform_upload_time);
#endif
            obj->updateHeader(cloudIndex);
        }

#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        /* copy share header into metabuffer */
        memcpy(obj->uploadMetaBuffer_[cloudIndex] + obj->metaWP_[cloudIndex], &(output.shareObj.share_header),
               obj->shareMDEntrySize_);
        obj->metaWP_[cloudIndex] += obj->shareMDEntrySize_;

        /* copy share data into container buffer */
        memcpy(obj->uploadContainer_[cloudIndex] + obj->containerWP_[cloudIndex], output.shareObj.data,
               shareSize);
        obj->containerWP_[cloudIndex] += shareSize;

        /* record share size */
        obj->shareSizeArray_[cloudIndex][obj->numOfShares_[cloudIndex]] = shareSize;
        obj->numOfShares_[cloudIndex]++;

        /* update file header pointer */
        obj->headerArray_[cloudIndex]->numOfComingSecrets += 1;
        ++total_chunks;
        obj->headerArray_[cloudIndex]->sizeOfComingSecrets += output.shareObj.share_header.secretSize;
#ifdef BREAKDOWN_ENABLED
        }, recipe_handling_time);
#endif

        /* IF this is the last share object, perform upload and exit thread */
        if(output.type == SHARE_END) {
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
                obj->performUpload(cloudIndex, true);
#ifdef BREAKDOWN_ENABLED
            }, perform_upload_time);
#endif
            printf("[Uploader] <meta:%d> SHARE_END\n", cloudIndex);
            printf("[Uploader] <meta:%d> total_chunks: %d\n", cloudIndex, total_chunks);
        }
    }

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Uploader] <meta:%d> perform_upload time: is /%lf/ s\n", cloudIndex, perform_upload_time);
    fprintf(stderr, "[Time] [Uploader] <meta:%d> recipe_handling time: is /%lf/ s\n", cloudIndex, recipe_handling_time);
    printf("[Time]===================\n\n");
#endif
    pthread_exit(NULL);
}

/*
 * constructor
 *
 * @param p - input large prime number
 * @param total - input total number of clouds
 * @param subset - input number of clouds to be chosen
 *
 */
Uploader::Uploader(int total, int subset, int userID, char *fileName, int nameSize)
{

    total_ = total * 2;
    subset_ = subset;

    memcpy(name_, fileName, nameSize);

    /* initialization */
    ringBuffer_ = (MessageQueue<Chunk_t> **) malloc(sizeof(MessageQueue<Chunk_t> *) * total_);
    ringBufferMeta_ = (MessageQueue<ItemMeta_t> **) malloc(sizeof(MessageQueue<ItemMeta_t> *) * total);
    uploadMetaBuffer_ = (char **) malloc(sizeof(char *) * total_);
    uploadContainer_ = (char **) malloc(sizeof(char *) * total_);
    containerWP_ = (int *) malloc(sizeof(int) * total_);
    metaWP_ = (int *) malloc(sizeof(int) * total_);
    numOfShares_ = (int *) malloc(sizeof(int) * total_);
    socketArray_ = (Socket **) malloc(sizeof(Socket *) * total_);
    headerArray_ = (fileShareMDHead_t **) malloc(sizeof(fileShareMDHead_t *) * total_);
    shareSizeArray_ = (int **) malloc(sizeof(int *) * total_);

    /* read server ip & port from config file */
    FILE *fp = fopen("./config", "rb");
    char line[225];
    const char ch[2] = ":";

    for(int i = 0; i < total; i++) {
        ringBufferMeta_[i] = new MessageQueue<ItemMeta_t>(UPLOAD_QUEUE_SIZE);
        shareSizeArray_[i] = (int *) malloc(sizeof(int) * UPLOAD_BUFFER_SIZE);
        uploadMetaBuffer_[i] = (char *) malloc(sizeof(char) * UPLOAD_BUFFER_SIZE);
        uploadContainer_[i] = (char *) malloc(sizeof(char) * UPLOAD_BUFFER_SIZE);
        containerWP_[i] = 0;
        metaWP_[i] = 0;
        numOfShares_[i] = 0;

        param_t *param = (param_t *) malloc(sizeof(param_t)); // thread's parameter
        param->cloudIndex = i;
        param->obj = this;
        pthread_create(&tid_[i], 0, &thread_handler_meta, (void *) param);

        /* line by line read config file*/
        int ret = fscanf(fp, "%s", line);
        if(ret == 0)
            printf("fail to load config file\n");
        char *token = strtok(line, ch);
        char *ip = token;
        token = strtok(NULL, ch);
        int port = atoi(token);

        /* set sockets */
        socketArray_[i] = new Socket(ip, port, userID);
        accuData_[i] = 0;
        accuUnique_[i] = 0;
    }
    for(int i = total; i < total_; i++) {
        ringBuffer_[i - total] = new MessageQueue<Chunk_t>(UPLOAD_QUEUE_SIZE);
        shareSizeArray_[i] = (int *) malloc(sizeof(int) * UPLOAD_BUFFER_SIZE);
        uploadMetaBuffer_[i] = (char *) malloc(sizeof(char) * UPLOAD_BUFFER_SIZE);
        uploadContainer_[i] = (char *) malloc(sizeof(char) * UPLOAD_BUFFER_SIZE);
        containerWP_[i] = 0;
        metaWP_[i] = 0;
        numOfShares_[i] = 0;

        param_t *param = (param_t *) malloc(sizeof(param_t)); // thread's parameter
        param->cloudIndex = i;
        param->obj = this;
        pthread_create(&tid_[i], 0, &thread_handler, (void *) param);

        /* line by line read config file*/
        int ret = fscanf(fp, "%s", line);
        if(ret == 0)
            printf("fail to load config file\n");
        char *token = strtok(line, ch);
        char *ip = token;
        token = strtok(NULL, ch);
        int port = atoi(token);

        /* set sockets */
        socketArray_[i] = new Socket(ip, port, userID);
        accuData_[i] = 0;
        accuUnique_[i] = 0;
    }
    fclose(fp);
    fileMDHeadSize_ = sizeof(fileShareMDHead_t);
    shareMDEntrySize_ = sizeof(shareMDEntry_t);
}

/*
 * destructor
 */
Uploader::~Uploader()
{
    for(int i = 0; i < total_; i++) {
        free(shareSizeArray_[i]);
        free(uploadMetaBuffer_[i]);
        free(uploadContainer_[i]);
        delete socketArray_[i];
    }
    for(int i = 0; i < total_ / 2; i++) {
        delete ringBuffer_[i];
        delete ringBufferMeta_[i];
    }
    free(ringBuffer_);
    free(ringBufferMeta_);
    free(shareSizeArray_);
    free(headerArray_);
    free(socketArray_);
    free(numOfShares_);
    free(metaWP_);
    free(containerWP_);
    free(uploadContainer_);
    free(uploadMetaBuffer_);
}

/*
 * Initiate upload
 *
 * @param cloudIndex - indicate targeting cloud
 * @param end - indicate ending(only used for metaDedupCore)
 *
 */
int Uploader::performUpload(int cloudIndex, bool end)
{
    /* 1. send metadata */
    socketArray_[cloudIndex]->sendMeta(uploadMetaBuffer_[cloudIndex], metaWP_[cloudIndex]);

    /* 2. get back the status list */
    int numOfShares;
    bool *statusList = (bool *) malloc(sizeof(bool) * (numOfShares_[cloudIndex] + 1));
    socketArray_[cloudIndex]->getStatus(statusList, &numOfShares);

    /* 3. according to status list, reconstruct the container buffer */
    int buffer_size = 0;
    bool metaType = false;
    if(cloudIndex < total_ / 2) {
        buffer_size = RING_BUFFER_META_SIZE;
        metaType = true;
    } else {
        buffer_size = RING_BUFFER_DATA_SIZE;
    }
    char temp[buffer_size];
    int indexCount = 0;
    int containerIndex = 0;
    int currentSize = 0;
    for(int i = 0; i < numOfShares; i++) {
        currentSize = shareSizeArray_[cloudIndex][i];
        if(statusList[i] == 0) {
            memcpy(temp, uploadContainer_[cloudIndex] + containerIndex, currentSize);
            memcpy(uploadContainer_[cloudIndex] + indexCount, temp, currentSize);
            indexCount += currentSize;
        }
        containerIndex += currentSize;
    }

    /* calculate the amount of sent data */
    accuData_[cloudIndex] += containerIndex;
    accuUnique_[cloudIndex] += indexCount;

    /* 4. finally send the unique data to the cloud */
    socketArray_[cloudIndex]->sendData(uploadContainer_[cloudIndex], indexCount, metaType, end);

    free(statusList);
    return 0;
}

/*
 * procedure for update headers when upload finished
 * 
 * @param cloudIndex - indicating targeting cloud
 *
 *
 *
 */
// 	SEND 1: (4 byte) state update indicator
int Uploader::updateHeader(int cloudIndex)
{

    /* get the file name size */
    int offset = headerArray_[cloudIndex]->fullNameSize;

    /* update header counts */
    headerArray_[cloudIndex]->numOfPastSecrets += headerArray_[cloudIndex]->numOfComingSecrets;
    headerArray_[cloudIndex]->sizeOfPastSecrets += headerArray_[cloudIndex]->sizeOfComingSecrets;

    /* reset coming counts */
    headerArray_[cloudIndex]->numOfComingSecrets = 0;
    headerArray_[cloudIndex]->sizeOfComingSecrets = 0;

    /* reset all index (means buffers are empty) */
    containerWP_[cloudIndex] = 0;
    metaWP_[cloudIndex] = 0;
    numOfShares_[cloudIndex] = 0;

    /* copy the header into metabuffer */
    memcpy(uploadMetaBuffer_[cloudIndex], headerArray_[cloudIndex], fileMDHeadSize_ + offset);
    metaWP_[cloudIndex] += fileMDHeadSize_ + offset;

    return 1;
}

/*
 * interface for adding object to ringbuffer
 *
 * @param item - the object to be added
 * @param index - the buffer index
 *
 */
int Uploader::add(Chunk_t &item, int index)
{
    ringBuffer_[index]->push(item);
    return 1;
}

/*
 * interface for adding object to ringbuffer
 *
 * @param item - the object to be added
 * @param index - the buffer index
 *
 */
int Uploader::addMeta(ItemMeta_t &item, int index)
{
    ringBufferMeta_[index]->push(item);
    return 1;
}

/*
 * indicate the end of uploading a file
 * 
 * @return total - total amount of data that input to uploader
 * @return uniq - the amount of unique data that transferred in network
 *
 */
int Uploader::indicateEnd(long long *total, long long *uniq)
{

    for(int i = 0; i < UPLOAD_NUM_THREADS * 2; i++) {

        pthread_join(tid_[i], NULL);
        *total += accuData_[i];
        *uniq += accuUnique_[i];
    }
    return 1;
}

/*
 * collect file header
 *
 * @param header - file header to be collect in Uploader
 * @param cloudIndex - the index of cloud server
 *
 */
void Uploader::collect_header(FileHeader_t &header, int cloudIndex)
{
    /* copy object content into metabuffer */
    memcpy(this->uploadMetaBuffer_[cloudIndex] + this->metaWP_[cloudIndex],
           &(header.file_shareMD_header), this->fileMDHeadSize_);

    /* head array point to new file header */
    this->headerArray_[cloudIndex] = (fileShareMDHead_t *) (this->uploadMetaBuffer_[cloudIndex] +
                                                            this->metaWP_[cloudIndex]);

    /* meta index update */
    this->metaWP_[cloudIndex] += this->fileMDHeadSize_;

    /* copy file full path name */
    memcpy(this->uploadMetaBuffer_[cloudIndex] + this->metaWP_[cloudIndex], header.encoded_file_name,
           header.file_shareMD_header.fullNameSize);

    /* meta index update */
    this->metaWP_[cloudIndex] += this->headerArray_[cloudIndex]->fullNameSize;
}

/*
 * copy Chunk_t to Item_t
 *
 * @param output - dest of data structure
 * @param input - src of data structure
 *
 */
void Uploader::copy_Chunk_to_Item(Uploader::Item_t &output, Chunk_t &input)
{
    output.shareObj.share_header.secretID = input.chunk_id;
    output.shareObj.share_header.secretSize = input.chunk_size;
    output.shareObj.share_header.shareID = input.share_id;
    output.shareObj.share_header.shareSize = input.share_size;
    memcpy(output.shareObj.share_header.shareFP, input.total_FP + input.share_id * FP_SIZE, FP_SIZE);
    output.shareObj.share_header.segID = input.seg_id;

    memcpy(output.shareObj.data, input.content + input.share_id * input.share_size, input.share_size);
    output.kmCloudIndex = input.kmCloudIndex;
    if(input.end == 1) {
        output.type = SHARE_END;
    } else {
        output.type = SHARE_OBJECT;
    }
}
