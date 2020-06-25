/*
 * encoder.cc
 *
 */

#include "encoder.hh"

using namespace std;

/*
 * thread handler for encoding each secret into shares
 *
 * @param param - parameters for encode thread
 */
void *Encoder::thread_handler(void *param)
{

    /* parse parameters */
    int index = ((param_encoder *) param)->index;
    Encoder *obj = ((param_encoder *) param)->obj;
    free(param);

    // Add time
    double encoding_time = 0;

    Chunk_t temp;
    unsigned char encoded_data[MAX_DATA_SIZE]{};
    int share_size = 0;
    /* main loop for getting secrets and encode them into shares*/
    while(true) {

        if(obj->inputbuffer_[index]->done_ && obj->inputbuffer_[index]->is_empty()) {
            // thread finished its mission, exit
            obj->calc_inputbuffer_[index]->set_job_done();
            break;
        }

        /* get an object from input buffer */
        if(!obj->inputbuffer_[index]->pop(temp)) {
            continue;
        }


        /* if it's share object */
#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        obj->encodeObj_[index]->encoding(temp.content, temp.chunk_size, encoded_data,
                                         &(share_size), temp.total_FP, false);
#ifdef BREAKDOWN_ENABLED
        }, encoding_time);
#endif
        // content role changed: content <=> encrypted data chunk
        memcpy(temp.content, encoded_data, share_size * TOTAL_SHARES_NUM);

        temp.share_size = (short) share_size;

        /* add the object to output buffer */
        obj->calc_inputbuffer_[index]->push(temp);
    }

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Encoder] <thread_handler> encoding time: is /%lf/ s\n", encoding_time);
    printf("[Time]===================\n\n");
#endif
    return nullptr;
}

/*
 * thread handler for calculating hash of data shares
 *
 * @param param - parameters for encode thread
 */
void *Encoder::thread_handler_hash(void *param)
{

    /* parse parameters */
    int index = ((param_encoder *) param)->index;
    Encoder *obj = ((param_encoder *) param)->obj;
    free(param);

    // Add time
    double generate_hash_time = 0;

    short shareSize = 0;
    /* main loop for getting secrets and encode them into shares*/
    Chunk_t temp;
    while(true) {
        if(obj->calc_inputbuffer_[index]->done_ && obj->calc_inputbuffer_[index]->is_empty()) {
            // thread finished its mission, exit
            obj->calc_outputbuffer_[index]->set_job_done();
            break;
        }

        /* get an object from input buffer */
        if(!obj->calc_inputbuffer_[index]->pop(temp)) {
            continue;
        }

        /* if it's share object */

        // split into `n_ - kmServerCount_` shares (currently, set to 4)
        shareSize = temp.share_size;
#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
            for(int i = 0; i < (obj->n_ - obj->kmServerCount_); ++i) {
                obj->calc_cryptoObj_[index]->generateHash(temp.content + i * shareSize, shareSize,
                                                          temp.total_FP + i * FP_SIZE);
            }
#ifdef BREAKDOWN_ENABLED
        }, generate_hash_time);
#endif

        /* add the object to output buffer */
        obj->calc_outputbuffer_[index]->push(temp);
    }


#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Encoder] <thread_hash:%d> generate hash time: is /%lf/ s\n", index, generate_hash_time);
    printf("[Time]===================\n\n");
#endif
    return nullptr;
}

/*
 * collect thread for getting share object in order
 *
 * @param param - parameters for collect thread
 */
void *Encoder::collect(void *param)
{
    /* index for sequentially collect shares */
    int nextBufferIndex = 0;

    /* parse parameters */
    Encoder *obj = (Encoder *) param;
    //metadata chunk part
    // init metachunk temp store
    int metaChunkCounter[obj->n_];
    int metaChunkID[obj->n_];
    int metaSize[obj->n_]; // for checking size overflow
    for(int i = 0; i < obj->n_; i++) {
        metaChunkCounter[i] = 0;
        metaChunkID[i] = -1;
        metaSize[i] = sizeof(int);
    }
    auto metaChunkBuffer = std::make_unique<std::unique_ptr<unsigned char[]>[]>(obj->n_);
    for(int i = 0; i < obj->n_; ++i) {
        metaChunkBuffer[i] = std::make_unique<unsigned char[]>(SECRET_SIZE_META);
    }

    // chunkCount is for debugging only
    auto chunkCount = std::make_unique<int[]>(obj->n_);

    auto metaChunkCount = std::make_unique<int[]>(obj->n_);

    Uploader::ItemMeta_t metaChunkUploadObj;

    /* record the previous SegID to check when to end meta data chunk */
    // i.e., segID <-> metadataID * -1
    int previousSegID = 0;

    // use array-type to preserve the value for packing up metadata chunks
    auto shareIndex = std::make_unique<int[]>(obj->n_);

    // Add time
    double generate_meta_chunk_time = 0;

    Chunk_t temp;
    /* main loop for collecting shares */
    while(true) {
        if(obj->calc_outputbuffer_[nextBufferIndex]->done_ &&
           obj->calc_outputbuffer_[nextBufferIndex]->is_empty()) {
            // thread finished its mission, exit
            for(int i = 0; i < obj->uploadObj_->total_ / 2; ++i) {
                obj->uploadObj_->ringBuffer_[i]->set_job_done();
                obj->uploadObj_->ringBufferMeta_[i]->set_job_done();
            }
            break;
        }

        /* extract an object from a certain ringbuffer */
        if(!obj->calc_outputbuffer_[nextBufferIndex]->pop(temp)) {
            continue;
        }

        nextBufferIndex = (nextBufferIndex + 1) % NUM_THREADS;

        /* get the object type */

        /* if it's share object */
        int kmServerID = temp.kmCloudIndex;

        // one segment to one meta data chunk
        // IF new segment encountered, assemble metaNodes into metadata and send it to uploader
        if(previousSegID != temp.seg_id) {

            // pack metaNodes into metadata and assemble metadata chunks for previous segment
            for(int i = 0; i < obj->n_; ++i) {
                if(metaChunkCounter[i] == 0) {
                    // empty meta nodes in this server => this server is KM server for this segment
                    continue;
                }

#ifdef BREAKDOWN_ENABLED
                Logger::measure_time([&]() {
#endif
                    /* skip kmServer when processing previous segment */
                    metaChunkUploadObj.type = SHARE_OBJECT;

                    obj->assignMetaShareHeader(metaChunkUploadObj, metaChunkID[i], metaChunkCounter[i],
                                               previousSegID, shareIndex[i], temp.kmCloudIndex);
                    metaChunkID[i]--;

                    obj->assembleMetadataChunks(metaChunkUploadObj, metaChunkBuffer[i].get(),
                                                metaChunkCounter[i]);
#ifdef BREAKDOWN_ENABLED
                }, generate_meta_chunk_time);
#endif

                obj->uploadObj_->addMeta(metaChunkUploadObj, i);

                /* prepare for (next segment | meta data chunk) */
                metaSize[i] = 0;
                memset(&metaChunkUploadObj, 0, sizeof(Uploader::ItemMeta_t));
                metaChunkCounter[i] = 0;
            }
            previousSegID = temp.seg_id;
        }

        /* start a new meta data chunk for a new segment */
        int loop_index = obj->getNextStreamIndex(kmServerID, obj->n_);
        int loop_count = 0;
        shareIndex[loop_index] = 0; // reset shareIndex for a loop

        while(loop_count < obj->n_) {
            /* check whether it is KM server */
            if(loop_index == kmServerID) {
                /* IF share ends, end <KM-index> thread which sends data to <KM-index> server */
                if(temp.end == 1) {
                    printf("\n[collect] <%d> Share_END! segID: %d | secretID: %d | kmServerID: %d\n",
                           loop_index,
                           temp.seg_id, temp.chunk_id, temp.kmCloudIndex);
                    printf("[collect] <%d> Telling uploader to exit\n", loop_index);

                    /* make sure Encoder::collect could exit thread normally */

                    /* IF there are meta data nodes not sent, send the remaining data */
                    if(metaChunkCounter[kmServerID] != 0) {
                        printf("[collect] unknown internal error here!! Check this\n");
                        exit(-4);
                    }

                    /* if SHARE_END, add fake data to tell Uploader::thread_Data/Meta to exit */
                    Chunk_t fakeInput;
                    Uploader::ItemMeta_t fakeInputMeta;

                    fakeInput.end = 1;
                    fakeInput.kmCloudIndex = kmServerID;
                    // Tell uploader this is the end of data chunks
                    fakeInput.chunk_id = DATA_SECRET_ID_END_INDICATOR;

                    fakeInputMeta.type = SHARE_END;
                    fakeInputMeta.kmCloudIndex = kmServerID;
                    // Tell uploader this is the end of meta chunks
                    fakeInputMeta.shareObj.share_header.secretID = META_SECRET_ID_END_INDICATOR;

                    printf("[collect] Add fake data and metaData to Uploader RingBuffer\n");
                    obj->uploadObj_->add(fakeInput, kmServerID);
                    obj->uploadObj_->addMeta(fakeInputMeta, kmServerID);
                }
                /* do not send data to KM server, thus skip kmServerID */
                ++loop_count;
                loop_index = obj->getNextStreamIndex(loop_index, obj->n_);
                continue;
            }

            // for debugging only
            ++chunkCount[loop_index];

            int shareID = shareIndex[loop_index];

            /* data range check */
            if(shareIndex[loop_index] >= obj->n_) {
                printf("[Data] [collect] Error: Incorrect share count. shareCount <= %d\n",
                       obj->n_ - obj->kmServerCount_);
                exit(-2);
            }
#ifdef ENCODE_ONLY_MODE
            if (temp.share_chunk.end == 1)
                    pthread_exit(NULL);
#else

            //meta chunk maker part -> make different meta chunk for each part of data chunk share

            /* metaChunkTemp <-> mChunk */
            metaNode metaChunkTemp;
#ifdef BREAKDOWN_ENABLED
            Logger::measure_time([&]() {
#endif
            metaChunkTemp.secretID = temp.chunk_id;
            metaChunkTemp.shareSize = temp.share_size;
            metaChunkTemp.secretSize = temp.chunk_size;
            metaChunkTemp.segID = temp.seg_id;
            metaChunkTemp.shareID = shareID;
            memcpy(metaChunkTemp.shareFP, temp.total_FP + (shareID * FP_SIZE), FP_SIZE);

#ifdef BREAKDOWN_ENABLED
            }, generate_meta_chunk_time);
#endif
            temp.share_id = shareID;

            obj->uploadObj_->add(temp, loop_index);

            if(metaSize[loop_index] + sizeof(metaNode) >= SECRET_SIZE_META) {
                printf("[collect] may overflow!!Exiting...\n");
                exit(-5);
            }
            // metaChunkBuffer structure: count<int> + [metaChunk_1, ... , metaChunk_n]
            memcpy(metaChunkBuffer[loop_index].get() + sizeof(int) + metaChunkCounter[loop_index] * sizeof(metaNode),
                   &metaChunkTemp, sizeof(metaNode));
            metaSize[loop_index] = metaSize[loop_index] + sizeof(metaNode);

            //Increase count
            metaChunkCounter[loop_index]++;

            /* IF SHARE_END, then clean up current metaChunkBuffer and add it to metaUploadObj to send to server */
            if(temp.end == 1) {
                printf("\n[collect] <%d> Share End\n", loop_index);
                printf("[collect] <%d> kmServerID = %d\n", loop_index, temp.kmCloudIndex);

#ifdef BREAKDOWN_ENABLED
                Logger::measure_time([&]() {
#endif
                    metaChunkUploadObj.type = SHARE_END;

                    obj->assignMetaShareHeader(metaChunkUploadObj, metaChunkID[loop_index],
                                               metaChunkCounter[loop_index], temp.seg_id, shareID, temp.kmCloudIndex);
                    metaChunkID[loop_index]--;

                    obj->assembleMetadataChunks(metaChunkUploadObj, metaChunkBuffer[loop_index].get(),
                                                metaChunkCounter[loop_index]);
#ifdef BREAKDOWN_ENABLED
                }, generate_meta_chunk_time);
#endif

                ++metaChunkCount[loop_index];
                obj->uploadObj_->addMeta(metaChunkUploadObj, loop_index);
            }

            // preserve shareID for future packing up metadata chunks
            int next_loop_index = obj->getNextStreamIndex(loop_index, obj->n_);
            shareIndex[next_loop_index] = shareIndex[loop_index];
            ++shareIndex[next_loop_index];
#endif
            ++loop_count;
            loop_index = next_loop_index;
        }
    }

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Encoder] <collect> metadata_handling time: is /%lf/ s\n", generate_meta_chunk_time);
    printf("[Time]===================\n\n");
#endif
    return nullptr;
}

/*
 * see if it's end of encoding file
 *
 */
void Encoder::indicateEnd()
{
    pthread_join(tid_[NUM_THREADS], NULL);
}

/*
 * constructor
 *
 * @param type - convergent dispersal type
 * @param n - total number of shares generated from a secret
 * @param m - reliability degree
 * @param kmServerCount - number of KM-assisted server (n - kmServerCount <=> original n)
 * @param r - confidentiality degree
 * @param securetype - encryption and hash type
 * @param uploaderObj - pointer link to uploader object
 *
 */
Encoder::Encoder(int type, int n, int m, int kmServerCount, int r, int securetype, Uploader *uploaderObj)
{

    /* initialization of variables */
    n_ = n;
    kmServerCount_ = kmServerCount;
    if(n_ - kmServerCount_ != TOTAL_SHARES_NUM) {
        printf("[Encoder] Mismatch setting detected. Please check your setting. \n");
        printf("[Encoder] Total number of shares set in Encoder macros is %d\n", TOTAL_SHARES_NUM);
        printf("[Encoder] Total number of shares set via Encoder constructor is %d\n", n_ - kmServerCount_);
        exit(-1);
    }
    nextAddIndex_ = 0;
    cryptoObj_ = (CryptoPrimitive **) malloc(sizeof(CryptoPrimitive *) * (NUM_THREADS + 1));
    inputbuffer_ = (MessageQueue<Chunk_t> **) malloc(sizeof(MessageQueue<Secret_Item_t> *) * NUM_THREADS);

    calc_inputbuffer_ = new MessageQueue<Chunk_t> *[NUM_THREADS];
    calc_outputbuffer_ = new MessageQueue<Chunk_t> *[NUM_THREADS];
    calc_cryptoObj_ = new CryptoPrimitive *[NUM_THREADS];

    /* initialization of objects - 2 threads */
    for(int i = 0; i < NUM_THREADS; ++i) {
        inputbuffer_[i] = new MessageQueue<Chunk_t>(QUEUE_SIZE);
        cryptoObj_[i] = new CryptoPrimitive(securetype);
        encodeObj_[i] = new CDCodec(type, n_ - kmServerCount_, m, r, cryptoObj_[i]);

        auto *temp = (param_encoder *) malloc(sizeof(param_encoder));
        temp->index = i;
        temp->obj = this;

        /* create encoding threads */
        pthread_create(&tid_[i], 0, &thread_handler, (void *) temp);
    }

    /* threads for calculating hashes */
    for(int i = 0; i < NUM_THREADS; ++i) {
        calc_inputbuffer_[i] = new MessageQueue<Chunk_t>(QUEUE_SIZE);
        calc_outputbuffer_[i] = new MessageQueue<Chunk_t>(QUEUE_SIZE);
        calc_cryptoObj_[i] = new CryptoPrimitive(securetype);
        auto *temp = (param_encoder *) malloc(sizeof(param_encoder));
        temp->index = i;
        temp->obj = this;

        /* create calculating hashes threads */
        pthread_create(&calc_tid_[i], 0, &thread_handler_hash, (void *) temp);
    }

    uploadObj_ = uploaderObj;
    cryptoObj_[NUM_THREADS] = new CryptoPrimitive(securetype);
    /* this encodeObj[NUM_THREADS] is used for encoding header in order to have n shares for n servers */
    /* `r + 1` used for making up for param settings loss due to added KM-assisted server */
    encodeObj_[NUM_THREADS] = new CDCodec(type, n_, m, r + 1, cryptoObj_[NUM_THREADS]);
    /* create collect thread */
    pthread_create(&tid_[NUM_THREADS], 0, &collect, (void *) this);
}

/*
 * destructor
 *
 */
Encoder::~Encoder()
{
    for(int i = 0; i < NUM_THREADS; i++) {
        delete cryptoObj_[i];
        delete encodeObj_[i];
        delete inputbuffer_[i];

        delete calc_inputbuffer_[i];
        delete calc_outputbuffer_[i];
        delete calc_cryptoObj_[i];
    }
    delete encodeObj_[NUM_THREADS];
    delete cryptoObj_[NUM_THREADS];

    delete[] calc_inputbuffer_;
    delete[] calc_outputbuffer_;
    delete[] calc_cryptoObj_;

    free(inputbuffer_);
    free(cryptoObj_);
}

/*
 * add function for sequentially add items to each encode buffer
 *
 * @param item - input object
 *
 */
int Encoder::add(Chunk_t &item)
{
    /* add item */
    inputbuffer_[nextAddIndex_]->push(item);

    /* increment the index */
    nextAddIndex_ = (nextAddIndex_ + 1) % NUM_THREADS;
    return 1;
}

/*
 * Assign the share_header of metadata chunk
 *
 * @param metaChunkUploadObj - the metadata chunk to be sent to uploader
 * @param metaChunkID - the ID of metadata chunk
 * @param counter - count the number of metaNodes
 * @param segID - the ID of segment
 * @param shareID - the ID of current share of a data chunk
 * @param kmCloudIndex - the index of Key Manager Server
 *
 */
void Encoder::assignMetaShareHeader(Uploader::ItemMeta_t &metaChunkUploadObj, int &metaChunkID, int &counter,
                                    int &segID, int &shareID, short &kmCloudIndex)
{
    metaChunkUploadObj.shareObj.share_header.secretID = metaChunkID;
    metaChunkUploadObj.shareObj.share_header.secretSize = sizeof(int) + counter * sizeof(metaNode);
    metaChunkUploadObj.shareObj.share_header.shareSize = sizeof(int) + counter * sizeof(metaNode);
    metaChunkUploadObj.shareObj.share_header.segID = segID;
    metaChunkUploadObj.shareObj.share_header.shareID = shareID;
    metaChunkUploadObj.kmCloudIndex = kmCloudIndex;
}

/*
 * Assemble metaNodes into metadata chunks
 *
 * @param metaChunkUploadObj - the metadata chunk to be sent to uploader
 * @param metaChunkBuffer - buffer of mataNodes
 * @param counter - count the number of metaNodes
 *
 */
void Encoder::assembleMetadataChunks(Uploader::ItemMeta_t &metaChunkUploadObj, unsigned char *metaChunkBuffer,
                                     int &counter)
{
    // update count in the head of metaChunkBuffer[loop_index].get()
    memcpy(metaChunkBuffer, &counter, sizeof(int));

    // add metaChunkBuffer[loop_index].get() into uploader Obj buffer
    memcpy(metaChunkUploadObj.shareObj.data, metaChunkBuffer, metaChunkUploadObj.shareObj.share_header.shareSize);

    /* metaChunkUploadObj.shareObj.share_header.shareFP <-> hash of metadata chunks*/
    this->cryptoObj_[NUM_THREADS]->generateHash((unsigned char *) metaChunkUploadObj.shareObj.data,
                                                metaChunkUploadObj.shareObj.share_header.shareSize,
                                                metaChunkUploadObj.shareObj.share_header.shareFP);
}

/*
 * collect file header
 *
 * @param header - file header to be collect and send it to Uploader
 *
 */
void Encoder::collect_header(FileHeader_t &header)
{
    /* copy file header information */
    header.file_shareMD_header.fileSize = header.file_header.fileSize;
    header.file_shareMD_header.numOfPastSecrets = 0;
    header.file_shareMD_header.sizeOfPastSecrets = 0;
    header.file_shareMD_header.numOfComingSecrets = 0;
    header.file_shareMD_header.sizeOfComingSecrets = 0;

    unsigned char tmp[header.file_header.fullNameSize * 32];
    int tmp_s;

    //encode pathname into shares for privacy
    unsigned char key[KEY_SIZE];
    memset(key, 0, KEY_SIZE);
    
    /* use encodeObj_[NUM_THREADS] to encode path name into n shares for n servers */
    this->encodeObj_[NUM_THREADS]->encoding(header.file_header.file_name, header.file_header.fullNameSize, tmp,
                                            &(tmp_s), key, true);
    header.file_header.fullNameSize = tmp_s;
    header.file_shareMD_header.fullNameSize = tmp_s;

#ifndef ENCODE_ONLY_MODE
    /* add the file header to each cloud's uploader buffer */
    for(int i = 0; i < this->n_; i++) {
        memcpy(header.encoded_file_name, tmp + i * tmp_s, tmp_s);
        // add to data_thread
        this->uploadObj_->collect_header(header, i + this->n_);
        // add to meta_thread
        this->uploadObj_->collect_header(header, i);
    }
#endif
}
