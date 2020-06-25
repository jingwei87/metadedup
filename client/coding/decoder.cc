/*
 * decoder.cc
 *
 */

#include "decoder.hh"

/*
 * thread handler for decode shares into secret
 *
 *
 */
void *Decoder::thread_handler(void *param)
{

    /* parse parameters */
    int index = ((param_decoder *) param)->index;
    Decoder *obj = ((param_decoder *) param)->obj;
    free(param);
    long countSize = 0;

    double decode_time = 0;

    /* main loop for decode shares into secret */
    ShareChunk_t temp;
    Secret_t input;
    while(true) {

        if(obj->inputbuffer_[index]->done_ && obj->inputbuffer_[index]->is_empty()) {
            // thread finished its mission, exit
            obj->outputbuffer_[index]->set_job_done();
            break;
        }

        /* get share objects */
        if(!obj->inputbuffer_[index]->pop(temp)) {
            continue;
        }

        /* decode shares */
        input.secretSize = temp.secretSize;
        countSize += input.secretSize;

        unsigned char *key;
#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        obj->decodeObj_[index]->decoding((unsigned char *) temp.data, temp.kShareIDList,
                                         temp.shareSize, temp.secretSize,
                                         (unsigned char *) input.data, key);
#ifdef BREAKDOWN_ENABLED
        }, decode_time);
#endif

        /* add secret into output buffer */
        obj->outputbuffer_[index]->push(input);
        if(countSize == obj->totalFileSize_) {
            printf("[Decoder] <thread_decoding:%d> Finish decoding!! Exiting...\n", index);
        }
    }
#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Decoder] <thread_decoding:%d> decode time: is /%lf/ s\n", index, decode_time);
    printf("[Time]===================\n\n");
#endif
    return NULL;
}

/*
 * collect thread for sequencially get secrets
 *
 */
void *Decoder::collect(void *param)
{

    /* parse parameters */
    char *buf = (char *) malloc(FWRITE_BUFFER_SIZE);
    Decoder *obj = (Decoder *) param;
    int count = 0;
    long countSize = 0;
    // out write pointer
    int out_wp = 0;
    bool job_done[DECODE_NUM_THREADS];
    for(bool &i : job_done) {
        i = false;
    }

    double collect_time = 0;
    /* main loop for get secrets */
    Secret_t temp;
    int loop_index = 0;
    while(true) {
        if(obj->outputbuffer_[loop_index]->done_ && obj->outputbuffer_[loop_index]->is_empty()) {
            job_done[loop_index] = true;
        }

        if(obj->check_all_job_done(job_done)) {
            // all jobs done, break for exiting
            break;
        }

        if(job_done[loop_index]) {
            loop_index = (loop_index + 1) % DECODE_NUM_THREADS;
        }

        /* extract secret object */
        if(!obj->outputbuffer_[loop_index]->pop(temp)) {
            continue;
        }
        loop_index = (loop_index + 1) % DECODE_NUM_THREADS;

#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        /* if write buffer full then write to file */
        if(out_wp + temp.secretSize > FWRITE_BUFFER_SIZE) {
            fwrite(buf, out_wp, 1, obj->fw_);
            out_wp = 0;
        }

        /* copy secret to write buffer */
        memcpy(buf + out_wp, temp.data, temp.secretSize);
        out_wp += temp.secretSize;
        countSize += temp.secretSize;

        /* if this is the last secret, write to file and  exit the collect */
        count++;

        if(countSize == obj->totalFileSize_) {
            if(out_wp > 0) {
                fwrite(buf, out_wp, 1, obj->fw_);
            }
        }
#ifdef BREAKDOWN_ENABLED
        }, collect_time);
#endif
    }
#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [Decoder] <collect> decode time: is /%lf/ s\n", collect_time);
    printf("[Time]===================\n\n");
#endif
    free(buf);
    return nullptr;
}

/*
 * decoder constructor
 *
 * @param type - convergent dispersal type
 * @param n - total number of shares created from a secret
 * @param m - reliability degree
 * @param kmServerCount - number of KM-assisted server (n - kmServerCount <=> original n)
 * @param r - confidentiality degree
 * @param securetype - encryption and hash type
 */
Decoder::Decoder(int type, int n, int m, int kmServerCount, int r, int securetype)
{
    int i;
    n_ = n;

    if(n - kmServerCount - m != NUM_OF_SHARES_NEEDED) {
        printf("[Decoder] Error setting!!! k is not equal to macros. Change both!\n");
        exit(-1);
    }

    /* initialization */
    cryptoObj_ = (CryptoPrimitive **) malloc(sizeof(CryptoPrimitive *) * n_);
    inputbuffer_ = (MessageQueue<ShareChunk_t> **) malloc(sizeof(MessageQueue<ShareChunk_t> *) * DECODE_NUM_THREADS);
    outputbuffer_ = (MessageQueue<Secret_t> **) malloc(sizeof(MessageQueue<Secret_t> *) * DECODE_NUM_THREADS);

    /* initialization for variables of each thread */
    for(i = 0; i < DECODE_NUM_THREADS; i++) {
        inputbuffer_[i] = new MessageQueue<ShareChunk_t>(DECODE_QUEUE_SIZE);
        outputbuffer_[i] = new MessageQueue<Secret_t>(DECODE_QUEUE_SIZE);
        cryptoObj_[i] = new CryptoPrimitive(securetype);
        decodeObj_[i] = new CDCodec(type, n - kmServerCount, m, r, cryptoObj_[i]);
        param_decoder *temp = (param_decoder *) malloc(sizeof(param_decoder));
        temp->index = i;
        temp->obj = this;

        /* create decode threads */
        pthread_create(&tid_[i], 0, &thread_handler, (void *) temp);
    }

    /* this decodeObj[DECODE_NUM_THREADS] is used for encoding header in order to have n shares for n servers */
    /* `r + 1` used for making up for param settings loss due to added KM-assisted server */
    decodeObj_[DECODE_NUM_THREADS] = new CDCodec(type, n, m, r + 1, cryptoObj_[0]);
    /* create collect thread */
    pthread_create(&tid_[DECODE_NUM_THREADS], 0, &collect, (void *) this);
}

/* 
 * test whether the decode thread returned
 */
int Decoder::indicateEnd()
{
    pthread_join(tid_[DECODE_NUM_THREADS], NULL);
    return 1;
}

/*
 * decoder destructor
 */
Decoder::~Decoder()
{
    for(int i = 0; i < DECODE_NUM_THREADS; i++) {
        delete (decodeObj_[i]);
        delete (cryptoObj_[i]);
        delete (inputbuffer_[i]);
        delete (outputbuffer_[i]);
    }
    delete decodeObj_[DECODE_NUM_THREADS];
    free(inputbuffer_);
    free(outputbuffer_);
    free(cryptoObj_);
}

/*
 * add interface for add item into decode input buffer
 *
 * @param item - the input object
 * @param index - the index of thread
 *
 */
int Decoder::add(ShareChunk_t *item, int index)
{
    inputbuffer_[index]->push(*item);
    return 1;
}

/*
 * set the file pointer
 *
 * @param fp - the output file pointer
 */
int Decoder::setFilePointer(FILE *fp)
{
    fw_ = fp;
    return 1;
}

/*
 * set the share list
 *
 * @param list - the share ID list indicate the shares come from which clouds
 */
int Decoder::setShareIDList(int *list)
{
    kShareIDList_ = list;
    return 1;
}

/*
 * pass the total secret number to decoder
 *
 * @param n - the total number of secrets in the file
 *
 */
int Decoder::setTotal(int totalSecrets)
{
    totalSecrets_ = totalSecrets;
    return 1;
}

/*
 * pass the file size to decoder
 *
 * @param totalFileSize - the total file size of file
 *
 */
int Decoder::setFileSize(long totalFileSize)
{
    totalFileSize_ = totalFileSize;
    return 1;
}

bool Decoder::check_all_job_done(const bool *job_done)
{
    for(int i = 0; i < DECODE_NUM_THREADS; ++i) {
        if(!job_done[i]) {
            return false;
        }
    }
    return true;
}
