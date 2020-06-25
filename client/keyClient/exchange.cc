#include "exchange.hh"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
using namespace std;

/*
 * thread handler for calculating hash value
 *
 * @param param - parameters for keyEx thread
 */
void *KeyEx::thread_handler_hash(void *param)
{
    // Add time
    double generate_hash_time = 0;

    KeyEx *obj = ((param_keyex *) param)->obj;
    int index = ((param_keyex *) param)->index;
    free(param);

    Chunk_t temp;
    /* main loop for getting secrets and encode them into shares*/
    while(true) {

        if(obj->inputbuffer_[index]->done_ && obj->inputbuffer_[index]->is_empty()) {
            // thread finished its mission, exit
            obj->outputbuffer_[index]->set_job_done();
            break;
        }
        /* get an object from input buffer */
        if(!obj->inputbuffer_[index]->pop(temp)) {
            continue;
        }

#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
            // use total_FP for storing KEY_SIZE key temporarily
            obj->calc_cryptoObj_[index]->generateHash(temp.content, temp.chunk_size, temp.total_FP);
#ifdef BREAKDOWN_ENABLED
        }, generate_hash_time);
#endif

        /* add the object to output buffer */
        obj->outputbuffer_[index]->push(temp);
    }

#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [KeyEx] <thread_hash:%d> generate hash time: is /%lf/ s\n", index, generate_hash_time);
    printf("[Time]===================\n\n");
#endif

    pthread_exit(0);
}

/*
 *   <Deprecated>PS: DOES NOT WORK WITH CURRENT SEGMENT VERSION. Modify this if you want to use this thread
 *
 *   function : thread handler with chunk based hash
 *
 *   note : do the main jobs of key manager
 **/
void *KeyEx::threadHandlerChunk(void *param)
{

    KeyEx *obj = ((param_keyex *) param)->obj;
    free(param);

    /* hash temp buffer to store hash value from data chunk */
    auto hash_tmp = std::make_unique<unsigned char[]>(HASH_SIZE);

    /* key buffer */
    auto keyBuffer = std::make_unique<unsigned char[]>(KEY_SIZE);

    int segID = 0;
    boost::compute::detail::lru_cache<string, string> keyCache(LRU_CACHE_SIZE);
    string cache_key;
    string cache_value;

    int buffer_index = 0;

    /* main loop for processing batches */
    while(true) {
        Chunk_t temp;

        /* getting a batch item from input buffer */
        // codes below do not work. Change it if you need to use this thread function
        if(obj->outputbuffer_[buffer_index]->done_ && obj->outputbuffer_[buffer_index]->is_empty()) {
            // thread finished its mission, exit
            for(int i = 0; i < NUM_THREADS; ++i) {
                obj->encodeObj_->inputbuffer_[i]->set_job_done();
            }
            break;
        }

        if(!obj->outputbuffer_[buffer_index]->pop(temp)) {
            continue;
        }
        obj->outputbuffer_[buffer_index]->pop(temp);
        buffer_index = (buffer_index + 1) % KEYEX_NUM_THREADS;

        /* generate data chunk hash as MLE key */
        obj->cryptoObj_->generateHash(temp.content, temp.chunk_size, hash_tmp.get());

        if(obj->cacheType_ == ENABLE_LRU_CACHE) {
            // check from cache
            cache_key.assign((char *) hash_tmp.get(), HASH_SIZE);
            boost::optional<string> cached_value = keyCache.get(cache_key);
            if(cached_value.is_initialized()) {
                // cache hit
                memcpy(keyBuffer.get(), cached_value.get().c_str(), KEY_SIZE);
            } else {
                // cache miss
                /* perform key generation */
                obj->keyExchange(hash_tmp.get(), 1, keyBuffer.get(), obj->cryptoObj_, segID);

                //insert into cache
                cache_value.assign((char *) keyBuffer.get(), KEY_SIZE);
                keyCache.insert(cache_key, cache_value);
            }
        } else {
            /* perform key generation */
            obj->keyExchange(hash_tmp.get(), 1, keyBuffer.get(), obj->cryptoObj_, segID);
        }

        /* bind data with MLE-derived key for encoder module */
        if(temp.end == 1) {
            printf("[!>] [KM] chunk type: SHARE_END\n");
        }

        /* Each server send once immediately and sent it to encoder */
        memcpy(temp.total_FP, keyBuffer.get(), KEY_SIZE);

        obj->encodeObj_->add(temp);
        ++segID;
        if(temp.end == 1) {
            break;
        }
    }
    return nullptr;
}

/*
 *   function : thread handler with min_hash(Paper: REED)
 *
 *   note : do the main jobs of key manager
 **/
void *KeyEx::threadHandlerMinHash(void *param)
{
    KeyEx *obj = ((param_keyex *) param)->obj;
    int cloudIndex = ((param_keyex *) param)->index;
    free(param);
    uint64_t segSizeTemp = 0;
    int segID = 0;

    /* segment buffer to store incoming chunk */
    auto segBuffer = std::make_unique<unsigned char[]>(MAX_SEGMENT_SIZE + sizeof(Chunk_t));

    /* key buffer to store the exchanged hashes */
    auto keyBuffer = std::make_unique<unsigned char[]>(KEY_SIZE);

    /* variables used in main loop below */
    // cycle is used for printing the result of program
    int cycle = 0;
    Chunk_t temp;
    unsigned char mask[FP_SIZE];
    unsigned char current[FP_SIZE];
    int itemSize = sizeof(Chunk_t);
    int countChunkInSeg = 0;
    boost::compute::detail::lru_cache<string, string> keyCache(LRU_CACHE_SIZE);
    string cache_key;
    string cache_value;

    // Add time
    double exchange_key_time = 0;
    double segmentation_time = 0;
    double insert_time = 0;

    int buffer_index = 0;
    int kmServerIndex = -1;
    memset(mask, '0', HASH_SIZE);
    memset(current, 0xFF, HASH_SIZE);
    /* main loop for processing batches */
    while(true) {

        if(obj->outputbuffer_[buffer_index]->done_ && obj->outputbuffer_[buffer_index]->is_empty()) {
            // thread finished its mission, exit
            for(int i = 0; i < NUM_THREADS; ++i) {
                obj->encodeObj_->inputbuffer_[i]->set_job_done();
            }
            break;
        }

        if(!obj->outputbuffer_[buffer_index]->pop(temp)) {
            continue;
        }

#ifndef BREAKDOWN_ENABLED
        if(!TRACE_DRIVEN_FSL_ENABLED) {
            if(cycle % 1000 == 0 && countChunkInSeg == 0) {
                printf("\n[KeyEx] ======= [cycle=%d] ========\n", cycle);
            }
        }
#endif

#ifdef BREAKDOWN_ENABLED
        Logger::measure_time([&]() {
#endif
        buffer_index = (buffer_index + 1) % KEYEX_NUM_THREADS;

        /* record segment ID to make sure data can be restored */
        temp.seg_id = segID;

        memcpy(segBuffer.get() + countChunkInSeg * itemSize, &temp, itemSize);

        segSizeTemp += itemSize;
        ++countChunkInSeg;

        /* get minimum hash in a segment */
        int ret = memcmp(temp.total_FP, current, HASH_SIZE);
        if(ret < 0) {
            memcpy(current, temp.total_FP, HASH_SIZE);
        }

        // segment function from Encoder::collect()
        // use part of hash value to speed up calculation although it is not the whole converted value
        int metaFPInt = *(int *) temp.total_FP;
        int remainder = metaFPInt & (DIVISOR - 1);
        int ret_flag = 0;
        if(remainder == PATTERN) {
            ret_flag = 1;
        }

        /*
         * Chuan Qin wrote this line of code with no comments from REED system. Not sure what it really does
         * Leave it if you do not know what it is doing
         */
        int unknownCodeRet = memcmp(temp.total_FP + (HASH_SIZE - 9), mask, 9);
        /* Condition to start a new segment:
         *     1. time to start to a new segment and segment size is more than minimum segment size
         *     2. exceed maximum segment size
         *     3. unknownCodeRet == 0
         *     4. chunk end
         * */
        if((ret_flag == 1 && segSizeTemp >= MIN_SEGMENT_SIZE) || segSizeTemp > MAX_SEGMENT_SIZE ||
           unknownCodeRet == 0 || temp.end == 1) {
            /* clean up for this segment */
            kmServerIndex = obj->calculateKMServerIndex(current, obj->serverCount_);

            if(obj->cacheType_ == ENABLE_LRU_CACHE) {
                // check from cache
                cache_key.assign((char *) current, HASH_SIZE);
                boost::optional<string> cached_value = keyCache.get(cache_key);
                if(cached_value.is_initialized()) {
                    // cache hit
                    memcpy(keyBuffer.get(), cached_value.get().c_str(), KEY_SIZE);
                } else {
                    // cache miss
                    /* send the key batch to key manager server */
                    if(countChunkInSeg != 0) {
                        /* perform key generation */
                        obj->keyExchange(current, 1, keyBuffer.get(), obj->cryptoObj_, kmServerIndex);
                    }

                    //insert into cache
                    cache_value.assign((char *) keyBuffer.get(), KEY_SIZE);
                    keyCache.insert(cache_key, cache_value);
                }
            } else {
                /* send the key batch to key manager server */
#ifdef BREAKDOWN_ENABLED
                Logger::measure_time([&]() {
#endif
                    if(countChunkInSeg != 0) {
                        /* perform key generation */
                        obj->keyExchange(current, 1, keyBuffer.get(), obj->cryptoObj_, kmServerIndex);
                    }
#ifdef BREAKDOWN_ENABLED
                }, exchange_key_time);
#endif
            }
            /* prepare for next segment */
            segSizeTemp = 0;
            ++segID;
            memset(current, 0xFF, HASH_SIZE);
            /* get back the keys */
#ifndef BREAKDOWN_ENABLED
            if(!TRACE_DRIVEN_FSL_ENABLED) {
                if(cycle % 1000 == 0) {
                    printf("\n[KeyEx] [Cycle=%d] chunkCountInSeg = %d\n", cycle, countChunkInSeg);
                }
            }
#endif
            for(int i = 0; i < countChunkInSeg; i++) {
                memcpy(&temp, segBuffer.get() + i * itemSize, itemSize);
                /* map corresponding keys in key_batch to input correctly */
                memcpy(temp.total_FP, keyBuffer.get(), KEY_SIZE);
                temp.kmCloudIndex = kmServerIndex;
#ifdef BREAKDOWN_ENABLED
                Logger::measure_time([&]() {
#endif
                obj->encodeObj_->add(temp);
#ifdef BREAKDOWN_ENABLED
                }, insert_time);
#endif
            }

            countChunkInSeg = 0;
            ++cycle;
        }
#ifdef BREAKDOWN_ENABLED
        }, segmentation_time);
#endif
    }
#ifdef BREAKDOWN_ENABLED
    printf("\n[Time] ===================\n");
    fprintf(stderr, "[Time] [KeyEx] exchange_key time: is /%lf/ s\n", exchange_key_time);
    fprintf(stderr, "[Time] [KeyEx] segmentation time: is /%lf/ s\n", segmentation_time - exchange_key_time - insert_time);
    printf("[Time]===================\n\n");
#endif

    return nullptr;
}

/*
 * constructor of KeyEx
 *
 * @param obj - Encoder obj
 * @param secureType - secure type for cryptoObj_
 * @param kmSeverConf - Key Management Server data read from config file
 * @param charaType - type of chara
 * @param segType - VAR_SEG or FIX_SEG
 * @param kmServerType - STATIC_KM_SERVER or DYNAMIC_KM_SERVER
 * @param cacheType - ENABLE_LRU_CACHE or DISABLE_LRU_CACHE
 *
 */
KeyEx::KeyEx(Encoder *obj, int secureType, std::unique_ptr<KMServerConf[]> kmServerConf, int userID, int charaType,
             int segType, int kmServerType, int cacheType)
{
    uploadFlag = true;
    nextAddIndex_ = 0;

    /* initialization */
    rsa_ = RSA_new();
    ctx_ = BN_CTX_new();
    r_ = BN_new();
    inv_ = BN_new();
    mid_ = BN_new();
    h_ = BN_new();
    n_ = KEY_BATCH_SIZE;
    charaType_ = charaType;
    kmServerType_ = kmServerType;
    cacheType_ = cacheType;
    if(kmServerType_ != STATIC_KM_SERVER && kmServerType_ != DYNAMIC_KM_SERVER) {
        printf("[KeyEx] Critical error settings for KM Server Type!! Current setting = %d\n", kmServerType_);
        exit(-1);
    }
    if(cacheType_ != ENABLE_LRU_CACHE && cacheType_ != DISABLE_LRU_CACHE) {
        printf("[KeyEx] Critical error settings for LRU cache Type!! Current setting = %d\n", cacheType_);
        exit(-1);
    }
    encodeObj_ = obj;
    serverCount_ = obj->n_;

    record_ = (BIGNUM **) malloc(sizeof(BIGNUM *) * n_);
    for(int i = 0; i < n_; i++) {
        record_[i] = BN_new();
    }

    sock_ = new Ssl *[SEND_THREADS];

    inputbuffer_ = new MessageQueue<Chunk_t> *[KEYEX_NUM_THREADS];
    outputbuffer_ = new MessageQueue<Chunk_t> *[KEYEX_NUM_THREADS];
    calc_cryptoObj_ = new CryptoPrimitive *[KEYEX_NUM_THREADS];
    cryptoObj_ = new CryptoPrimitive(secureType);

    /* set segmentation type */
    if(charaType_ != CHARA_MIN_HASH) {
        segType_ = 0;
    } else if(charaType_ == CHARA_MIN_HASH) {
        segType_ = segType;
    }

    auto *temp = (param_keyex *) malloc(sizeof(param_keyex));
    temp->index = 0;
    temp->obj = this;
    readKeyFile();

    for(int i = 0; i < obj->n_; ++i) {
        sock_[i] = new Ssl((char *) kmServerConf[i].ip.c_str(), kmServerConf[i].port, userID);
    }

    for(int i = 0; i < KEYEX_NUM_THREADS; ++i) {
        auto *temp_obj = (param_keyex *) malloc(sizeof(param_keyex));
        temp_obj->index = i;
        temp_obj->obj = this;
        inputbuffer_[i] = new MessageQueue<Chunk_t>(CHUNK_QUEUE_NUM);
        outputbuffer_[i] = new MessageQueue<Chunk_t>(CHUNK_QUEUE_NUM);
        calc_cryptoObj_[i] = new CryptoPrimitive(secureType);
        /* create encoding threads */
        pthread_create(&calc_tid_[i], 0, &thread_handler_hash, (void *) temp_obj);
    }

    /* create key generation thread */
    if(charaType_ == CHARA_CHUNK_HASH) {

        pthread_create(&tid_, 0, &threadHandlerChunk, (void *) temp);
    } else if(charaType_ == CHARA_MIN_HASH) {

        pthread_create(&tid_, 0, &threadHandlerMinHash, (void *) temp);
    }

}

/*
    function : constructor of key exchange for force KM server thread to exit

    Yes, it is necessary!
    Do not delete this constructor unless you make changes about the whole design of this system and understand why
*/
KeyEx::KeyEx(int cloudNumber, int down_server_index, int down_server_num,
             std::unique_ptr<KMServerConf[]> kmServerConf, int userID, int kmServerType)
{
    uploadFlag = false;

    this->down_server_index_ = down_server_index;
    this->down_server_num_ = down_server_num;

    /* initialization */
    kmServerType_ = kmServerType;
    if(kmServerType_ != STATIC_KM_SERVER && kmServerType_ != DYNAMIC_KM_SERVER) {
        printf("[KeyEx] Critical error settings for KM Server Type!! Current setting = %d\n", kmServerType_);
        exit(-1);
    }

    if(kmServerType_ == STATIC_KM_SERVER) {
        printf("[KeyEx] STATIC_KM_SERVER is not supported in current version\n");
        exit(-1);
    }

    sock_ = new Ssl *[SEND_THREADS];

    for(int i = 0; i < cloudNumber; ++i) {
        if(i == down_server_index) {
            continue;
        }
        sock_[i] = new Ssl((char *) kmServerConf[i].ip.c_str(), kmServerConf[i].port, userID);
    }

    /* send indicator to end ssl connection */
    sendEndIndicator(cloudNumber);
}

KeyEx::~KeyEx()
{
    if(uploadFlag) {

        RSA_free(rsa_);
        BN_CTX_free(ctx_);
        BN_clear_free(r_);
        BN_clear_free(inv_);
        BN_clear_free(mid_);
        BN_clear_free(h_);
        BIO_free(key_);

        for(int i = 0; i < n_; i++) {

            BN_clear_free(record_[i]);
        }
        free(record_);
        for(int i = 0; i < SEND_THREADS; ++i) {
            delete sock_[i];
        }
        delete[] sock_;

        for(int i = 0; i < KEYEX_NUM_THREADS; ++i) {
            delete inputbuffer_[i];
            delete outputbuffer_[i];
            delete calc_cryptoObj_[i];
        }
        delete[] inputbuffer_;
        delete[] outputbuffer_;
        delete[] calc_cryptoObj_;
        delete cryptoObj_;
    } else {
        for(int i = 0; i < SEND_THREADS; ++i) {
            if(i == this->down_server_index_) {
                continue;
            }
            delete sock_[i];
        }
        delete[] sock_;
    }
}

void KeyEx::readKeyFile()
{

    key_ = BIO_new_file("./keys/public.pem", "r");
    PEM_read_bio_RSAPublicKey(key_, &rsa_, NULL, NULL);
}

void KeyEx::printBN(BIGNUM *input)
{

    char *str = BN_bn2hex(input);
    printf("%s\n", str);
}

void KeyEx::printBuf(unsigned char *buff, int size)
{

    BN_bin2bn(buff, size, mid_);
    char *str = BN_bn2hex(mid_);
    printf("%s\n", str);
}

/*
 *  function : procedure for remove blind in returned keys
 *  input :
 *      @param buff - input big number buffer<return>
 *      @param size - input big number size
 *      @param index - the index of recorded random number r
 **/
void KeyEx::elimination(unsigned char *buff, int size, int index)
{

    // 	convert buffer data into big number
    BN_bin2bn(buff, size, h_);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* openssl <= 1.1.0 */
    // 	compute inverse
    BN_mod_inverse(inv_, record_[index], rsa_->n, ctx_);
    // 	compute (h^(-1))d mod n
    BN_mod_mul(mid_, h_, inv_, rsa_->n, ctx_);
#else
    /* openssl >= 1.1.0 */
    // 	compute inverse
    const BIGNUM *n;
    RSA_get0_key(rsa_, &n, NULL, NULL);
    BN_mod_inverse(inv_, record_[index], n, ctx_);
    // 	compute (h^(-1))d mod n
    BN_mod_mul(mid_, h_, inv_, n, ctx_);
#endif

    // 	convert big number back to char data
    memset(buff, 0, size);
    BN_bn2bin(mid_, buff + (size - BN_num_bytes(mid_)));
}

/*
 *  function : procedure for verify returned keys
 *  input :
 *      @param original - the original hash value buffer
 *      @param buff - the buffer contains returned blinded key
 *      @param size - the size of hash value
 *  output :
 *      verify pass -> 0, verification fails -> others
 **/
int KeyEx::verify(unsigned char *original, unsigned char *buff, int size)
{

    // 	convert buffer data into big number
    BN_bin2bn(buff, size, h_);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* openssl <= 1.1.0 */
    //	compute h^e mod n */
    BN_mod_exp(mid_, h_, rsa_->e, rsa_->n, ctx_);
#else
    const BIGNUM *n;
    const BIGNUM *e;
    RSA_get0_key(rsa_, &n, &e, NULL);
    //	compute h^e mod n */
    BN_mod_exp(mid_, h_, e, n, ctx_);
#endif

    //	convert original data into big number
    BN_bin2bn(original, 32, h_);
    //	compare two numbers
    return BN_cmp(h_, mid_);
}

/*
 *  function : procedure for blind hash value
 *  input :
 *      @param hash_buf - input buffer storing hash
 *      @param size - the size of input hash
 *      @param ret_buf - the returned buffer holding blinded hash <return>
 *      @param index - the index of record random number r
 **/
void KeyEx::decoration(unsigned char *hash_buf, int size, unsigned char *ret_buf, int index)
{

    /* openssl <= 1.1.0 */
    //	random generate 256bits big number
    BN_pseudo_rand(record_[index], 256, -1, 0);
    //	convert buffer data into big number
    BN_bin2bn(hash_buf, size, h_);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    //	compute r^e mod n
    BN_mod_exp(mid_, record_[index], rsa_->e, rsa_->n, ctx_);
    //	compute h*r^e mod n
    BN_mod_mul(mid_, mid_, h_, rsa_->n, ctx_);
#else
    /* openssl >= 1.1.0 */
    const BIGNUM *n;
    const BIGNUM *e;
    RSA_get0_key(rsa_, &n, &e, NULL);
    //	compute r^e mod n
    BN_mod_exp(mid_, record_[index], e, n, ctx_);
    //	compute h*r^e mod n
    BN_mod_mul(mid_, mid_, h_, n, ctx_);
#endif

    //	convert the big number back to buffer data
    memset(ret_buf, 0, 128);
    BN_bn2bin(mid_, ret_buf + (128 - BN_num_bytes(mid_)));
    //	BN_bn2bin(mid_,ret_buf);
}

/*
 * function : main procedure for init key generation with key server
 *  input :
 *      @param hash_buf - the buffer holding hash values
 *      @param num - the number of hashes
 *      @param key_buf - the returned buffer contains keys <return>
 *      @param obj - the pointer to crypto object
 *      @param cloudIndex - index of KM server
 * */
void KeyEx::keyExchange(unsigned char *hash_buf, int num, unsigned char *key_buf, CryptoPrimitive *obj, int cloudIndex)
{

    // store all blinded hashes
    auto buffer = std::make_unique<unsigned char[]>(sizeof(int) + KEYEX_COMPUTE_SIZE * num);

    // Add num into the first of buffer data
    memcpy(buffer.get(), &num, sizeof(int));

    /* blind all hashes */
    for(int i = 0; i < num; i++) {

        decoration(hash_buf + i * HASH_SIZE, HASH_SIZE, buffer.get() + sizeof(int) + i * KEYEX_COMPUTE_SIZE, i);
    }

    if(kmServerType_ == STATIC_KM_SERVER) {
        // use server 0 as default KM server when using STATIC_KM_SERVER mode
        cloudIndex = 0;
    } else {
        // use DYNAMIC_KM_SERVER mode
        cloudIndex = cloudIndex % serverCount_;
    }

    /* sizeof(int) -> the number of hash, which is `num` in this case */
    sock_[cloudIndex]->genericSend((char *) buffer.get(), sizeof(int) + KEYEX_COMPUTE_SIZE * num);
    /* get back the blinded keys */
    sock_[cloudIndex]->genericDownload((char *) buffer.get(), KEYEX_COMPUTE_SIZE * num);

    /* remove the blind in returned keys */
    for(int i = 0; i < num; i++) {

        elimination(buffer.get() + i * KEYEX_COMPUTE_SIZE, KEYEX_COMPUTE_SIZE, i);
        /* hash 1024bit value back to 256bit(32Byte) */
        obj->generateHash(buffer.get() + i * KEYEX_COMPUTE_SIZE, KEYEX_COMPUTE_SIZE, key_buf + i * KEY_SIZE);
    }
}

/*
 *  function : add Chunk_t into input Ring Buffer
 *  input : item (Chunk_t struct)
 **/
void KeyEx::add(Chunk_t &item)
{

    /* add item */
    inputbuffer_[nextAddIndex_]->push(item);

    /* increment the index */
    nextAddIndex_ = (nextAddIndex_ + 1) % KEYEX_NUM_THREADS;
}

/*
 * send end indicator to KM server to exit. Used only for download procedure
 *
 * Only used in destructor in KeyEx
 *
 * */
bool KeyEx::sendEndIndicator(int cloudNumber)
{
    auto buffer = std::make_unique<char[]>(sizeof(int));

    // use `EXIT_KM_THREAD` to tell KM server to exit thread
    int indicator = EXIT_KM_THREAD;
    memcpy(buffer.get(), &indicator, sizeof(int));

    for(int i = 0; i < cloudNumber; ++i) {
        if(i == this->down_server_index_) {
            // skip downed-server
            continue;
        }
        sock_[i]->genericSend(buffer.get(), sizeof(int));
        printf("[KeyEx] [sendEndIndicator] <%d> Send indicator successfully\n", i);
    }

    return true;
}

/*
 * determine which server is the key manager server
 *
 * */
int KeyEx::calculateKMServerIndex(unsigned char *fingerprint, int &modulus)
{
    auto key_as_uint64 = *(uint64_t *) fingerprint;
    return key_as_uint64 % modulus;
}


#pragma clang diagnostic pop