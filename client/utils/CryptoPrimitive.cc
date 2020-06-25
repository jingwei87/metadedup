/*
 * CryptoPrimitive.cc
 */

#include "CryptoPrimitive.hh"

/*initialize the static variable*/
opensslLock_t *CryptoPrimitive::opensslLock_ = NULL;

/*
 * OpenSSL locking callback function
 */
void CryptoPrimitive::opensslLockingCallback_(int mode, int type, const char *file, int line)
{
#if OPENSSL_DEBUG
    CRYPTO_THREADID id;
    CRYPTO_THREADID_current(&id);
    /*'file' and 'line' are the file number of the function setting the lock. They can be useful for debugging.*/
    fprintf(stdout, "thread=%4ld, mode=%s, lock=%s, %s:%d\n", id.val, (mode & CRYPTO_LOCK) ? "l" : "u",
        (type & CRYPTO_READ) ? "r" : "w", file, line);
#endif

    if(mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(opensslLock_->lockList[type]));
        CryptoPrimitive::opensslLock_->cntList[type]++;
    } else {
        pthread_mutex_unlock(&(opensslLock_->lockList[type]));
    }
}

/*
 * get the id of the current thread
 *
 * @param id - the thread id <return>
 */
void CryptoPrimitive::opensslThreadID_(CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric(id, pthread_self());
}

/*
 * set up OpenSSL locks
 *
 * @return - a boolean value that indicates if the setup succeeds
 */
bool CryptoPrimitive::opensslLockSetup()
{
#if defined(OPENSSL_THREADS)
    fprintf(stdout, "OpenSSL lock setup started\n");

    opensslLock_ = (opensslLock_t *) malloc(sizeof(opensslLock_t));

    opensslLock_->lockList = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    opensslLock_->cntList = (long *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    fprintf(stdout, "cntList[i]:CRYPTO_get_lock_name(i)\n");
    for(int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(opensslLock_->lockList[i]), NULL);
        opensslLock_->cntList[i] = 0;
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        printf("%8ld:%s\n", opensslLock_->cntList[i], CRYPTO_get_lock_name(i));
#else
        printf("%8ld\n", opensslLock_->cntList[i]);
#endif
    }

    CRYPTO_THREADID_set_callback(&opensslThreadID_);
    CRYPTO_set_locking_callback(&opensslLockingCallback_);

    fprintf(stdout, "OpenSSL lock setup done\n");

    return 1;
#else
    fprintf(stdout, "Error: OpenSSL was not configured with thread support!\n");

    return 0;
#endif
}

/*
 * clean up OpenSSL locks
 *
 * @return - a boolean value that indicates if the cleanup succeeds
 */
bool CryptoPrimitive::opensslLockCleanup()
{
#if defined(OPENSSL_THREADS)
    CRYPTO_set_locking_callback(NULL);

    fprintf(stdout, "OpenSSL lock cleanup started\n");

    fprintf(stdout, "cntList[i]:CRYPTO_get_lock_name(i)\n");
    for(int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(opensslLock_->lockList[i]));
        //fprintf(stdout, "%8ld:%s\n", opensslLock_->cntList[i], CRYPTO_get_lock_name(i));
    }

    OPENSSL_free(opensslLock_->lockList);
    OPENSSL_free(opensslLock_->cntList);
    free(opensslLock_);

    fprintf(stdout, "OpenSSL lock cleanup done\n");

    return 1;
#else
    fprintf(stdout, "Error: OpenSSL was not configured with thread support!\n");

    return 0;
#endif
}

/*
 * constructor of CryptoPrimitive
 *
 * @param cryptoType - the type of CryptoPrimitive
 */
CryptoPrimitive::CryptoPrimitive(int cryptoType)
{
    cryptoType_ = cryptoType;

#if defined(OPENSSL_THREADS)
    /*check if opensslLockSetup() has been called to set up OpenSSL locks*/
    if(opensslLock_ == NULL) {
        fprintf(stdout, "Error: opensslLockSetup() was not called before initializing CryptoPrimitive instances\n");
        exit(1);
    }

    if(cryptoType_ == HIGH_SEC_PAIR_TYPE) {
        /*get the EVP_MD structure for SHA-256*/
        md_ = EVP_sha256();
        hashSize_ = 32;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);

        /**initializes cipher context cipherctx_*/
        EVP_CIPHER_CTX_init(&cipherctx_);
#else
        cipherctx_ = EVP_CIPHER_CTX_new();
        mdctx_ = EVP_MD_CTX_new();
#endif

        /*get the EVP_CIPHER structure for AES-256*/
        cipher_ = EVP_aes_256_cbc();
        keySize_ = 32;
        blockSize_ = 16;

        /*allocate a constant IV*/
        iv_ = (unsigned char *) malloc(sizeof(unsigned char) * blockSize_);
        memset(iv_, 0, blockSize_);
    }

    if(cryptoType_ == LOW_SEC_PAIR_TYPE) {

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);
        /*initializes cipher contex cipherctx_*/
        EVP_CIPHER_CTX_init(&cipherctx_);
#else
        cipherctx_ = EVP_CIPHER_CTX_new();
        mdctx_ = EVP_MD_CTX_new();
#endif

        /*get the EVP_MD structure for MD5*/
        md_ = EVP_md5();
        hashSize_ = 16;

        /*get the EVP_CIPHER structure for AES-128*/
        cipher_ = EVP_aes_128_cbc();
        keySize_ = 16;
        blockSize_ = 16;

        /*allocate a constant IV*/
        iv_ = (unsigned char *) malloc(sizeof(unsigned char) * blockSize_);
        memset(iv_, 0, blockSize_);

        fprintf(stdout, "\nA CryptoPrimitive based on a pair of MD5 and AES-128 has been constructed! \n");
        fprintf(stdout, "Parameters: \n");
        fprintf(stdout, "      hashSize_: %d \n", hashSize_);
        fprintf(stdout, "      keySize_: %d \n", keySize_);
        fprintf(stdout, "      blockSize_: %d \n", blockSize_);
        fprintf(stdout, "\n");
    }

    if(cryptoType_ == SHA256_TYPE) {
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);
#else
        mdctx_ = EVP_MD_CTX_new();
#endif
        /*get the EVP_MD structure for SHA-256*/
        md_ = EVP_sha256();
        hashSize_ = 32;

        keySize_ = -1;
        blockSize_ = -1;

        fprintf(stdout, "\nA CryptoPrimitive based on SHA-256 has been constructed! \n");
        fprintf(stdout, "Parameters: \n");
        fprintf(stdout, "      hashSize_: %d \n", hashSize_);
        fprintf(stdout, "\n");
    }

    if(cryptoType_ == SHA1_TYPE) {
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(&mdctx_);
#else
        mdctx_ = EVP_MD_CTX_new();
#endif
        /*get the EVP_MD structure for SHA-1*/
        md_ = EVP_sha1();
        hashSize_ = 20;

        keySize_ = -1;
        blockSize_ = -1;

        fprintf(stdout, "\nA CryptoPrimitive based on SHA-1 has been constructed! \n");
        fprintf(stdout, "Parameters: \n");
        fprintf(stdout, "      hashSize_: %d \n", hashSize_);
        fprintf(stdout, "\n");
    }

#else
    fprintf(stdout, "Error: OpenSSL was not configured with thread support!\n");
    exit(1);
#endif
}

/*
 * destructor of CryptoPrimitive
 */
CryptoPrimitive::~CryptoPrimitive()
{
    if((cryptoType_ == HIGH_SEC_PAIR_TYPE) || (cryptoType_ == LOW_SEC_PAIR_TYPE)) {
        /*clean up the digest context mdctx_ and free up the space allocated to it*/
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        EVP_MD_CTX_cleanup(&mdctx_);
        /**clean up the cipher context cipherctx_ and free up the space allocated to it */
        EVP_CIPHER_CTX_cleanup(&cipherctx_);
#else
        EVP_MD_CTX_free(mdctx_);
        EVP_CIPHER_CTX_free(cipherctx_);
#endif
        free(iv_);
    }

    if((cryptoType_ == SHA256_TYPE) || (cryptoType_ == SHA1_TYPE)) {
        /*clean up the digest context mdctx_ and free up the space allocated to it*/
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
        EVP_MD_CTX_cleanup(&mdctx_);
#else
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_free(mdctx_);
#endif
    }
}

/*
 * get the hash size
 *
 * @return - the hash size
 */
int CryptoPrimitive::getHashSize()
{
    return hashSize_;
}

/*
 * get the key size
 *
 * @return - the key size
 */
int CryptoPrimitive::getKeySize()
{
    return keySize_;
}

/*
 * get the size of the encryption block unit
 *
 * @return - the block size
 */
int CryptoPrimitive::getBlockSize()
{
    return blockSize_;
}

/*
 * generate the hash for the data stored in a buffer
 *
 * @param dataBuffer - the buffer that stores the data
 * @param dataSize - the size of the data
 * @param hash - the generated hash <return>
 *
 * @return - a boolean value that indicates if the hash generation succeeds
 */
bool CryptoPrimitive::generateHash(unsigned char *dataBuffer, const int &dataSize, unsigned char *hash)
{
    int hashSize;

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    EVP_DigestInit_ex(&mdctx_, md_, NULL);
    EVP_DigestUpdate(&mdctx_, dataBuffer, dataSize);
    EVP_DigestFinal_ex(&mdctx_, hash, (unsigned int *) &hashSize);
#else
    EVP_DigestInit_ex(mdctx_, md_, NULL);
    EVP_DigestUpdate(mdctx_, dataBuffer, dataSize);
    EVP_DigestFinal_ex(mdctx_, hash, (unsigned int *) &hashSize);
#endif

    if(hashSize != hashSize_) {
        fprintf(stdout,
                "Error: the size of the generated hash (%d bytes) does not match with the expected one (%d bytes)!\n",
                hashSize, hashSize_);

        return 0;
    }

    return 1;
}

/*
 * encrypt the data stored in a buffer with a key
 *
 * @param dataBuffer - the buffer that stores the data
 * @param dataSize - the size of the data
 * @param key - the key used to encrypt the data
 * @param ciphertext - the generated ciphertext <return>
 *
 * @return - a boolean value that indicates if the encryption succeeds
 */
bool CryptoPrimitive::encryptWithKey(unsigned char *dataBuffer, const int &dataSize, unsigned char *key,
                                     unsigned char *ciphertext)
{
    int ciphertextSize, ciphertextTailSize;

    if(dataSize % blockSize_ != 0) {
        fprintf(stdout,
                "Error: the size of the input data (%d bytes) is not a multiple of that of encryption block unit (%d bytes)!\n",
                dataSize,
                blockSize_);

        return 0;
    }

#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    EVP_EncryptInit_ex(&cipherctx_, cipher_, NULL, key, iv_);
    /*disable padding to ensure that the generated ciphertext has the same size as the input data*/
    EVP_CIPHER_CTX_set_padding(&cipherctx_, 0);
    EVP_EncryptUpdate(&cipherctx_, ciphertext, &ciphertextSize, dataBuffer, dataSize);
    EVP_EncryptFinal_ex(&cipherctx_, ciphertext + ciphertextSize, &ciphertextTailSize);
#else
    EVP_EncryptInit_ex(cipherctx_, cipher_, NULL, key, iv_);
    /*disable padding to ensure that the generated ciphertext has the same size as the input data*/
    EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
    EVP_EncryptUpdate(cipherctx_, ciphertext, &ciphertextSize, dataBuffer, dataSize);
    EVP_EncryptFinal_ex(cipherctx_, ciphertext + ciphertextSize, &ciphertextTailSize);
#endif

    ciphertextSize += ciphertextTailSize;

    if(ciphertextSize != dataSize) {
        fprintf(stdout,
                "Error: the size of the cipher output (%d bytes) does not match with that of the input (%d bytes)!\n",
                ciphertextSize, dataSize);

        return 0;
    }

    return 1;
}

/*
 * decrypt the data stored in a buffer with a key
 *
 * @param dataBuffer - the buffer that stores the data
 * @param dataSize - the size of the data
 * @param key - the key used to encrypt the data
 * @param ciphertext - the generated ciphertext <return>
 *
 * @return - a boolean value that indicates if the encryption succeeds
 */
bool CryptoPrimitive::decryptWithKey(unsigned char *ciphertext, const int &dataSize, unsigned char *key,
                                     unsigned char *dataBuffer)
{
    int plaintextSize, plaintextTailSize;

    if(dataSize % blockSize_ != 0) {
        fprintf(stdout,
                "Error: the size of the input data (%d bytes) is not a multiple of that of encryption block unit (%d bytes)!\n",
                dataSize,
                blockSize_);

        return 0;
    }
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    EVP_DecryptInit_ex(&cipherctx_, cipher_, NULL, key, iv_);
    EVP_CIPHER_CTX_set_padding(&cipherctx_, 0);
    EVP_DecryptUpdate(&cipherctx_, dataBuffer, &plaintextSize, ciphertext, dataSize);
    EVP_DecryptFinal_ex(&cipherctx_, dataBuffer + plaintextSize, &plaintextTailSize);
#else
    EVP_DecryptInit_ex(cipherctx_, cipher_, NULL, key, iv_);
    EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
    EVP_DecryptUpdate(cipherctx_, dataBuffer, &plaintextSize, ciphertext, dataSize);
    EVP_DecryptFinal_ex(cipherctx_, dataBuffer + plaintextSize, &plaintextTailSize);
#endif

    plaintextSize += plaintextTailSize;

    if(plaintextSize != dataSize) {
        fprintf(stdout,
                "Error: the size of the plaintext output (%d bytes) does not match with that of the original data (%d bytes)!\n",
                plaintextSize,
                dataSize);

        return 0;
    }

    return 1;
}