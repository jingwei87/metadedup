/*
 * CDCodec.cc
 */

#include "CDCodec.hh"

/*
 * constructor of CDCodec
 *
 * @param CDType - convergent dispersal type
 * @param n - total number of shares generated from a secret
 * @param m - reliability degree (i.e. maximum number of lost shares that can be tolerated)
 * @param r - confidentiality degree (i.e. maximum number of shares from which nothing can be derived)
 * @param cryptoObj - the CryptoPrimitive instance for hash generation and data encryption
 */
CDCodec::CDCodec(int CDType, int n, int m, int r, CryptoPrimitive *cryptoObj)
{
    int i, j, sum;

    CDType_ = CDType;
    cryptoObj_ = cryptoObj;

    if(cryptoObj_ == NULL) {
        fprintf(stdout, "Error: no CryptoPrimitive instance for hash generation and data encryption!\n");
        exit(1);
    }

    if(CDType_ == CRSSS_TYPE) { /*CDCodec based on CRSSS*/
        if(n <= 0) {
            fprintf(stdout, "Error: n should be > 0!\n");
            exit(1);
        }
        if((m <= 0) || (m >= n)) {
            fprintf(stdout, "Error: m should be in (0, n)!\n");
            exit(1);
        }
        if(n - m <= 1) {
            fprintf(stdout, "Error: k = n -m should be > 1 for further providing confidentiality!\n");
            exit(1);
        }
        if((r <= 0) || (r >= n - m)) {
            fprintf(stdout, "Error: r should be in (0, n-m)!\n");
            exit(1);
        }
        n_ = n;
        m_ = m;
        k_ = n - m;
        r_ = r;

        /*initialize the secret word size*/
        bytesPerSecretWord_ = cryptoObj_->getHashSize();

        /*initialize the number of secret words per hash generation group and the number of bytes per group*/
        secretWordsPerGroup_ = k_ - r_;
        bytesPerGroup_ = bytesPerSecretWord_ * secretWordsPerGroup_;

        /*allocate a buffer for storing the input of the hash function*/
        hashInputBuffer_ = (unsigned char *) malloc(bytesPerSecretWord_ * secretWordsPerGroup_ + 1);
        /*allocate some space for storing the r hashes*/
        rHashes_ = (unsigned char *) malloc(sizeof(unsigned char) * bytesPerSecretWord_ * r_);

        /*allocate some space for storing the aligned secret*/
        alignedSecretBufferSize_ = MAX_SECRET_SIZE + bytesPerSecretWord_ * secretWordsPerGroup_;
        alignedSecretBuffer_ = (unsigned char *) malloc(sizeof(unsigned char) * alignedSecretBufferSize_);

        /*allocate some space for storing k data blocks to be encoded by Rabin's IDA*/
        erasureCodingDataSize_ =
                (bytesPerSecretWord_ * (alignedSecretBufferSize_ / (bytesPerSecretWord_ * secretWordsPerGroup_))) * k_;
        erasureCodingData_ = (unsigned char *) malloc(sizeof(unsigned char) * erasureCodingDataSize_);

        /*initialize the gf_t object using defaults*/
        bitsPerGFWord_ = 8; /*8 bits for the use of GF(256)*/
        if(!gf_init_easy(&gfObj_, bitsPerGFWord_)) {
            fprintf(stdout, "Error: bad gf specification\n");
            exit(1);
        }

        /*initialize the distribution matrix (i.e. the transpose of generator matrix) as an n * k Cauchy matrix*/
        distributionMatrix_ = (int *) malloc(sizeof(int) * n_ * k_);
        for(i = 0; i < n_; i++) {
            for(j = 0; j < k_; j++) {
                sum = i ^ (n_ + j);
                distributionMatrix_[k_ * i + j] = gfObj_.divide.w32(&gfObj_, 1, sum);
            }
        }

        /*allocate two k * k matrices for decoding*/
        squareMatrix_ = (int *) malloc(sizeof(int) * k_ * k_);
        inverseMatrix_ = (int *) malloc(sizeof(int) * k_ * k_);

        fprintf(stdout, "\nA CDCodec based on CRSSS has been constructed! \n");
        fprintf(stdout, "Parameters: \n");
        fprintf(stdout, "      n_: %d \n", n_);
        fprintf(stdout, "      m_: %d \n", m_);
        fprintf(stdout, "      k_: %d \n", k_);
        fprintf(stdout, "      r_: %d \n", r_);
        fprintf(stdout, "      bytesPerSecretWord_: %d \n", bytesPerSecretWord_);
        fprintf(stdout, "      bitsPerGFWord_: %d \n", bitsPerGFWord_);
        fprintf(stdout, "      distributionMatrix_: (see below) \n");
        for(i = 0; i < n_; i++) {
            fprintf(stdout, "         | ");
            for(j = 0; j < k_; j++) {
                fprintf(stdout, "%3d ", distributionMatrix_[k_ * i + j]);
            }

            fprintf(stdout, "| \n");
        }
        fprintf(stdout, "\n");
    }

    if((CDType_ == AONT_RS_TYPE) || (CDType_ == OLD_CAONT_RS_TYPE) ||
       (CDType_ == CAONT_RS_TYPE)) { /*CDCodec based on AONT-RS, old CAONT-RS, or CAONT-RS*/
        if(n <= 0) {
            fprintf(stdout, "Error: n should be > 0!\n");
            exit(1);
        }
        if((m <= 0) || (m >= n)) {
            fprintf(stdout, "Error: m should be in (0, n)!\n");
            exit(1);
        }
        if(n - m <= 1) {
            fprintf(stdout, "Error: k = n -m should be > 1 for further providing confidentiality!\n");
            exit(1);
        }
        if(r != n - m - 1) {
            fprintf(stdout, "Error: r should be = n - m - 1!\n");
            exit(1);
        }
        n_ = n;
        m_ = m;
        k_ = n - m;
        r_ = r;

        /*initialize the secret word size*/
        if(cryptoObj_->getHashSize() == cryptoObj_->getKeySize()) {
            bytesPerSecretWord_ = cryptoObj_->getHashSize();
        } else {
            fprintf(stdout,
                    "Error: the hash size is not equal to the key size in the input CryptoPrimitive instance!\n");
            exit(1);
        }

        /*allocate bytesPerSecretWord_-byte space for storing the key*/
        key_ = (unsigned char *) malloc(sizeof(unsigned char) * bytesPerSecretWord_);

        /*allocate some space for storing the aligned secret*/
        alignedSecretBufferSize_ = MAX_SECRET_SIZE + bytesPerSecretWord_ * k_;
        alignedSecretBuffer_ = (unsigned char *) malloc(sizeof(unsigned char) * alignedSecretBufferSize_);

        if((CDType_ == AONT_RS_TYPE) || (CDType_ == OLD_CAONT_RS_TYPE)) {
            /*allocate a word of size bytesPerSecretWord_ for storing an index*/
            wordForIndex_ = (unsigned char *) malloc(sizeof(unsigned char) * bytesPerSecretWord_);
            memset(wordForIndex_, 0, bytesPerSecretWord_);
        }

        if(CDType_ == CAONT_RS_TYPE) {
            /*allocate some space for storing the aligned secret*/
            alignedSizeConstant_ = (unsigned char *) malloc(sizeof(unsigned char) * alignedSecretBufferSize_);
            for(i = 0; i < alignedSecretBufferSize_; i++)
                alignedSizeConstant_[i] = i & 0xff;
        }

        /*allocate some space for storing k data blocks to be encoded by systematic Cauchy RS code*/
        erasureCodingDataSize_ =
                (bytesPerSecretWord_ * (((alignedSecretBufferSize_ / bytesPerSecretWord_) + 1) / k_)) * k_;
        erasureCodingData_ = (unsigned char *) malloc(sizeof(unsigned char) * erasureCodingDataSize_);

        /*initialize the gf_t object using defaults*/
        bitsPerGFWord_ = 8; /*8 bits for the use of GF(256)*/
        if(!gf_init_easy(&gfObj_, bitsPerGFWord_)) {
            fprintf(stdout, "Error: bad gf specification\n");
            exit(1);
        }

        /*initialize the distribution matrix (i.e. the transpose of generator matrix)*/
        distributionMatrix_ = (int *) malloc(sizeof(int) * n_ * k_);
        /*the submatrix of the first k row is a k * k indentity matrix*/
        for(i = 0; i < k_; i++) {
            for(j = 0; j < k_; j++) {
                if(i == j) {
                    distributionMatrix_[k_ * i + j] = 1;
                } else {
                    distributionMatrix_[k_ * i + j] = 0;
                }
            }
        }
        /*the submatrix of the last m row is an m * k Cauchy matrix*/
        for(i = 0; i < m_; i++) {
            for(j = 0; j < k_; j++) {
                sum = i ^ (m_ + j);
                distributionMatrix_[k_ * (k_ + i) + j] = gfObj_.divide.w32(&gfObj_, 1, sum);
            }
        }

        /*allocate two k * k matrices for decoding*/
        squareMatrix_ = (int *) malloc(sizeof(int) * k_ * k_);
        inverseMatrix_ = (int *) malloc(sizeof(int) * k_ * k_);
        if(CDType_ == AONT_RS_TYPE) {
            fprintf(stdout, "\nA CDCodec based on AONT-RS has been constructed! \n");
        }
        if(CDType_ == OLD_CAONT_RS_TYPE) {
            fprintf(stdout, "\nA CDCodec based on old CAONT-RS has been constructed! \n");
        }
        if(CDType_ == CAONT_RS_TYPE) {
            fprintf(stdout, "\nA CDCodec based on CAONT-RS has been constructed! \n");
        }
        fprintf(stdout, "Parameters: \n");
        fprintf(stdout, "      n_: %d \n", n_);
        fprintf(stdout, "      m_: %d \n", m_);
        fprintf(stdout, "      k_: %d \n", k_);
        fprintf(stdout, "      r_: %d \n", r_);
        fprintf(stdout, "      bytesPerSecretWord_: %d \n", bytesPerSecretWord_);
        fprintf(stdout, "      bitsPerGFWord_: %d \n", bitsPerGFWord_);
        fprintf(stdout, "      distributionMatrix_: (see below) \n");
        for(i = 0; i < n_; i++) {
            fprintf(stdout, "         | ");
            for(j = 0; j < k_; j++) {
                fprintf(stdout, "%3d ", distributionMatrix_[k_ * i + j]);
            }

            fprintf(stdout, "| \n");
        }
        fprintf(stdout, "\n");
    }
}

/* 
 * destructor of CDCodec 
 */
CDCodec::~CDCodec()
{
    if(CDType_ == CRSSS_TYPE) { /*CDCodec based on CRSSS*/
        free(hashInputBuffer_);
        free(rHashes_);

        free(alignedSecretBuffer_);

        free(erasureCodingData_);

        /*free the gf_t object*/
        gf_free(&gfObj_, 1);

        free(distributionMatrix_);

        free(squareMatrix_);
        free(inverseMatrix_);
    }

    if((CDType_ == AONT_RS_TYPE) || (CDType_ == OLD_CAONT_RS_TYPE) ||
       (CDType_ == CAONT_RS_TYPE)) { /*CDCodec based on AONT-RS, old CAONT-RS, or CAONT-RS*/
        free(key_);

        free(alignedSecretBuffer_);

        if((CDType_ == AONT_RS_TYPE) || (CDType_ == OLD_CAONT_RS_TYPE)) {
            free(wordForIndex_);
        }

        if(CDType_ == CAONT_RS_TYPE) {
            free(alignedSizeConstant_);
        }

        free(erasureCodingData_);

        /*free the gf_t object*/
        gf_free(&gfObj_, 1);

        free(distributionMatrix_);

        free(squareMatrix_);
        free(inverseMatrix_);
    }
}

/*
 * invert the square matrix squareMatrix_ into inverseMatrix_ in GF
 *
 * @return - a boolean value that indicates if the square matrix squareMatrix_ is invertible
 */
bool CDCodec::squareMatrixInverting()
{
    int matrixSize;
    int rowStartIndex1, rowStartIndex2;
    int tmp, multFactor;
    int i, j, h, l;

    matrixSize = k_ * k_;

    /*first store an identity matrix in inverseMatrix_*/
    i = 0;
    while(i < matrixSize) {
        if(i / k_ == i % k_) {
            inverseMatrix_[i] = 1;
        } else {
            inverseMatrix_[i] = 0;
        }

        i++;
    }

    /*convert squareMatrix_ into an upper triangular matrix*/
    for(i = 0; i < k_; i++) {
        rowStartIndex1 = k_ * i;

        /*if the i-th element in the i-th row is zero, we need to swap the i-th row with a row (below it) 
          whose i-th element is non-zero*/
        if(squareMatrix_[rowStartIndex1 + i] == 0) {
            j = i + 1;
            while((j < k_) && (squareMatrix_[k_ * j + i] == 0))
                j++;
            /*if we cannot find such a row below the i-th row, we can judge that squareMatrix_ is noninvertible*/
            if(j == k_) {
                return 0;
            }

            /*swap the i-th row with the j-th row for both squareMatrix_ and inverseMatrix_*/
            rowStartIndex2 = k_ * j;

            for(h = 0; h < k_; h++) {
                tmp = squareMatrix_[rowStartIndex1 + h];
                squareMatrix_[rowStartIndex1 + h] = squareMatrix_[rowStartIndex2 + h];
                squareMatrix_[rowStartIndex2 + h] = tmp;

                /*do the same for inverseMatrix_*/
                tmp = inverseMatrix_[rowStartIndex1 + h];
                inverseMatrix_[rowStartIndex1 + h] = inverseMatrix_[rowStartIndex2 + h];
                inverseMatrix_[rowStartIndex2 + h] = tmp;
            }
        }

        tmp = squareMatrix_[rowStartIndex1 + i];
        /*if the i-th element in the i-th row is not equal to 1, divide each element in this row by the i-th element*/
        if(tmp != 1) {
            multFactor = gfObj_.divide.w32(&gfObj_, 1, tmp);

            for(j = 0; j < k_; j++) {
                squareMatrix_[rowStartIndex1 + j] = gfObj_.multiply.w32(&gfObj_,
                                                                        squareMatrix_[rowStartIndex1 + j], multFactor);

                /*do the same for inverseMatrix_*/
                inverseMatrix_[rowStartIndex1 + j] = gfObj_.multiply.w32(&gfObj_,
                                                                         inverseMatrix_[rowStartIndex1 + j],
                                                                         multFactor);
            }
        }

        /*multiply the i-th row with a factor and add it to each row below it such that the i-th element in each row becomes zero*/
        for(j = i + 1; j < k_; j++) {
            rowStartIndex2 = k_ * j;
            h = rowStartIndex2 + i;

            if(squareMatrix_[h] !=
               0) { /*we need to do this when the i-th element in the j-th row is not equal to zero*/
                if(squareMatrix_[h] == 1) {
                    for(l = 0; l < k_; l++) {
                        squareMatrix_[rowStartIndex2 + l] ^= squareMatrix_[rowStartIndex1 + l];

                        /*do the same for inverseMatrix_*/
                        inverseMatrix_[rowStartIndex2 + l] ^= inverseMatrix_[rowStartIndex1 + l];
                    }
                } else {
                    multFactor = squareMatrix_[h];

                    for(l = 0; l < k_; l++) {
                        squareMatrix_[rowStartIndex2 + l] ^= gfObj_.multiply.w32(&gfObj_,
                                                                                 squareMatrix_[rowStartIndex1 + l],
                                                                                 multFactor);

                        /*do the same for inverseMatrix_*/
                        inverseMatrix_[rowStartIndex2 + l] ^= gfObj_.multiply.w32(&gfObj_,
                                                                                  inverseMatrix_[rowStartIndex1 + l],
                                                                                  multFactor);
                    }
                }
            }
        }
    }

    /*based on the upper triangular matrix, make squareMatrix_ become an identity matrix. 
      then, inverseMatrix_ become the final inverse matrix*/
    for(i = k_ - 1; i >= 0; i--) {
        rowStartIndex1 = k_ * i;

        for(j = 0; j < i; j++) {
            rowStartIndex2 = k_ * j;
            h = rowStartIndex2 + i;

            if(squareMatrix_[h] !=
               0) { /*we need to do this when the i-th element in the j-th row is not equal to zero*/
                if(squareMatrix_[h] == 1) {
                    for(l = 0; l < k_; l++) {
                        /*squareMatrix_[rowStartIndex2+l] ^= squareMatrix_[rowStartIndex1+l];*/

                        /*do the same for inverseMatrix_	*/
                        inverseMatrix_[rowStartIndex2 + l] ^= inverseMatrix_[rowStartIndex1 + l];
                    }
                } else {
                    multFactor = squareMatrix_[h];

                    for(l = 0; l < k_; l++) {
                        /*squareMatrix_[rowStartIndex2+l] ^= gfObj_.multiply.w32(&gfObj_, 
                          squareMatrix_[rowStartIndex1+l], multFactor);*/

                        /*do the same for inverseMatrix_*/
                        inverseMatrix_[rowStartIndex2 + l] ^= gfObj_.multiply.w32(&gfObj_,
                                                                                  inverseMatrix_[rowStartIndex1 + l],
                                                                                  multFactor);
                    }
                }

                /*we simply zero this element since squareMatrix_ will eventually become an identity matrix*/
                squareMatrix_[h] = 0;
            }
        }
    }

    return 1;
}

/*
 * encode a secret into n shares using CRSSS
 *
 * @param secretBuffer - a buffer that stores the secret
 * @param secretSize - the size of the secret
 * @param shareBuffer - a buffer for storing the n generated shares <return>
 * @param shareSize - the size of each share <return>
 *
 * @return - a boolean value that indicates if the encoding succeeds
 */
bool CDCodec::crsssEncoding(unsigned char *secretBuffer, int secretSize, unsigned char *shareBuffer, int *shareSize,
                            unsigned char *keyBuffer)
{
    int numOfGroups, alignedSecretSize;
    int coef;
    int i, j;

    /*align the secret size into alignedSecretSize*/
    if((secretSize % bytesPerGroup_) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize = bytesPerGroup_ * ((secretSize / bytesPerGroup_) + 1);
    }
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }

    /*deduce the share size into shareSize*/
    numOfGroups = alignedSecretSize / bytesPerGroup_;
    (*shareSize) = bytesPerSecretWord_ * numOfGroups;
    if(erasureCodingDataSize_ < (*shareSize) * k_) {
        fprintf(stderr, "Error: please use an internal erasureCodingData_[] of size >= %d bytes!\n", (*shareSize) * k_);

        return 0;
    }

    /*copy the secret from secretBuffer to alignedSecretBuffer_*/
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if(alignedSecretSize != secretSize) {
        memset(alignedSecretBuffer_ + secretSize, 0, alignedSecretSize - secretSize);
    }

    /*Step 1: generate r hashes from each group of k - r secret words, and 
      append the k - r secret words and the r hashes to k different data blocks, respectively*/

    for(i = 0; i < numOfGroups; i++) {
        /*generate r hashes from the group of k - r secret words*/
        for(j = 0; j < r_; j++) {
            memcpy(hashInputBuffer_, alignedSecretBuffer_ + bytesPerGroup_ * i, bytesPerGroup_);
            /*add a constant seed for imitating a different hash function*/
            hashInputBuffer_[bytesPerGroup_] = (unsigned char) j;

            if(!cryptoObj_->generateHash(hashInputBuffer_, bytesPerGroup_ + 1, rHashes_ + bytesPerSecretWord_ * j)) {
                fprintf(stderr, "Error: fail in the hash calculation!\n");

                return 0;
            }
        }

        /*append the k - r secret words to k - r different data blocks, respectively*/
        for(j = 0; j < secretWordsPerGroup_; j++) {
            memcpy(erasureCodingData_ + (*shareSize) * j + bytesPerSecretWord_ * i,
                   alignedSecretBuffer_ + bytesPerGroup_ * i + bytesPerSecretWord_ * j, bytesPerSecretWord_);
        }

        /*append the r hashes to other r different data blocks, respectively*/
        for(j = 0; j < r_; j++) {
            memcpy(erasureCodingData_ + (*shareSize) * (secretWordsPerGroup_ + j) + bytesPerSecretWord_ * i,
                   rHashes_ + bytesPerSecretWord_ * j, bytesPerSecretWord_);
        }
    }

    /*Step 2: encode the k data blocks of size shareSize into n shares using Rabin's IDA*/
    for(i = 0; i < n_; i++) {
        for(j = 0; j < k_; j++) {
            coef = distributionMatrix_[k_ * i + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * i, coef, (*shareSize), 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * i, coef, (*shareSize), 1);
            }
        }
    }

    return 1;
}

/*
 * decode the secret from k = n - m shares using CRSSS
 *
 * @param shareBuffer - a buffer that stores the k shares 
 * @param kShareIDList - a list that stores the IDs of the k shares
 * @param shareSize - the size of each share 
 * @param secretSize - the size of the secret
 * @param secretBuffer - a buffer for storing the secret <return>
 *
 * @return - a boolean value that indicates if the decoding succeeds
 */
bool CDCodec::crsssDecoding(unsigned char *shareBuffer, int *kShareIDList, int shareSize,
                            int secretSize, unsigned char *secretBuffer, unsigned char *keyBuffer)
{
    int numOfGroups, alignedSecretSize;
    int coef;
    int i, j;

    if((shareSize % bytesPerSecretWord_) != 0) {
        fprintf(stderr,
                "Error: the share size (i.e. %d bytes) should be a multiple of secret word size (i.e. %d bytes)!\n",
                shareSize, bytesPerSecretWord_);

        return 0;
    }
    if(erasureCodingDataSize_ < shareSize * k_) {
        fprintf(stderr, "Error: please use an internal erasureCodingData_[] of size >= %d bytes!\n", shareSize * k_);

        return 0;
    }

    numOfGroups = shareSize / bytesPerSecretWord_;
    alignedSecretSize = bytesPerGroup_ * numOfGroups;
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }
    if(secretSize > alignedSecretSize) {
        fprintf(stderr, "Error: the input secret size (%d bytes) cannot exceed %d bytes!\n", secretSize,
                alignedSecretSize);

        return 0;
    }

    /*store the k rows (corresponding to the k shares) of the distribution matrix into squareMatrix_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            squareMatrix_[k_ * i + j] = distributionMatrix_[k_ * kShareIDList[i] + j];
        }
    }

    /*invert squareMatrix_ into inverseMatrix_*/
    if(!squareMatrixInverting()) {
        fprintf(stderr, "Error: a k * k submatrix of the distribution matrix is noninvertible!\n");

        return 0;
    }

    /*perform IDA decoding*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            coef = inverseMatrix_[k_ * i + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 1);
            }
        }
    }

    /*check the integrity of each group of k - r secret words using the corresponding r hashes, and also restore the secret*/
    for(i = 0; i < numOfGroups; i++) {
        /*copy the group of k - r secret words from erasureCodingData_ to alignedSecretBuffer_*/
        for(j = 0; j < secretWordsPerGroup_; j++) {
            memcpy(alignedSecretBuffer_ + bytesPerGroup_ * i + bytesPerSecretWord_ * j,
                   erasureCodingData_ + shareSize * j + bytesPerSecretWord_ * i, bytesPerSecretWord_);
        }

        /*generate r hashes from the group of k - r secret words, and then compare them with the stored ones, respectively*/
        for(j = 0; j < r_; j++) {
            /*generate the hash from the group of the k - r secret words*/
            memcpy(hashInputBuffer_, alignedSecretBuffer_ + bytesPerGroup_ * i, bytesPerGroup_);
            /*add a constant seed for imitating a different hash function*/
            hashInputBuffer_[bytesPerGroup_] = (unsigned char) j;
            if(!cryptoObj_->generateHash(hashInputBuffer_, bytesPerGroup_ + 1, rHashes_ + bytesPerSecretWord_ * j)) {
                fprintf(stderr, "Error: fail in the hash calculation!\n");

                return 0;
            }

            /*check if the generated hash is the same as the stored hash*/
            if(memcmp(erasureCodingData_ + shareSize * (secretWordsPerGroup_ + j) + bytesPerSecretWord_ * i,
                      rHashes_ + bytesPerSecretWord_ * j, bytesPerSecretWord_)
               != 0) {
                fprintf(stderr, "Error: fail in integrity checking!\n");

                return 0;
            }
        }
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return 1;
}

/*
 * encode a secret into n shares using AONT-RS (proposed by Jason K. Resch and James S. Plank)
 *
 * @param secretBuffer - a buffer that stores the secret
 * @param secretSize - the size of the secret
 * @param shareBuffer - a buffer for storing the n generated shares <return>
 * @param shareSize - the size of each share <return>
 *
 * @return - a boolean value that indicates if the encoding succeeds
 */
bool CDCodec::aontRSEncoding(unsigned char *secretBuffer, int secretSize,
                             unsigned char *shareBuffer, int *shareSize, unsigned char *keyBuffer)
{
    int alignedSecretSize, numOfSecretWords;
    int coef;
    int i, j;

    /*align the secret size into alignedSecretSize*/
    if(((secretSize + bytesPerSecretWord_) % (bytesPerSecretWord_ * k_)) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize =
                (bytesPerSecretWord_ * k_) * (((secretSize + bytesPerSecretWord_) / (bytesPerSecretWord_ * k_)) + 1) -
                bytesPerSecretWord_;
    }
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }

    /*deduce the share size into shareSize*/
    numOfSecretWords = alignedSecretSize / bytesPerSecretWord_;
    (*shareSize) = bytesPerSecretWord_ * ((numOfSecretWords + 1) / k_);

    /*copy the secret from secretBuffer to alignedSecretBuffer_*/
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if(alignedSecretSize != secretSize) {
        memset(alignedSecretBuffer_ + secretSize, 0, alignedSecretSize - secretSize);
    }

    /*Step 1: generate an AONT package (containing numOfSecretWords + 1 words) from the secret, and 
      store it into erasureCodingData_*/

    /*+a) generate each of the first numOfSecretWords AONT words, and store it into erasureCodingData_*/

    /*generate a random key*/
    srand48(time(0));
    for(i = 0; i < bytesPerSecretWord_; i++) {
        key_[i] = lrand48() % 256;
    }

    /*generate each of the first numOfSecretWords AONT words with the random key*/
    for(i = 0; i < numOfSecretWords; i++) {
        /*store the index i into wordForIndex_*/
        wordForIndex_[0] = (unsigned char) i;
        wordForIndex_[1] = (unsigned char) (i >> 8);
        wordForIndex_[2] = (unsigned char) (i >> 16);
        wordForIndex_[3] = (unsigned char) (i >> 24);

        /*encrypt the index i with the random key, and temporarily store the ciphertext in erasureCodingData_*/
        if(!cryptoObj_->encryptWithKey(wordForIndex_, bytesPerSecretWord_, key_,
                                       erasureCodingData_ + bytesPerSecretWord_ * i)) {
            fprintf(stderr, "Error: fail in the data encryption!\n");

            return 0;
        }

        /*the AONT word is obtained by XORing the ciphertext with the secret word*/
        coef = 1;
        gfObj_.multiply_region.w32(&gfObj_, alignedSecretBuffer_ + bytesPerSecretWord_ * i,
                                   erasureCodingData_ + bytesPerSecretWord_ * i, coef, bytesPerSecretWord_, 1);
    }

    /*+b) generate the last AONT word from the first numOfSecretWords AONT words, and store it into erasureCodingData_*/

    /*generate a hash from the first numOfSecretWords AONT words, and temporarily store it into erasureCodingData_*/
    if(!cryptoObj_->generateHash(erasureCodingData_, alignedSecretSize, erasureCodingData_ + alignedSecretSize)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*the last AONT word is obtained by XORing the hash with the previous random key for encryption*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, key_, erasureCodingData_ + alignedSecretSize, coef, bytesPerSecretWord_, 1);

    /*Step 2: generate the n shares from  the AONT package using systematic Cauchy RS code*/

    /*directly copy the AONT package from erasureCodingData_ to shareBuffer as the first k shares*/
    memcpy(shareBuffer, erasureCodingData_, alignedSecretSize + bytesPerSecretWord_);

    /*generate only the last m shares from the AONT package*/
    for(i = 0; i < m_; i++) {
        for(j = 0; j < k_; j++) {
            coef = distributionMatrix_[k_ * (k_ + i) + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * (k_ + i), coef, (*shareSize), 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * (k_ + i), coef, (*shareSize), 1);
            }
        }
    }

    return 1;
}

/*
 * decode the secret from k = n - m shares using AONT-RS (proposed by Jason K. Resch and James S. Plank)
 *
 * @param shareBuffer - a buffer that stores the k shares 
 * @param kShareIDList - a list that stores the IDs of the k shares
 * @param shareSize - the size of each share 
 * @param secretSize - the size of the secret
 * @param secretBuffer - a buffer for storing the secret <return>
 *
 * @return - a boolean value that indicates if the decoding succeeds
 */
bool CDCodec::aontRSDecoding(unsigned char *shareBuffer, int *kShareIDList, int shareSize,
                             int secretSize, unsigned char *secretBuffer, unsigned char *keyBuffer)
{
    int alignedSecretSize, numOfSecretWords;
    int coef;
    int i, j;

    if((shareSize % bytesPerSecretWord_) != 0) {
        fprintf(stderr,
                "Error: the share size (i.e. %d bytes) should be a multiple of secret word size (i.e. %d bytes)!\n",
                shareSize, bytesPerSecretWord_);

        return 0;
    }
    if(erasureCodingDataSize_ < shareSize * k_) {
        fprintf(stderr, "Error: please use an internal erasureCodingData_[] of size >= %d bytes!\n", shareSize * k_);

        return 0;
    }

    alignedSecretSize = shareSize * k_ - bytesPerSecretWord_;
    numOfSecretWords = alignedSecretSize / bytesPerSecretWord_;
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }
    if(secretSize > alignedSecretSize) {
        fprintf(stderr, "Error: the input secret size (%d bytes) cannot exceed %d bytes!\n", secretSize,
                alignedSecretSize);

        return 0;
    }

    /*store the k rows (corresponding to the k shares) of the distribution matrix into squareMatrix_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            squareMatrix_[k_ * i + j] = distributionMatrix_[k_ * kShareIDList[i] + j];
        }
    }

    /*invert squareMatrix_ into inverseMatrix_*/
    if(!squareMatrixInverting()) {
        fprintf(stderr, "Error: a k * k submatrix of the distribution matrix is noninvertible!\n");

        return 0;
    }

    /*perform RS decoding and obtain the AONT package in erasureCodingData_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            coef = inverseMatrix_[k_ * i + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 1);
            }
        }
    }

    /*generate a hash from the first numOfSecretWords AONT words, and temporarily store it into key_*/
    if(!cryptoObj_->generateHash(erasureCodingData_, alignedSecretSize, key_)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*the key later used for encryption is obtained by XORing the generated hash with the last AONT word*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + alignedSecretSize, key_, coef, bytesPerSecretWord_, 1);

    /*generate each of the numOfSecretWords aligned secret words, and store it into alignedSecretBuffer_*/
    for(i = 0; i < numOfSecretWords; i++) {
        /*store the index i into wordForIndex_*/
        wordForIndex_[0] = (unsigned char) i;
        wordForIndex_[1] = (unsigned char) (i >> 8);
        wordForIndex_[2] = (unsigned char) (i >> 16);
        wordForIndex_[3] = (unsigned char) (i >> 24);

        /*encrypt the index i with the key, and temporarily store the ciphertext in alignedSecretBuffer_*/
        if(!cryptoObj_->encryptWithKey(wordForIndex_, bytesPerSecretWord_, key_,
                                       alignedSecretBuffer_ + bytesPerSecretWord_ * i)) {
            fprintf(stderr, "Error: fail in the data encryption!\n");

            return 0;
        }

        /*the aligned secret word is obtained by XORing the ciphertext with the AONT word*/
        coef = 1;
        gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + bytesPerSecretWord_ * i,
                                   alignedSecretBuffer_ + bytesPerSecretWord_ * i, coef, bytesPerSecretWord_, 1);
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return 1;
}

/*
 * encode a secret into n shares using old CAONT-RS (proposed in the HotStorage '14 paper)
 *
 * @param secretBuffer - a buffer that stores the secret
 * @param secretSize - the size of the secret
 * @param shareBuffer - a buffer for storing the n generated shares <return>
 * @param shareSize - the size of each share <return>
 *
 * @return - a boolean value that indicates if the encoding succeeds
 */
bool CDCodec::caontRSOldEncoding(unsigned char *secretBuffer, int secretSize,
                                 unsigned char *shareBuffer, int *shareSize, unsigned char *keyBuffer)
{
    int alignedSecretSize, numOfSecretWords;
    int coef;
    int i, j;

    /*align the secret size into alignedSecretSize*/
    if(((secretSize + bytesPerSecretWord_) % (bytesPerSecretWord_ * k_)) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize =
                (bytesPerSecretWord_ * k_) * (((secretSize + bytesPerSecretWord_) / (bytesPerSecretWord_ * k_)) + 1) -
                bytesPerSecretWord_;
    }
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }

    /*deduce the share size into shareSize*/
    numOfSecretWords = alignedSecretSize / bytesPerSecretWord_;
    (*shareSize) = bytesPerSecretWord_ * ((numOfSecretWords + 1) / k_);

    /*copy the secret from secretBuffer to alignedSecretBuffer_*/
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if(alignedSecretSize != secretSize) {
        memset(alignedSecretBuffer_ + secretSize, 0, alignedSecretSize - secretSize);
    }

    /*Step 1: generate a CAONT package (containing numOfSecretWords + 1 words) from the secret, and 
      store it into erasureCodingData_*/

    /*+a) generate each of the first numOfSecretWords CAONT words, and store it into erasureCodingData_*/

    /*generate a hash key from the aligned secret*/
    if(!cryptoObj_->generateHash(alignedSecretBuffer_, alignedSecretSize, key_)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*generate each of the first numOfSecretWords CAONT words with the hash key*/
    for(i = 0; i < numOfSecretWords; i++) {
        /*store the index i into wordForIndex_*/
        wordForIndex_[0] = (unsigned char) i;
        wordForIndex_[1] = (unsigned char) (i >> 8);
        wordForIndex_[2] = (unsigned char) (i >> 16);
        wordForIndex_[3] = (unsigned char) (i >> 24);

        /*encrypt the index i with the hash key, and temporarily store the ciphertext in erasureCodingData_*/
        if(!cryptoObj_->encryptWithKey(wordForIndex_, bytesPerSecretWord_, key_,
                                       erasureCodingData_ + bytesPerSecretWord_ * i)) {
            fprintf(stderr, "Error: fail in the data encryption!\n");

            return 0;
        }

        /*the CAONT word is obtained by XORing the ciphertext with the secret word*/
        coef = 1;
        gfObj_.multiply_region.w32(&gfObj_, alignedSecretBuffer_ + bytesPerSecretWord_ * i,
                                   erasureCodingData_ + bytesPerSecretWord_ * i, coef, bytesPerSecretWord_, 1);
    }

    /*+b) generate the last CAONT word from the first numOfSecretWords CAONT words, and store it into erasureCodingData_*/

    /*generate a hash from the first numOfSecretWords CAONT words, and temporarily store it into erasureCodingData_*/
    if(!cryptoObj_->generateHash(erasureCodingData_, alignedSecretSize, erasureCodingData_ + alignedSecretSize)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*the last CAONT word is obtained by XORing the hash with the previous hash key for encryption*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, key_, erasureCodingData_ + alignedSecretSize, coef, bytesPerSecretWord_, 1);

    /*Step 2: generate the n shares from  the CAONT package using systematic Cauchy RS code*/

    /*directly copy the CAONT package from erasureCodingData_ to shareBuffer as the first k shares*/
    memcpy(shareBuffer, erasureCodingData_, alignedSecretSize + bytesPerSecretWord_);

    /*generate only the last m shares from the CAONT package*/
    for(i = 0; i < m_; i++) {
        for(j = 0; j < k_; j++) {
            coef = distributionMatrix_[k_ * (k_ + i) + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * (k_ + i), coef, (*shareSize), 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * (k_ + i), coef, (*shareSize), 1);
            }
        }
    }

    return 1;
}

/*
 * decode the secret from k = n - m shares using old CAONT-RS (proposed in the HotStorage '14 paper)
 *
 * @param shareBuffer - a buffer that stores the k shares 
 * @param kShareIDList - a list that stores the IDs of the k shares
 * @param shareSize - the size of each share 
 * @param secretSize - the size of the secret
 * @param secretBuffer - a buffer for storing the secret <return>
 *
 * @return - a boolean value that indicates if the decoding succeeds
 */
bool CDCodec::caontRSOldDecoding(unsigned char *shareBuffer, int *kShareIDList, int shareSize,
                                 int secretSize, unsigned char *secretBuffer, unsigned char *keyBuffer)
{
    int alignedSecretSize, numOfSecretWords;
    int coef;
    int i, j;

    if((shareSize % bytesPerSecretWord_) != 0) {
        fprintf(stderr,
                "Error: the share size (i.e. %d bytes) should be a multiple of secret word size (i.e. %d bytes)!\n",
                shareSize, bytesPerSecretWord_);

        return 0;
    }
    if(erasureCodingDataSize_ < shareSize * k_) {
        fprintf(stderr, "Error: please use an internal erasureCodingData_[] of size >= %d bytes!\n", shareSize * k_);

        return 0;
    }

    alignedSecretSize = shareSize * k_ - bytesPerSecretWord_;
    numOfSecretWords = alignedSecretSize / bytesPerSecretWord_;
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }
    if(secretSize > alignedSecretSize) {
        fprintf(stderr, "Error: the input secret size (%d bytes) cannot exceed %d bytes!\n", secretSize,
                alignedSecretSize);

        return 0;
    }

    /*store the k rows (corresponding to the k shares) of the distribution matrix into squareMatrix_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            squareMatrix_[k_ * i + j] = distributionMatrix_[k_ * kShareIDList[i] + j];
        }
    }

    /*invert squareMatrix_ into inverseMatrix_*/
    if(!squareMatrixInverting()) {
        fprintf(stderr, "Error: a k * k submatrix of the distribution matrix is noninvertible!\n");

        return 0;
    }

    /*perform RS decoding and obtain the CAONT package in erasureCodingData_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            coef = inverseMatrix_[k_ * i + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 1);
            }
        }
    }

    /*generate a hash from the first numOfSecretWords CAONT words, and temporarily store it into key_*/
    if(!cryptoObj_->generateHash(erasureCodingData_, alignedSecretSize, key_)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*the key later used for encryption is obtained by XORing the generated hash with the last CAONT word*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + alignedSecretSize, key_, coef, bytesPerSecretWord_, 1);

    /*generate each of the numOfSecretWords aligned secret words, and store it into alignedSecretBuffer_*/
    for(i = 0; i < numOfSecretWords; i++) {
        /*store the index i into wordForIndex_*/
        wordForIndex_[0] = (unsigned char) i;
        wordForIndex_[1] = (unsigned char) (i >> 8);
        wordForIndex_[2] = (unsigned char) (i >> 16);
        wordForIndex_[3] = (unsigned char) (i >> 24);

        /*encrypt the index i with the key, and temporarily store the ciphertext in alignedSecretBuffer_*/
        if(!cryptoObj_->encryptWithKey(wordForIndex_, bytesPerSecretWord_, key_,
                                       alignedSecretBuffer_ + bytesPerSecretWord_ * i)) {
            fprintf(stderr, "Error: fail in the data encryption!\n");

            return 0;
        }

        /*the aligned secret word is obtained by XORing the ciphertext with the CAONT word*/
        coef = 1;
        gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + bytesPerSecretWord_ * i,
                                   alignedSecretBuffer_ + bytesPerSecretWord_ * i, coef, bytesPerSecretWord_, 1);
    }

    /*generate a hash from the aligned secret, and temporarily store it in the front end of erasureCodingData_*/
    if(!cryptoObj_->generateHash(alignedSecretBuffer_, alignedSecretSize, erasureCodingData_)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*check if the generated hash is the same as the previous used key*/
    if(memcmp(erasureCodingData_, key_, bytesPerSecretWord_) != 0) {
        fprintf(stderr, "Error: fail in integrity checking!\n");

        return 0;
    }

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return 1;
}

/*
 * encode a secret into n shares using CAONT-RS
 *
 * @param secretBuffer - a buffer that stores the secret
 * @param secretSize - the size of the secret
 * @param shareBuffer - a buffer for storing the n generated shares <return>
 * @param shareSize - the size of each share <return>
 * @param is_header - flag used for detecting encoding header
 *
 * @return - a boolean value that indicates if the encoding succeeds
 */
bool CDCodec::caontRSEncoding(unsigned char *secretBuffer, int secretSize, unsigned char *shareBuffer, int *shareSize,
                              unsigned char *keyBuffer, bool is_header)
{
    int alignedSecretSize;
    int coef;
    int i, j;

    /*align the secret size into alignedSecretSize*/
    if(((secretSize + bytesPerSecretWord_) % (bytesPerSecretWord_ * k_)) == 0) {
        alignedSecretSize = secretSize;
    } else {
        alignedSecretSize =
                (bytesPerSecretWord_ * k_) * (((secretSize + bytesPerSecretWord_) / (bytesPerSecretWord_ * k_)) + 1) -
                bytesPerSecretWord_;
    }
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }

    /*deduce the share size into shareSize*/
    (*shareSize) = bytesPerSecretWord_ * (((alignedSecretSize / bytesPerSecretWord_) + 1) / k_);

    /*copy the secret from secretBuffer to alignedSecretBuffer_*/
    memcpy(alignedSecretBuffer_, secretBuffer, secretSize);
    if(alignedSecretSize != secretSize) {
        memset(alignedSecretBuffer_ + secretSize, 0, alignedSecretSize - secretSize);
    }

    /*Step 1: generate a CAONT package from the secret, and store it into erasureCodingData_*/

    /*+a) generate the main part of the CAONT package from the secret, and store them into erasureCodingData_*/

    /* use keys derived from MLE with key manager instead of generating it from the aligned secret */
    if(!is_header) {
        memcpy(key_, keyBuffer, KEY_SIZE);
    } else {
        if (!cryptoObj_->generateHash(alignedSecretBuffer_, alignedSecretSize, key_)) {
            fprintf(stderr, "Error: fail in the hash calculation!\n");
            return 0;
        }
    }


    /*encrypt alignedSizeConstant_ of size alignedSecretSize with the hash key, and
      temporarily store the ciphertext into erasureCodingData_*/
    if(!cryptoObj_->encryptWithKey(alignedSizeConstant_, alignedSecretSize, key_, erasureCodingData_)) {
        fprintf(stderr, "Error: fail in the data encryption!\n");

        return 0;
    }

    /*the main part of the CAONT package is obtained by XORing the ciphertext with the aligned secret*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, alignedSecretBuffer_, erasureCodingData_, coef, alignedSecretSize, 1);

    /*+b) generate the tail part of the CAONT package, and store it into erasureCodingData_*/

    /*generate a hash from the main part of the CAONT package, and temporarily store it into erasureCodingData_*/
    if(!cryptoObj_->generateHash(erasureCodingData_, alignedSecretSize, erasureCodingData_ + alignedSecretSize)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*the tail part of the CAONT package is obtained by XORing the hash with the previous hash key for encryption*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, key_, erasureCodingData_ + alignedSecretSize, coef, bytesPerSecretWord_, 1);

    /*Step 2: generate the n shares from  the CAONT package using systematic Cauchy RS code*/

    /*directly copy the CAONT package from erasureCodingData_ to shareBuffer as the first k shares*/
    memcpy(shareBuffer, erasureCodingData_, alignedSecretSize + bytesPerSecretWord_);

    /*generate only the last m shares from the CAONT package*/
    for(i = 0; i < m_; i++) {
        for(j = 0; j < k_; j++) {
            coef = distributionMatrix_[k_ * (k_ + i) + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * (k_ + i), coef, (*shareSize), 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + (*shareSize) * j,
                                           shareBuffer + (*shareSize) * (k_ + i), coef, (*shareSize), 1);
            }
        }
    }

    return 1;
}

/*
 * decode the secret from k = n - m shares using CAONT-RS
 *
 * @param shareBuffer - a buffer that stores the k shares 
 * @param kShareIDList - a list that stores the IDs of the k shares
 * @param shareSize - the size of each share 
 * @param secretSize - the size of the secret
 * @param secretBuffer - a buffer for storing the secret <return>
 *
 * @return - a boolean value that indicates if the decoding succeeds
 */
bool CDCodec::caontRSDecoding(unsigned char *shareBuffer, int *kShareIDList, int shareSize,
                              int secretSize, unsigned char *secretBuffer, unsigned char *keyBuffer)
{
    int alignedSecretSize;
    int coef;
    int i, j;

    if((shareSize % bytesPerSecretWord_) != 0) {
        fprintf(stderr,
                "Error: the share size (i.e. %d bytes) should be a multiple of secret word size (i.e. %d bytes)!\n",
                shareSize, bytesPerSecretWord_);

        return 0;
    }
    if(erasureCodingDataSize_ < shareSize * k_) {
        fprintf(stderr, "Error: please use an internal erasureCodingData_[] of size >= %d bytes!\n", shareSize * k_);

        return 0;
    }

    alignedSecretSize = shareSize * k_ - bytesPerSecretWord_;
    if(alignedSecretBufferSize_ < alignedSecretSize) {
        fprintf(stderr, "Error: please use an internal alignedSecretBuffer_[] of size >= %d bytes!\n",
                alignedSecretSize);

        return 0;
    }
    if(secretSize > alignedSecretSize) {
        fprintf(stderr, "Error: the input secret size (%d bytes) cannot exceed %d bytes!\n", secretSize,
                alignedSecretSize);
        printf("[CDCodec] Error:\n");
        printf("\t shareSize = %d\n", shareSize);
        printf("\t secretSize = %d\n", secretSize);

        exit(-1);
    }

    /*store the k rows (corresponding to the k shares) of the distribution matrix into squareMatrix_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            squareMatrix_[k_ * i + j] = distributionMatrix_[k_ * kShareIDList[i] + j];
        }
    }

    /*invert squareMatrix_ into inverseMatrix_*/
    if(!squareMatrixInverting()) {
        fprintf(stderr, "Error: a k * k submatrix of the distribution matrix is noninvertible!\n");
        printf("[CDCodec] kShareIDList:\n");
        for(int k = 0; k < k_; ++k) {
            printf("%d ", kShareIDList[k]);
        }
        printf("\n");

        exit(-1);
    }

    /*perform RS decoding and obtain the CAONT package in erasureCodingData_*/
    for(i = 0; i < k_; i++) {
        for(j = 0; j < k_; j++) {
            coef = inverseMatrix_[k_ * i + j];
            if(j == 0) {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 0);
            } else {
                gfObj_.multiply_region.w32(&gfObj_, shareBuffer + shareSize * j,
                                           erasureCodingData_ + shareSize * i, coef, shareSize, 1);
            }
        }
    }

    /*generate a hash from the main part of the CAONT package, and temporarily store it into key_*/
    if(!cryptoObj_->generateHash(erasureCodingData_, alignedSecretSize, key_)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /*the key later used for encryption is obtained by XORing the generated hash with the tail part of the CAONT package*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_ + alignedSecretSize, key_, coef, bytesPerSecretWord_, 1);

    /*encrypt alignedSizeConstant_ of size alignedSecretSize with the key, and 
      temporarily store the ciphertext into alignedSecretBuffer_*/
    if(!cryptoObj_->encryptWithKey(alignedSizeConstant_, alignedSecretSize, key_, alignedSecretBuffer_)) {
        fprintf(stderr, "Error: fail in the data encryption!\n");

        return 0;
    }

    /*the aligned secret is obtained by XORing the ciphertext with the main part of the CAONT package stored in erasureCodingData_*/
    coef = 1;
    gfObj_.multiply_region.w32(&gfObj_, erasureCodingData_, alignedSecretBuffer_, coef, alignedSecretSize, 1);

    /*generate a hash from the aligned secret, and temporarily store it in the front end of erasureCodingData_*/
    if(!cryptoObj_->generateHash(alignedSecretBuffer_, alignedSecretSize, erasureCodingData_)) {
        fprintf(stderr, "Error: fail in the hash calculation!\n");

        return 0;
    }

    /* do not check in KM-assisted server version since no keys are stored. Checking would be invalid */
    /* It's doable to check if the generated hash is the same as the previous used key in no-KM-assisted server version */

    memcpy(secretBuffer, alignedSecretBuffer_, secretSize);

    return 1;
}

/*
 * encode a secret into n shares
 *
 * @param secretBuffer - a buffer that stores the secret
 * @param secretSize - the size of the secret
 * @param shareBuffer - a buffer for storing the n generated shares <return>
 * @param shareSize - the size of each share <return>
 * @param keyBuffer - used for encoding
 *
 * @return - a boolean value that indicates if the encoding succeeds
 */
bool CDCodec::encoding(unsigned char *secretBuffer, int secretSize, unsigned char *shareBuffer, int *shareSize,
                       unsigned char *keyBuffer, bool is_header)
{
    bool success = 0;

    if(CDType_ == CRSSS_TYPE) { /*CDCodec based on CRSSS*/
        success = crsssEncoding(secretBuffer, secretSize, shareBuffer, shareSize, keyBuffer);
    }

    if(CDType_ == AONT_RS_TYPE) { /*CDCodec based on AONT-RS*/
        success = aontRSEncoding(secretBuffer, secretSize, shareBuffer, shareSize, keyBuffer);
    }

    if(CDType_ == OLD_CAONT_RS_TYPE) { /*CDCodec based on old CAONT-RS*/
        success = caontRSOldEncoding(secretBuffer, secretSize, shareBuffer, shareSize, keyBuffer);
    }

    if(CDType_ == CAONT_RS_TYPE) { /*CDCodec based on CAONT-RS*/
        success = caontRSEncoding(secretBuffer, secretSize, shareBuffer, shareSize, keyBuffer, is_header);
    }

    return success;
}

/*
 * decode the secret from k = n - m shares
 *
 * @param shareBuffer - a buffer that stores the k shares 
 * @param kShareIDList - a list that stores the IDs of the k shares
 * @param shareSize - the size of each share 
 * @param secretSize - the size of the secret
 * @param secretBuffer - a buffer for storing the secret <return>
 * @param keyBuffer - not used for decoding since CAONT could deduce keys
 *
 * @return - a boolean value that indicates if the decoding succeeds
 */
bool CDCodec::decoding(unsigned char *shareBuffer, int *kShareIDList, int shareSize,
                       int secretSize, unsigned char *secretBuffer, unsigned char *keyBuffer)
{
    bool success = 0;

    if(CDType_ == CRSSS_TYPE) { /*CDCodec based on CRSSS*/
        success = crsssDecoding(shareBuffer, kShareIDList, shareSize, secretSize, secretBuffer, keyBuffer);
    }

    if(CDType_ == AONT_RS_TYPE) { /*CDCodec based on AONT-RS*/
        success = aontRSDecoding(shareBuffer, kShareIDList, shareSize, secretSize, secretBuffer, keyBuffer);
    }

    if(CDType_ == OLD_CAONT_RS_TYPE) { /*CDCodec based on old CAONT-RS*/
        success = caontRSOldDecoding(shareBuffer, kShareIDList, shareSize, secretSize, secretBuffer, keyBuffer);
    }

    if(CDType_ == CAONT_RS_TYPE) { /*CDCodec based on CAONT-RS*/
        success = caontRSDecoding(shareBuffer, kShareIDList, shareSize, secretSize, secretBuffer, keyBuffer);
    }

    return success;
}
