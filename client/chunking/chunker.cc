/*
 * Chunker.cc
 */

#include "chunker.hh"

/*
 * constructor of Chunker
 *
 * @param chunkerType - chunker type (FIX_SIZE_TYPE or VAR_SIZE_TYPE)
 * @param avgChunkSize - average chunk size
 * @param minChunkSize - minimum chunk size
 * @param maxChunkSize - maximum chunk size
 * @param slidingWinSize - sliding window size
 *
 * NOTE: if chunkerType = FIX_SIZE_TYPE, only input avgChunkSize
 */
Chunker::Chunker(int chunkerType, int avgChunkSize, int minChunkSize, int maxChunkSize, int slidingWinSize)
{
    chunkerType_ = chunkerType;

    if(chunkerType_ == FIX_SIZE_TYPE) { /*fixed-size chunker*/
        avgChunkSize_ = avgChunkSize;

        fprintf(stderr, "\nA fixed-size chunker has been constructed! \n");
        fprintf(stderr, "Parameters: \n");
        fprintf(stderr, "      avgChunkSize_: %d \n", avgChunkSize_);
        fprintf(stderr, "\n");
    } else if(chunkerType_ == VAR_SIZE_TYPE) { /*variable-size chunker*/
        int numOfMaskBits, i;

        if(minChunkSize >= avgChunkSize) {
            fprintf(stderr, "Error: minChunkSize should be smaller than avgChunkSize!\n");
            exit(1);
        }
        if(maxChunkSize <= avgChunkSize) {
            fprintf(stderr, "Error: maxChunkSize should be larger than avgChunkSize!\n");
            exit(1);
        }
        avgChunkSize_ = avgChunkSize;
        minChunkSize_ = minChunkSize;
        maxChunkSize_ = maxChunkSize;

        slidingWinSize_ = slidingWinSize;

        /*initialize the base and modulus for calculating the fingerprint of a window*/
        /*these two values were employed in open-vcdiff: "http://code.google.com/p/open-vcdiff/"*/
        polyBase_ = 257; /*a prime larger than 255, the max value of "unsigned char"*/
        polyMOD_ = (1 << 23); /*polyMOD_ - 1 = 0x7fffff: use the last 23 bits of a polynomial as its hash*/

        /*initialize the lookup table for accelerating the power calculation in rolling hash*/
        powerLUT_ = (uint32_t *) malloc(sizeof(uint32_t) * slidingWinSize_);
        /*powerLUT_[i] = power(polyBase_, i) mod polyMOD_*/
        powerLUT_[0] = 1;
        for(i = 1; i < slidingWinSize_; i++) {
            /*powerLUT_[i] = (powerLUT_[i-1] * polyBase_) mod polyMOD_*/
            powerLUT_[i] = (powerLUT_[i - 1] * polyBase_) & (polyMOD_ - 1);
        }

        /*initialize the lookup table for accelerating the byte remove in rolling hash*/
        removeLUT_ = (uint32_t *) malloc(sizeof(uint32_t) * 256); /*256 for unsigned char*/
        for(i = 0; i < 256; i++) {
            /*removeLUT_[i] = (- i * powerLUT_[slidingWinSize_-1]) mod polyMOD_*/
            removeLUT_[i] = (i * powerLUT_[slidingWinSize_ - 1]) & (polyMOD_ - 1);
            if(removeLUT_[i] != 0)
                removeLUT_[i] = polyMOD_ - removeLUT_[i];
            /*note: % is a remainder (rather than modulus) operator*/
            /*      if a < 0,  -polyMOD_ < a % polyMOD_ <= 0       */
        }

        /*initialize the mask for depolytermining an anchor*/
        /*note: power(2, numOfMaskBits) = avgChunkSize_*/
        numOfMaskBits = 1;
        while((avgChunkSize_ >> numOfMaskBits) != 1)
            numOfMaskBits++;
        anchorMask_ = (1 << numOfMaskBits) - 1;

        /*initialize the value for depolytermining an anchor*/
        anchorValue_ = 0;

        fprintf(stdout, "\nA variable-size chunker has been constructed! \n");
        fprintf(stdout, "Parameters: \n");
        fprintf(stdout, "      avgChunkSize_: %d \n", avgChunkSize_);
        fprintf(stdout, "      minChunkSize_: %d \n", minChunkSize_);
        fprintf(stdout, "      maxChunkSize_: %d \n", maxChunkSize_);
        fprintf(stdout, "      slidingWinSize_: %d \n", slidingWinSize_);
        fprintf(stdout, "      polyBase_: 0x%x \n", polyBase_);
        fprintf(stdout, "      polyMOD_: 0x%x \n", polyMOD_);
        fprintf(stdout, "      anchorMask_: 0x%x \n", anchorMask_);
        fprintf(stdout, "      anchorValue_: 0x%x \n", anchorValue_);
        fprintf(stdout, "\n");
    } else if(chunkerType_ == TRACE_FSL_TYPE) { /*trace_driven FSL chunker*/
        maxChunkSize_ = maxChunkSize;
        chunkBuffer_ = new u_char[maxChunkSize + 6];
        trace_line_num_ = 0;
        fprintf(stdout, "\n[Chunker] Using trace driven FSL now... \n");
    }
}

/*
 * destructor of Chunker
 */
Chunker::~Chunker()
{
    if(chunkerType_ == VAR_SIZE_TYPE) { /*variable-size chunker*/
        free(powerLUT_);
        free(removeLUT_);
    } else if(chunkerType_ == TRACE_FSL_TYPE) {
        delete[] chunkBuffer_;
    }
}

/*
 * divide a buffer into a number of fixed-size chunks
 *
 * @param buffer - a buffer to be chunked
 * @param bufferSize - the size of the buffer
 * @param chunkEndIndexList - a list for returning the end index of each chunk <return>
 * @param numOfChunks - the number of chunks <return>
 */
void Chunker::fixSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks)
{
    int chunkEndIndex;

    (*numOfChunks) = 0;
    chunkEndIndex = -1 + avgChunkSize_;

    /*divide the buffer into chunks*/
    while(chunkEndIndex < bufferSize) {
        /*record the end index of a chunk*/
        chunkEndIndexList[(*numOfChunks)] = chunkEndIndex;

        /*go on for the next chunk*/
        chunkEndIndex = chunkEndIndexList[(*numOfChunks)] + avgChunkSize_;
        (*numOfChunks)++;
    }

    /*deal with the tail of the buffer*/
    if(((*numOfChunks) == 0) || (((*numOfChunks) > 0) && (chunkEndIndexList[(*numOfChunks) - 1] != bufferSize - 1))) {
        /*note: such a tail chunk has a size < avgChunkSize_*/
        chunkEndIndexList[(*numOfChunks)] = bufferSize - 1;
        (*numOfChunks)++;
    }
}

/*
 * divide a buffer into a number of variable-size chunks
 *
 * @param buffer - a buffer to be chunked
 * @param bufferSize - the size of the buffer
 * @param chunkEndIndexList - a list for returning the end index of each chunk <return>
 * @param numOfChunks - the number of chunks <return>
 */
void Chunker::varSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks)
{
    int chunkEndIndex, chunkEndIndexLimit;
    uint32_t winFp; /*the fingerprint of a window*/
    int i;

    /*note: to improve performance, we use the optimization in open-vcdiff: "http://code.google.com/p/open-vcdiff/"*/

    (*numOfChunks) = 0;
    chunkEndIndex = -1 + minChunkSize_;
    chunkEndIndexLimit = -1 + maxChunkSize_;

    /*divide the buffer into chunks*/
    while(chunkEndIndex < bufferSize) {
        if(chunkEndIndexLimit >= bufferSize)
            chunkEndIndexLimit = bufferSize - 1;

        /*calculate the fingerprint of the first window*/
        winFp = 0;
        for(i = 0; i < slidingWinSize_; i++) {
            /*winFp = winFp + ((buffer[chunkEndIndex-i] * powerLUT_[i]) mod polyMOD_)*/
            winFp = winFp + ((buffer[chunkEndIndex - i] * powerLUT_[i]) & (polyMOD_ - 1));
        }
        /*winFp = winFp mod polyMOD_*/
        winFp = winFp & (polyMOD_ - 1);

        while(((winFp & anchorMask_) != anchorValue_) && (chunkEndIndex < chunkEndIndexLimit)) {
            /*move the window forward by 1 byte*/
            chunkEndIndex++;

            /*update the fingerprint based on rolling hash*/
            /*winFp = ((winFp + removeLUT_[buffer[chunkEndIndex-slidingWinSize_]]) * polyBase_ + buffer[chunkEndIndex]) mod polyMOD_*/
            winFp = ((winFp + removeLUT_[buffer[chunkEndIndex - slidingWinSize_]]) * polyBase_ +
                     buffer[chunkEndIndex]) & (polyMOD_ - 1);
        }

        /*record the end index of a chunk*/
        chunkEndIndexList[(*numOfChunks)] = chunkEndIndex;

        /*go on for the next chunk*/
        chunkEndIndex = chunkEndIndexList[(*numOfChunks)] + minChunkSize_;
        chunkEndIndexLimit = chunkEndIndexList[(*numOfChunks)] + maxChunkSize_;
        (*numOfChunks)++;
    }

    /*deal with the tail of the buffer*/
    if(((*numOfChunks) == 0) || (((*numOfChunks) > 0) && (chunkEndIndexList[(*numOfChunks) - 1] != bufferSize - 1))) {
        /*note: such a tail chunk has a size < minChunkSize_*/
        chunkEndIndexList[(*numOfChunks)] = bufferSize - 1;
        (*numOfChunks)++;
    }
}

/*
 * trace driven for FSL
 *
 * @param path - the path of FSL chunking file
 *
 */
void Chunker::trace_driven_FSL_chunking(const string &path)
{
    double chunk_time = 0;

    load_chunk_stream(path);
    std::ifstream &fin = get_trace_fstream();
    uint64_t chunk_id_counter = 0;
    uint64_t file_size = 0;
    char readLineBuffer[256];
    std::string readLineStr;
    long line_count = 0;

    Chunk_t input;
    /*start chunking*/
    getline(fin, readLineStr);
    while(true) {
        getline(fin, readLineStr);
        if(fin.eof()) {
            break;
        }
        ++line_count;
        memset(readLineBuffer, 0, 256);
        memcpy(readLineBuffer, (char *) readLineStr.c_str(), readLineStr.length());

        u_char chunk_fp[7];
        memset(chunk_fp, 0, 7);
        char *item;
        item = strtok(readLineBuffer, ":\t\n ");
        for(int index = 0; item != NULL && index < 6; index++) {
            chunk_fp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunk_fp[6] = '\0';
        /* increment size */
        auto size = atoi(item);
        int copySize = 0;
        memset(chunkBuffer_, 0, sizeof(char) * maxChunkSize_ + 6);
        if(size > maxChunkSize_) {
            continue;
        }
        while(copySize < size) {
            memcpy(chunkBuffer_ + copySize, chunk_fp, 6);
            copySize += 6;
        }

        input.chunk_id = chunk_id_counter;
        input.chunk_size = size;
        memcpy(input.content, chunkBuffer_, size);
        input.end = 0;
        if(line_count == trace_line_num_) {
            // this is the last lien of fsl chunking stream, set end flag
            input.end = 1;
        }

        key_obj_->add(input);
        chunk_id_counter++;
        file_size += size;
    }
    // notify thread to exit
    for(int i = 0; i < KEYEX_NUM_THREADS; ++i) {
        key_obj_->inputbuffer_[i]->set_job_done();
    }
    fin.close();
}

/*
 * divide a buffer into a number of chunks
 *
 * @param buffer - a buffer to be chunked
 * @param bufferSize - the size of the buffer
 * @param chunkEndIndexList - a list for returning the end index of each chunk <return>
 * @param numOfChunks - the number of chunks <return>
 */
void Chunker::chunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks)
{
    if(chunkerType_ == FIX_SIZE_TYPE) { /*fixed-size chunker*/
        fixSizeChunking(buffer, bufferSize, chunkEndIndexList, numOfChunks);
    }

    if(chunkerType_ == VAR_SIZE_TYPE) { /*variable-size chunker*/
        varSizeChunking(buffer, bufferSize, chunkEndIndexList, numOfChunks);
    }
}

/*
 * set KeyEx obj for adding to KeyEx's buffer
 *
 * @param keyEx - keyEx obj
 *
 * */
void Chunker::set_key_obj(KeyEx *keyEx)
{
    key_obj_ = keyEx;
}

/*
 * get current FSL trace fstream
 *
 * @return fstream - file pointer of FSL trace
 *
 * */
std::ifstream &Chunker::get_trace_fstream()
{
    if(!fsl_chunking_file_.is_open()) {
        cerr << "Chunker : chunking file open failed" << endl;
        exit(1);
    }
    return fsl_chunking_file_;
}

/*
 * load chunk file from FSL
 *
 * @param path - the path of FSL chunking file
 *
 * */
void Chunker::load_chunk_stream(const std::string &path)
{
    if(fsl_chunking_file_.is_open()) {
        fsl_chunking_file_.close();
    }
    fsl_chunking_file_.open(path, std::ios::binary);
    if(!fsl_chunking_file_.is_open()) {
        cerr << "Chunker : open file: " << path << "error" << endl;
        exit(1);
    }
}

/*
 * get current FSL-type trace total size
 *
 * @param path - the path of FSL chunking file
 * @return size - the total size of the current size
 *
 * */
long Chunker::get_trace_size(const string &path)
{
    std::string readLineStr;
    char readLineBuffer[256];
    long fileSize = 0;
    long line_count = 0;

    load_chunk_stream(path);
    std::ifstream &fin = this->get_trace_fstream();
    getline(fin, readLineStr);

    // extract file size and get the total size of trace
    while(true) {
        getline(fin, readLineStr);
        if(fin.eof()) {
            break;
        }
        ++line_count;
        memset(readLineBuffer, 0, 256);
        memcpy(readLineBuffer, (char *) readLineStr.c_str(), readLineStr.length());
        char *item;
        item = strtok(readLineBuffer, ":\t\n ");
        for(int index = 0; item != NULL && index < 6; index++) {
            strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        /* increment size */
        auto size = atoi(item);
        fileSize += size;
    }

    trace_line_num_ = line_count;
    fin.close();
    return fileSize;
}
