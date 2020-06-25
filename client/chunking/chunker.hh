/*
 * Chunker.hh
 */

#ifndef __CHUNKER_HH__
#define __CHUNKER_HH__

#include "DataStruct.hh"
#include "../keyClient/exchange.hh"
#include "Logger.hh"

#include <stdint.h> /*for uint32_t*/
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

/*macro for the type of fixed-size chunker*/
#define FIX_SIZE_TYPE 0
/*macro for the type of variable-size chunker*/
#define VAR_SIZE_TYPE 1
/*macro for the type of trace-driven FSL chunker*/
#define TRACE_FSL_TYPE 2

class Chunker {
private:
    /*chunker type (FIX_SIZE_TYPE or VAR_SIZE_TYPE)*/
    int chunkerType_;

    /*used for FSL trace-driven*/
    u_char *chunkBuffer_;
    KeyEx *key_obj_;
    std::ifstream fsl_chunking_file_;
    long trace_line_num_;

    /*average chunk size*/
    int avgChunkSize_;
    /*minimum chunk size*/
    int minChunkSize_;
    /*maximum chunk size*/
    int maxChunkSize_;

    /*sliding window size*/
    int slidingWinSize_;

    /*the base for calculating the value of the polynomial in rolling hash*/
    uint32_t polyBase_;
    /*the modulus for limiting the value of the polynomial in rolling hash*/
    uint32_t polyMOD_;
    /*note: to avoid overflow, polyMOD_*255 should be in the range of "uint32_t"*/
    /*      here, 255 is the max value of "unsigned char"                       */

    /*the lookup table for accelerating the power calculation in rolling hash*/
    uint32_t *powerLUT_;
    /*the lookup table for accelerating the byte remove in rolling hash*/
    uint32_t *removeLUT_;

    /*the mask for determining an anchor*/
    uint32_t anchorMask_;
    /*the value for determining an anchor*/
    uint32_t anchorValue_;

    /*
    * divide a buffer into a number of fixed-size chunks
    *
    * @param buffer - a buffer to be chunked
    * @param bufferSize - the size of the buffer
    * @param chunkEndIndexList - a list for returning the end index of each chunk <return>
    * @param numOfChunks - the number of chunks <return>
    */
    void fixSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks);

    /*
    * divide a buffer into a number of variable-size chunks
    *
    * @param buffer - a buffer to be chunked
    * @param bufferSize - the size of the buffer
    * @param chunkEndIndexList - a list for returning the end index of each chunk <return>
    * @param numOfChunks - the number of chunks <return>
    */
    void varSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks);

    /*
     * load chunk file from FSL
     *
     * @param path - the path of FSL chunking file
     *
     * */
    void load_chunk_stream(const string& path);

    /*
     * get current FSL trace fstream
     *
     * @return fstream - file pointer of FSL trace
     *
     * */
    std::ifstream& get_trace_fstream();

public:
    /*
    * constructor of Chunker
    *
    * @param chunkerType - chunker type (FIX_SIZE_TYPE or VAR_SIZE_TYPE)
    * @param avgChunkSize - average chunk size (default: 8KB)
    * @param minChunkSize - minimum chunk size (default: 2KB)
    * @param maxChunkSize - maximum chunk size (default: 16KB)
    * @param slidingWinSize - sliding window size
    *
    * NOTE: if chunkerType = FIX_SIZE_TYPE, only input avgChunkSize
    */
    Chunker(int chunkerType = VAR_SIZE_TYPE,
            int avgChunkSize = (8 << 10),
            int minChunkSize = (2 << 10),
            int maxChunkSize = (16 << 10),
            int slidingWinSize = 48);

    /*
         * destructor of Chunker
         */
    ~Chunker();

    /*
    * divide a buffer into a number of chunks
    *
    * @param buffer - a buffer to be chunked
    * @param bufferSize - the size of the buffer
    * @param chunkEndIndexList - a list for returning the end index of each chunk <return>
    * @param numOfChunks - the number of chunks <return>
    */
    void chunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks);

    /*
     * set KeyEx obj for adding to KeyEx's buffer
     *
     * @param keyEx - keyEx obj
     *
     * */
    void set_key_obj(KeyEx *keyEx);

    /*
     * get current FSL-type trace total size
     *
     * @param path - the path of FSL chunking file
     * @return size - the total size of the current size
     *
     * */
    long get_trace_size(const string& path);

    /*
     * trace driven for FSL
     *
     * @param path - the path of FSL chunking file
     *
     */
    void trace_driven_FSL_chunking(const string& path);
};

#endif
