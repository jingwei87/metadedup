/*
 * main test program
 */
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <sys/time.h>

#include "CDCodec.hh"
#include "CryptoPrimitive.hh"
#include "chunker.hh"
#include "conf.hh"
#include "DataStruct.hh"
#include "decoder.hh"
#include "downloader.hh"
#include "encoder.hh"
#include "keyClient/exchange.hh"
#include "uploader.hh"

using namespace std;

Chunker *chunkerObj;
Decoder *decoderObj;
Encoder *encoderObj;
Uploader *uploaderObj;
Downloader *downloaderObj;
Configuration *confObj;

struct timeval timestart;
struct timeval timeend;

void usage(char *s)
{

    printf("usage: %s [filename] [userID] [action] [secureType]\n", s);
    printf("\t- [filename]: full path of the file;\n");
    printf("\t- [userID]: use ID of current client;\n");
    printf("\t- [action]: [-u] upload; [-d] download;\n");
    printf("\t- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1\n");
}

int main(int argc, char *argv[])
{

    /* argument test */
    if(argc != 5) {
        usage(argv[0]);
        return -1;
    }
    /* get options */
    int userID = atoi(argv[2]);
    char *opt = argv[3];
    char *securesetting = argv[4];
    /* read file */
    unsigned char *buffer;
    int *chunkEndIndexList;
    int numOfChunks;
    int n, m, kmServerCount, k, r;
    long size = 0;

    /* initialize openssl locks */
    if(!CryptoPrimitive::opensslLockSetup()) {
        printf("fail to set up OpenSSL locks\n");
        return 0;
    }

    confObj = new Configuration();
    /* fix parameters here */
    n = confObj->getN();
    m = confObj->getM();
    kmServerCount = confObj->getKMServerCount();
    k = confObj->getK();
    r = confObj->getR();
    std::unique_ptr<KMServerConf[]> kmServerConf = confObj->getKMServerConf();
    printf("\n[Main] KM server info:\n");
    for(int i = 0; i < n + 1; ++i) {
        printf("[%d] %s:%d\n", i, kmServerConf[i].ip.c_str(), kmServerConf[i].port);
    }

    /* initialize buffers */
    int bufferSize = confObj->getBufferSize();
    int chunkEndIndexListSize = confObj->getListSize();

    delete confObj;
    buffer = (unsigned char *) malloc(sizeof(unsigned char) * bufferSize);
    chunkEndIndexList = (int *) malloc(sizeof(int) * chunkEndIndexListSize);

    /* full file name size process */
    int namesize = 0;
    while(argv[1][namesize] != '\0') {
        namesize++;
    }
    namesize++;
    /* parse secure parameters */
    int secureType = LOW_SEC_PAIR_TYPE;
    if(strncmp(securesetting, "HIGH", 4) == 0) {
        secureType = HIGH_SEC_PAIR_TYPE;
    }


    if(strncmp(opt, "-u", 2) == 0) {

        uploaderObj = new Uploader(n + 1, n + 1, userID, argv[1], namesize);

        encoderObj = new Encoder(CAONT_RS_TYPE, n + 1, m, kmServerCount, r, secureType, uploaderObj);


        auto *keyObj = new KeyEx(encoderObj, secureType, std::move(kmServerConf), userID,
                                 CHARA_MIN_HASH, VAR_SEG, DYNAMIC_KM_SERVER, DISABLE_LRU_CACHE);

        FILE *fin;
        if(!TRACE_DRIVEN_FSL_ENABLED) {
            printf("\n[main] normal file mode...\n");
            chunkerObj = new Chunker(VAR_SIZE_TYPE);
            fin = fopen(argv[1], "r");
            if(fin == nullptr) {
                printf("[main] File not found!!\n");
                delete uploaderObj;
                delete chunkerObj;
                delete encoderObj;
                fclose(fin);

                free(buffer);
                free(chunkEndIndexList);
                return -1;
            }

            /* get file size */
            fseek(fin, 0, SEEK_END);
            size = ftell(fin);
            fseek(fin, 0, SEEK_SET);
        } else {
            printf("\n[main] FSL trace-driven mode...\n");
            // IF normal file instead of trace-driven FSL
            chunkerObj = new Chunker(TRACE_FSL_TYPE);
            size = chunkerObj->get_trace_size(argv[1]);
            printf("[main] file size = %ld\n", size);
        }

        gettimeofday(&timestart, NULL);

        //chunking
        FileHeader_t header;
        memcpy(header.file_header.file_name, argv[1], namesize);
        header.file_header.fullNameSize = namesize;
        header.file_header.fileSize = size;

        // do header encoder
        std::thread header_th(&Encoder::collect_header, encoderObj, std::ref(header));
        header_th.detach();

        printf("[Main] header inserted into encoder\n");

        if(!TRACE_DRIVEN_FSL_ENABLED) {

            double chunking_time = 0;

            bool job_done = false;
            long total = 0;
            int totalChunks = 0;
            while(total < size) {

                int ret = fread(buffer, 1, bufferSize, fin);
#ifdef BREAKDOWN_ENABLED
                Logger::measure_time([&]() {
#endif
                chunkerObj->chunking(buffer, ret, chunkEndIndexList, &numOfChunks);
#ifdef BREAKDOWN_ENABLED
                }, chunking_time);
#endif
                int count = 0;
                int preEnd = -1;
                Chunk_t input;
                while(count < numOfChunks) {
                    input.chunk_id = totalChunks;
                    input.chunk_size = chunkEndIndexList[count] - preEnd;
                    // content <=> chunk data
                    memcpy(input.content, buffer + preEnd + 1, input.chunk_size);
                    input.end = 0;

                    if(total + ret == size && count + 1 == numOfChunks) {
                        input.end = 1;
                        job_done = true;
                    }

                    keyObj->add(input);

                    if(job_done) {
                        // notify thread to exit
                        for(int i = 0; i < KEYEX_NUM_THREADS; ++i) {
                            keyObj->inputbuffer_[i]->set_job_done();
                        }
                    }
                    totalChunks++;
                    preEnd = chunkEndIndexList[count];
                    count++;
                }
                total += ret;
            }
            printf("\n[!>] <main> Total chunks = %d\n", totalChunks);

#ifdef BREAKDOWN_ENABLED
            printf("\n[Time] ===================\n");
            fprintf(stderr, "[Time] [Chunker] Chunking time is /%lf/ s\n", chunking_time);
            printf("[Time]===================\n\n");
#endif
        } else {
            chunkerObj->set_key_obj(keyObj);
            chunkerObj->trace_driven_FSL_chunking(argv[1]);
        }

        long long tt = 0, unique = 0;
        printf("\n[!>] <main> Indicate Start ===>\n");
        uploaderObj->indicateEnd(&tt, &unique);
        printf("\n[!>] <main> Indicate End ===>\n");

        gettimeofday(&timeend, NULL);
        long diff_global = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        double second_global = diff_global / 1000000.0;
        fprintf(stderr, "%s (%.2lf MB): upload time is /%lf/ s\n", argv[1], (double)size * 1.0 / 1024 / 1024, second_global);
        printf("\n");

        delete uploaderObj;
        delete chunkerObj;
        delete encoderObj;
        delete keyObj;
        if(!TRACE_DRIVEN_FSL_ENABLED) {
            fclose(fin);
        }
    } else if(strncmp(opt, "-d", 2) == 0) {

        decoderObj = new Decoder(CAONT_RS_TYPE, n + 1, m, kmServerCount, r, secureType);

        /* Currently, you have to set this value manually to support fault-tolerance */
        // possible value of down_server_index: 0, 1, 2, 3, 4
        int down_server_index = 3;
        int down_server_num = 1;

        // Assume there's one server going down
        downloaderObj = new Downloader(n + 1, n + 1, down_server_index, down_server_num, userID, decoderObj, argv[1], namesize);

        // Tell all online KM server thread to exit to prevent being blocked. Yes, it is necessary.
        auto *keyObj = new KeyEx(n + 1, down_server_index, down_server_num, std::move(kmServerConf), userID,
                                 DYNAMIC_KM_SERVER);

        gettimeofday(&timestart, NULL);

        char nameBuffer[256];
        sprintf(nameBuffer, "%s.d", argv[1]);
        FILE *fw = fopen(nameBuffer, "wb");

        decoderObj->setFilePointer(fw);

        int preFlag = downloaderObj->preDownloadFile(argv[1], namesize, n + 1);
        if(preFlag == 1) {
            downloaderObj->downloadFile(argv[1], namesize, n + 1, k);
        }
        decoderObj->indicateEnd();
        printf("[main] decoder end!!\n");
        downloaderObj->indicateEnd();
        printf("[main] downloader end!!\n");

        fclose(fw);

        gettimeofday(&timeend, NULL);
        long diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        double second = diff / 1000000.0;
        fprintf(stderr, "%s: download time is /%lf/ s\n", argv[1], second);
        printf("\n");

        delete keyObj;
        delete downloaderObj;
        delete decoderObj;
    } else {
        printf("[main] Unknown parameter detected!! Please Check your parameter\n");
        printf("\n");
    }

    free(buffer);
    free(chunkEndIndexList);
    CryptoPrimitive::opensslLockCleanup();

    return 0;
}
