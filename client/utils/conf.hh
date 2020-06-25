/*
 * conf.hh
 */

#ifndef __CONF_HH__
#define __CONF_HH__

#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>

/* uncomment code below for disabling time breakdown */
//#define BREAKDOWN_ENABLED (1)

/* 0 for disabling trace-driven, 1 for enabling trace-driven */
#define TRACE_DRIVEN_FSL_ENABLED (0)

using namespace std;

typedef struct kmServerConf {
    string ip;
    int port;
} KMServerConf;

/*
 * configuration class
 */

class Configuration {
private:
    /* total number for storage cloud */
    int n_;

    /* fault tolerance degree */
    int m_;

    /* k = (n - kmServerCount_) - m */
    int k_;

    /* security degree */
    int r_;

    /* KM server count */
    int kmServerCount_;

    /* secret buffer size */
    int secretBufferSize_;

    /* share buffer size */
    int shareBufferSize_;

    /* buffer size */
    int bufferSize_;

    /* chunk end list size */
    int chunkEndIndexListSize_;

    /* Key management server config */
    /* 0<= index < this->n_ */
    std::unique_ptr<KMServerConf[]> kmServerConf;

public:
    /* constructor */
    Configuration()
    {
        n_ = 4;
        kmServerCount_ = 1;
        m_ = 1;
        k_ = n_ - m_;
        r_ = k_ - 1;

        bufferSize_ = 128 * 1024 * 1024;
        chunkEndIndexListSize_ = 1024 * 1024;

        kmServerConf = std::make_unique<KMServerConf[]>(n_ + 1);

        /* read key management server ip & port from config file */
        /* must put the config to the end of file */
        int numLines = 0;
        string configPath("./config");
        int lineEnd = getLineNumberFromFile(configPath);
        int lineStart = lineEnd - 4;
        ifstream in(configPath);
        std::string currentLine;
        int count = 0;
        while(std::getline(in, currentLine)) {
            ++numLines;
            if(numLines >= lineStart && numLines <= lineEnd) {
                const char ch[2] = ":";
                char *token = strtok((char *) currentLine.c_str(), ch);
                char *ip = token;
                token = strtok(NULL, ch);
                int port = atoi(token);

                kmServerConf[count].ip = ip;
                kmServerConf[count].port = port;
                ++count;
            }
        }

        /* safety check */
        if(count != n_ + 1) {
            cout << "Read error from file" << endl;
            exit(-2);
        }
    }

    ~Configuration()
    = default;

    inline int getN() { return n_; }

    inline int getM() { return m_; }

    inline int getKMServerCount() { return kmServerCount_; }

    inline int getK() { return k_; }

    inline int getR() { return r_; }

    inline int getSecretBufferSize() { return secretBufferSize_; }

    inline int getShareBufferSize() { return shareBufferSize_; }

    inline int getBufferSize() { return bufferSize_; }

    inline int getListSize() { return chunkEndIndexListSize_; }

    inline std::unique_ptr<KMServerConf[]> getKMServerConf() { return std::move(kmServerConf); };

    int getLineNumberFromFile(string fileName)
    {
        int numLines = 0;
        ifstream in(fileName);
        std::string unused;
        while(std::getline(in, unused)) {
            ++numLines;
        }
        return numLines;
    }
};

#endif
