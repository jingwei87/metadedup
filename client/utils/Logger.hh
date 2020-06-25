//
// Created by Gabriel on 2019-06-24.
// This is for logging
//

#ifndef CLIENT_LOGGER_HH
#define CLIENT_LOGGER_HH

#include <chrono>
#include <cstdio>
#include <mutex>

class Logger {
public:
    Logger();

    ~Logger();

    /*
     * print value as hex
     *
     * output: 0x010203
     *
     * @param value - value to be printed out
     * @param size - the size/length of value
     *
     * */
    static void printHexValue(const unsigned char *value, int size);

    //T&& means universal reference
    template<class T>
    static void measure_time(T &&func, double &seconds)
    {
        using namespace std::chrono;
        auto start = system_clock::now();
        func();
        duration<double> diff = system_clock::now() - start;
        seconds += diff.count();
    }

};


#endif //CLIENT_LOGGER_HH
