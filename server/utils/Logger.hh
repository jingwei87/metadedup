//
// Created by Gabriel on 2019-06-24.
// This is for logging
//

#ifndef CLIENT_LOGGER_HH
#define CLIENT_LOGGER_HH

#include <cstdio>
#include <chrono>
#include <memory>

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

/*
 * print current time for debugging usage
 * */
static void printCurrentTime();

};

#endif //CLIENT_LOGGER_HH
