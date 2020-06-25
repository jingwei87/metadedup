//
// Created by Gabriel on 2019-06-24.
// This is for logging
//

#include "Logger.hh"

Logger::Logger()
= default;

Logger::~Logger()
= default;

/*
 * print value as hex
 *
 * output: 0x010203
 *
 * @param value - value to be printed out
 * @param size - the size/length of value
 *
 * */
void Logger::printHexValue(const unsigned char *value, const int size)
{
    printf("0x");
    for(int i = 0; i < size; ++i) {
        printf("%02x", *(value + i));
    }
}

/*
 * print current time for debugging usage
 * */
void Logger::printCurrentTime()
{
    auto timeBuffer = std::make_unique<char[]>(9);
    auto now = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(now);
    std::strftime(timeBuffer.get(), 9, "%H:%M:%S", std::localtime(&current_time));
    printf("%s", timeBuffer.get());
}


