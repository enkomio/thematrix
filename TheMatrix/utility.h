#ifndef UTILITY_H
#define UTILITY_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

// log data to an hard-coded directory
void log_data(size_t data_size, uint8_t* data, char* name);

#endif