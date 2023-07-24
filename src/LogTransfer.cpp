

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "LogTransfer.hpp"


LogTransfer::LogTransfer() {
    reset();
}

LogTransfer::~LogTransfer() {
    reset();
}

void LogTransfer::reset() {

    item_list.clear();
    reqh_needed_list.clear();
    resh_needed_list.clear();
}

