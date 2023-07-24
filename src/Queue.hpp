//
// Created by philip on 9/28/15.
//

#ifndef V4_0_QUEUE_HPP
#define V4_0_QUEUE_HPP
//#define __GXX_EXPERIMENTAL_CXX0X__
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <queue>
#include "LogTransfer.hpp"

template <typename T>
class Queue {
private:
    std::mutex              d_mutex;
    std::condition_variable d_condition;
    std::queue<T> Q;
public:
  //  void push(T const& value)  {
    void push(T  value)  {
        std::lock_guard<std::mutex> lock(d_mutex);
        Q.push(value);
        d_condition.notify_one();
    };
    T pop(void) {
        std::unique_lock<std::mutex> lock(d_mutex);
         d_condition.wait(lock, [=] { return !Q.empty(); });
        T rc = Q.front();
        Q.pop();
        return rc;
    };
    int size() {
        std::lock_guard<std::mutex> lock(d_mutex);
        return Q.size();
    }
};

struct LQ_rec {
    Socket *sock;
    unsigned int ct_type;
};


//  CT_TYPE DEFS
#define CT_PROXY          1     // Normal proxy connection also handles tranpartent http
#define CT_THTTPS       2     // Transparent https connection
#define CT_ICAP              4     //  ICAP connection
#define CT_PROXY_TLS          8     // Normal proxy connection over https




#endif //V4_0_QUEUE_HPP
