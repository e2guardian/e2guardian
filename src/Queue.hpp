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
    long size() {
        std::lock_guard<std::mutex> lock(d_mutex);
        return Q.size();
    }
};


#endif //V4_0_QUEUE_HPP
