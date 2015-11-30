//
// Created by philip on 9/28/15.
//

#ifndef V4_0_QUEUE_HPP
#define V4_0_QUEUE_HPP
#define __GXX_EXPERIMENTAL_CXX0X__
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>

template <typename T>

class Queue {
private:
    std::mutex              d_mutex;
    std::condition_variable d_condition;
    std::deque<T>           d_queue;
public:
    void push(T const& value);
    T pop();
    long size();
    long max_size();

};


#endif //V4_0_QUEUE_HPP
