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
 //   std::deque<T>           d_queue;
    std::queue<T> Q;
public:
  //  void push(T const& value)  {
    void push(T  value)  {
        std::unique_lock<std::mutex> lock(d_mutex);
        Q.push(value);
        d_condition.notify_one();
    };
    T pop(void) {
        std::unique_lock<std::mutex> lock(d_mutex);
        while (Q.empty()) {
            //this->d_condition.wait(lock, [=] { return !this->d_queue.empty(); });
            this->d_condition.wait(lock);
        }
    //    T rc(std::move(this->d_queue.back()));
        T rc = Q.front();
    //    this->d_queue.pop_back();
        Q.pop();
        return rc;
    };
    long size() {
        return Q.size();
    }
  //  long max_size() {
  //      return this->Q.maxsize();
    //}

};


#endif //V4_0_QUEUE_HPP
