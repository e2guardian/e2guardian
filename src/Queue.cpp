//
// Created by philip on 9/28/15.
//


#include "Queue.hpp"

template <typename T>

void Queue::push(T const& value) {
        {
            std::unique_lock<std::mutex> lock(this->d_mutex);
            d_queue.push_front(value);
        }
        this->d_condition.notify_one();
}
T Queue::pop() {
        std::unique_lock<std::mutex> lock(this->d_mutex);
        this->d_condition.wait(lock, [=] { return !this->d_queue.empty(); });
        T rc(std::move(this->d_queue.back()));
        this->d_queue.pop_back();
        return rc;
}
long Queue::size() {
    return this->d_queue.size()
}

long Queue::max_size() {
    return this->d_queue.max_size();
}
