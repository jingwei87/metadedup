#ifndef __MESSAGEQUEUE_HH__
#define __MESSAGEQUEUE_HH__

#include <boost/atomic.hpp>
#include <boost/lockfree/spsc_queue.hpp>

template<class T>
class MessageQueue {
private:
    int capacity;
    boost::lockfree::spsc_queue<T> queue;

    int get_capacity(int size)
    {
        if(size < 2) {
            capacity = 2;
        } else {
            capacity = size;
        }
        return capacity;
    }


public:
    boost::atomic<bool> done_;

    explicit MessageQueue(int size) : queue(get_capacity(size))
    {
        done_ = false;
    }

    ~MessageQueue()
    = default;

    bool push(T &data)
    {
        while(!queue.push(data));
        return true;
    }

    bool pop(T &data)
    {
        return queue.pop(data);
    }

    bool set_job_done()
    {
        done_ = true;
    }

    void read(T &data)
    {
        while(queue.read_available() <= 0);
        data = queue.front();
    }

    bool is_empty()
    {
        return queue.empty();
    }
};

#endif // __MESSAGEQUEUE_HH__