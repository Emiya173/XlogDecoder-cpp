#pragma once
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class ThreadPool {
public:
  explicit ThreadPool(size_t threads = std::thread::hardware_concurrency()) {
    for (size_t i = 0; i < threads; ++i) {
      workers.emplace_back([this] {
        while (true) {
          std::function<void()> task;
          {
            std::unique_lock lock(queue_mutex);
            condition.wait(lock, [this] { return stop || !tasks.empty(); });
            if (stop && tasks.empty()) {
              return;
            }
            task = std::move(tasks.front());
            tasks.pop();
          }
          task();
        }
      });
    }
  }

  template <class F> auto enqueue(F &&f) -> std::future<decltype(f())> {
    using return_type = decltype(f());
    auto task =
        std::make_shared<std::packaged_task<return_type()>>(std::forward<F>(f));
    std::future<return_type> res = task->get_future();
    {
      std::unique_lock lock(queue_mutex);
      if (stop) {
        throw std::runtime_error("enqueue on stopped ThreadPool");
      }
      tasks.emplace([task]() { (*task)(); });
    }
    condition.notify_one();
    return res;
  }

  ~ThreadPool() {
    {
      std::unique_lock lock(queue_mutex);
      stop = true;
    }
    condition.notify_all();
    for (auto &worker : workers) {
      worker.join();
    }
  }

private:
  std::vector<std::thread> workers;
  std::queue<std::function<void()>> tasks;
  std::mutex queue_mutex;
  std::condition_variable condition;
  bool stop = false;
};
