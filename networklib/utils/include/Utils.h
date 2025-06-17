#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <chrono>

namespace Utils
{
    class Timer {
    public:
        void start() {
            _start = std::chrono::high_resolution_clock::now();
        }

        void stop() {
            _end = std::chrono::high_resolution_clock::now();
        }

        double elapsed_ms() const {
            return std::chrono::duration<double, std::milli>(_end - _start).count();
        }

        void print(const std::string& label = "Elapsed") const {
            std::cout << label << ": " << elapsed_ms() << " ms\n";
        }

    private:
        std::chrono::high_resolution_clock::time_point _start, _end;
    };
};

#endif //UTILS_H
