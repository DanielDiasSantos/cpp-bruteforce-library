#include "../include/bruteforce.h"
#include <cstdint>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, int n) 
{ 
    return (x >> n) | (x << (32 - n)); 
}

static std::string sha256(const std::string& input)
{
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bit_len = input.size() * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    for (int i = 7; i >= 0; --i)
        msg.push_back((bit_len >> (i * 8)) & 0xff);

    for (size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; ++j)
            w[j] = (msg[i+j*4] << 24) | (msg[i+j*4+1] << 16) 
                 | (msg[i+j*4+2] << 8) | msg[i+j*4+3];
        for (int j = 16; j < 64; ++j) {
            uint32_t s0 = rotr(w[j-15],7) ^ rotr(w[j-15],18) ^ (w[j-15] >> 3);
            uint32_t s1 = rotr(w[j-2],17) ^ rotr(w[j-2],19)  ^ (w[j-2]  >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t S1   = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch   = (e & f) ^ (~e & g);
            uint32_t tmp1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0   = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj  = (a & b) ^ (a & c) ^ (b & c);
            uint32_t tmp2 = S0 + maj;
            hh=g; g=f; f=e; e=d+tmp1;
            d=c; c=b; b=a; a=tmp1+tmp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    char hex[65];
    for (int i = 0; i < 8; ++i)
        snprintf(hex + i*8, 9, "%08x", h[i]);
    return std::string(hex, 64);
}


// ─── Combination Generator ────────────────────────────────────────────────────
static void generate(
    const std::string& charset,
    int max_length,
    std::function<bool(const std::string&)> callback
)
{
    int cs = static_cast<int>(charset.size());

    for (int len = 1; len <= max_length; ++len)
    {
        std::vector<int> indices(len, 0);

        while (true)
        {
            std::string candidate(len, ' ');
            for (int i = 0; i < len; ++i)
                candidate[i] = charset[indices[i]];

            if (!callback(candidate)) return;

            int pos = len - 1;
            while (pos >= 0 && ++indices[pos] == cs)
            {
                indices[pos] = 0;
                --pos;
            }
            if (pos < 0) break;
        }
    }
}

// ─── Sequential Mode ──────────────────────────────────────────────────────────
static bruteforce::Result run_sequential(
    const std::string& target_hash,
    const std::string& charset,
    int max_length
)
{
    bruteforce::Result result{"", 0, 0.0, false};

    auto start = std::chrono::high_resolution_clock::now();

    generate(charset, max_length, [&](const std::string& candidate) -> bool
    {
        ++result.attempts;

        if (sha256(candidate) == target_hash)
        {
            result.found_password = candidate;
            result.success = true;
            return false; 
        }

        return true;
    });

    auto end = std::chrono::high_resolution_clock::now();
    result.execution_time = std::chrono::duration<double>(end - start).count();

    return result;
}

// ─── Multithreaded Mode ───────────────────────────────────────────────────────

static bruteforce::Result run_multithreaded(
    const std::string& target_hash,
    const std::string& charset,
    int max_length,
    int num_threads
)
{
    bruteforce::Result result{"", 0, 0.0, false};
    std::atomic<bool> found(false);
    std::atomic<long long> total_attempts(0);
    std::string found_password;
    std::mutex result_mutex;

    auto start = std::chrono::high_resolution_clock::now();

    int cs = static_cast<int>(charset.size());
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]()
        {
            if (t == 0)
            {
                for (int i = 0; i < cs && !found; ++i)
                {
                    std::string candidate(1, charset[i]);
                    total_attempts.fetch_add(1, std::memory_order_relaxed);

                    if (sha256(candidate) == target_hash)
                    {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        found_password = candidate;
                        found = true;
                        return;
                    }
                }
            }

            for (int len = 2; len <= max_length && !found; ++len)
            {
                for (int first = t; first < cs && !found; first += num_threads)
                {
                    std::vector<int> indices(len, 0);
                    indices[0] = first;
                    bool first_iter = true;

                    while (!found)
                    {
                        if (!first_iter)
                        {
                            int pos = len - 1;
                            while (pos > 0 && ++indices[pos] == cs)
                            {
                                indices[pos] = 0;
                                --pos;
                            }
                            if (pos == 0) break;
                        }
                        first_iter = false;

                        std::string candidate(len, ' ');
                        for (int i = 0; i < len; ++i)
                            candidate[i] = charset[indices[i]];

                        total_attempts.fetch_add(1, std::memory_order_relaxed);

                        if (sha256(candidate) == target_hash)
                        {
                            std::lock_guard<std::mutex> lock(result_mutex);
                            found_password = candidate;
                            found = true;
                            return;
                        }
                    }
                }
            }
        });
    }

    for (auto& th : threads) th.join();

    auto end = std::chrono::high_resolution_clock::now();
    result.execution_time = std::chrono::duration<double>(end - start).count();
    result.attempts = total_attempts.load();
    result.found_password = found_password;
    result.success = found.load();

    return result;
}

// ─── Run ───────────────────────────────────────────────────────────────

bruteforce::Result bruteforce::run(
    const std::string& target_hash,
    const std::string& charset,
    int max_length,
    ExecutionMode execution_mode,
    std::optional<int> num_threads,
    std::optional<std::string> wordlist_path
)
{
    if (execution_mode == ExecutionMode::SEQUENTIAL)
    {
        return run_sequential(target_hash, charset, max_length);
    }
    else if (execution_mode == ExecutionMode::DICTIONARY)
    {
        if (!wordlist_path.has_value())
        {
            return {"", 0, 0.0, false};
        }
        return run_dictionary(target_hash, wordlist_path.value());
    }
    else
    {
        int threads = num_threads.value_or(std::thread::hardware_concurrency());
        return run_multithreaded(target_hash, charset, max_length, threads);
    }
}

bruteforce::Result bruteforce::run_dictionary(
    const std::string& targer_hash,
    const std::string& wordlist_path
)
{
    std::string line;
    std::ifstream file(wordlist_path);

    if (!file.is_open())
    {
        return {"", 0 , 0.0, false};
    }

    long long attempts = 0;
    auto start = std::chrono::high_resolution_clock::now();

    while (std::getline(file, line))
    {
        ++attempts;
        std::string hash_code = sha256(line);

        if(hash_code == targer_hash ){
            auto end = std::chrono::high_resolution_clock::now();
            double execution_time = std::chrono::duration<double>(end - start).count();
            return {line, attempts, execution_time, true};
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double execution_time = std::chrono::duration<double>(end - start).count();
    return {"", attempts, execution_time, false};
}

