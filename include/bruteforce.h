#pragma once 
#include <string>
#include <optional>

namespace bruteforce
{
    // A struct to hold the result of a brute-force password cracking attempt
    struct Result
    {
        std::string found_password; // The password that was found
        long long attempts; // The number of attempts it took to find the password
        double execution_time; // The time it took to find the password in seconds
        bool success; // True if the password was found, false otherwise
    };

    enum class ExecutionMode
    {
        SEQUENTIAL,
        MULTITHREADED,
        DICTIONARY
    };

    // Function to perform a brute-force attack to find the password corresponding to the given hash
    Result run(
        const std::string& target_hash,
        const std::string& charset,
        int max_length,
        ExecutionMode execution_mode,
        std::optional<int> num_threads,
        std::optional<std::string> wordlist_path = std::nullopt
    ); 
    
    Result run_dictionary(
        const std::string& targer_hash,
        const std::string& wordlist_path
    );
}// namespace bruteforce