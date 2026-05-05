#include <iostream>
#include <cassert>
#include "bruteforce.h"

// Simple SHA-256 of "abc" — known value for validation
// echo -n "abc" | sha256sum
// = 98d16b2c90070e3216379738e6ad62b90931326bc10a8fdf74edb63e1ad21f8f

static const std::string ABC_HASH =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

void test_sequential()
{
    std::cout << "[TEST] Sequential mode..." << std::endl;

    auto result = bruteforce::run(
        ABC_HASH,
        "abcdefghijklmnopqrstuvwxyz",
        3,
        bruteforce::ExecutionMode::SEQUENTIAL,
        std::nullopt
    );

    assert(result.success == true);
    assert(result.found_password == "abc");
    assert(result.attempts > 0);
    assert(result.execution_time > 0.0);

    std::cout << "  Found:    " << result.found_password << std::endl;
    std::cout << "  Attempts: " << result.attempts << std::endl;
    std::cout << "  Time:     " << result.execution_time << "s" << std::endl;
    std::cout << "  [PASS]" << std::endl;
}

void test_multithreaded()
{
    std::cout << "[TEST] Multithreaded mode..." << std::endl;

    auto result = bruteforce::run(
        ABC_HASH,
        "abcdefghijklmnopqrstuvwxyz",
        3,
        bruteforce::ExecutionMode::MULTITHREADED,
        std::nullopt
    );

    assert(result.success == true);
    assert(result.found_password == "abc");
    assert(result.attempts > 0);
    assert(result.execution_time > 0.0);

    std::cout << "  Found:    " << result.found_password << std::endl;
    std::cout << "  Attempts: " << result.attempts << std::endl;
    std::cout << "  Time:     " << result.execution_time << "s" << std::endl;
    std::cout << "  [PASS]" << std::endl;
}

void test_not_found()
{
    std::cout << "[TEST] Password not found..." << std::endl;

    auto result = bruteforce::run(
        ABC_HASH,
        "xyz",  // charset too small to find "abc"
        2,
        bruteforce::ExecutionMode::SEQUENTIAL,
        std::nullopt
    );

    assert(result.success == false);
    assert(result.found_password.empty());

    std::cout << "  [PASS]" << std::endl;
}
void test_other_passwords()
{
    std::cout << "[TEST] Other passwords..." << std::endl;

    // Test with "ola" 
    std::string hash_ab = "55a9f4f8994b1bbf2058ea38c8efb6c459000814d5f39c087002571639e6230e";
    auto r1 = bruteforce::run(hash_ab, "abcdefghijklmnopqrstuvwxyz", 3, bruteforce::ExecutionMode::SEQUENTIAL, std::nullopt);
    assert(r1.success == true);
    assert(r1.found_password == "ola");                     
    std::cout << "  'ola' found in " << r1.attempts << " attempts [PASS]" << std::endl;

}

void test_dictionary()
{
    std::cout << "[TEST] Dictionary attack..." << std::endl;

    // hash of "spiderman"
    std::string hash = "c9344c5f1079f7ce9b007e604829f7e8e4516e9132e098ebd58e2cc7f2a5fd4c";

    auto result = bruteforce::run(
        hash,
        "",
        0,
        bruteforce::ExecutionMode::DICTIONARY,
        std::nullopt,
        "data/wordlist.txt"
    );

    assert(result.success == true);
    assert(result.found_password == "spiderman");

    std::cout << "  Found:    " << result.found_password << std::endl;
    std::cout << "  Attempts: " << result.attempts << std::endl;
    std::cout << "  Time:     " << result.execution_time << "s" << std::endl;
    std::cout << "  [PASS]" << std::endl;
}

void test_dictionary_not_found()
{
    std::cout << "[TEST] Dictionary attack - not found..." << std::endl;

    std::string hash = "0000000000000000000000000000000000000000000000000000000000000000";

    auto result = bruteforce::run(
        hash,
        "",
        0,
        bruteforce::ExecutionMode::DICTIONARY,
        std::nullopt,
        "data/wordlist.txt"
    );

    assert(result.success == false);
    assert(result.found_password.empty());
    assert(result.attempts > 0);

    std::cout << "  Not found after " << result.attempts << " attempts [PASS]" << std::endl;
}

int main()
{
    std::cout << "=== Bruteforce Library Tests ===" << std::endl;

    test_sequential();
    test_multithreaded();
    test_not_found();
    test_other_passwords();
    test_dictionary();
    test_dictionary_not_found();
    std::cout << "=== All tests passed! ===" << std::endl;
    return 0;
}