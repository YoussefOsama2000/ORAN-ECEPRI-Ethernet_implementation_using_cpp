#include <iostream>
#include <cmath>
#include <random>
#include <vector>
#include <iostream>
#include "Ethernet.h"

// Function to randomize the data to send
std::vector<uint8_t> randomize_data_to_send(uint64_t number_of_bytes)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255); // Random byte between 0 and 255

    std::vector<uint8_t> data_to_send(number_of_bytes); // Create a vector to store the random data
    for (auto &byte : data_to_send)
    {
        byte = dis(gen); // Assign a random byte value to each element in the vector
    }

    return data_to_send; // Return the randomized data
}

int main()
{
    char *ethernet_config_path = "./config_files/ether_config.txt";
    Ethernet ethernet(ethernet_config_path);
    uint64_t number_of_bytes_to_send = ethernet.get_line_rate() * pow(10, 6) * ethernet.get_capture_size() / 8;
    std::vector<uint8_t> data = randomize_data_to_send(number_of_bytes_to_send);
    ethernet.set_data_to_send(data);
    ethernet.generate_stream();
}