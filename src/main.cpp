#include <iostream>
#include <cmath>
#include <random>
#include <vector>
#include <iostream>
#include "Ethernet.h"
#include <iomanip>

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

void print_vector_as_hex(const std::vector<uint8_t> &data)
{
    for (size_t i = 0; i < data.size(); i += 4)
    {
        uint32_t value = 0;
        // Combine 4 bytes into a 32-bit value
        for (size_t j = 0; j < 4 && i + j < data.size(); ++j)
        {
            value |= static_cast<uint32_t>(data[i + j]) << (8 * (3 - j));
        }

        // Print the 32-bit value as 8 hexadecimal digits, padded with leading zeros if necessary
        std::cout << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value << std::endl;
    }
}

int main()
{
    char *ethernet_config_path = "./config_files/ether_config.txt";
    Ethernet ethernet(ethernet_config_path);
    uint64_t number_of_bytes_to_send = ethernet.get_line_rate() * pow(10, 6) * ethernet.get_capture_size() / 8;
    std::vector<uint8_t> data = randomize_data_to_send(number_of_bytes_to_send);
    ethernet.set_data_to_send(data);
    while (!ethernet.buffer_empty())
    {
        print_vector_as_hex(ethernet.generate_burst());
    }
}