#include "protocol.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <string>
#include <iostream>
int Protocol::extract_unsigned_int(const std::string &str)
{
    // Check if the string is empty
    if (str.empty())
    {
        return -1;
    }

    // Check if all characters in the string are digits
    for (char c : str)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
        {
            return -1;
        }
    }

    // Convert the string to an unsigned long
    try
    {
        unsigned long number = std::stoul(str);
        return static_cast<int>(number);
    }
    catch (const std::invalid_argument &e)
    {
        // If the string is not a valid number
        return -1;
    }
    catch (const std::out_of_range &e)
    {
        // If the number is out of the range of unsigned long
        return -1;
    }
}

uint64_t Protocol::extract_hex_value(const std::string &address)
{
    // Convert hex string to uint64_t
    try
    {
        uint64_t result = std::stoull(address, nullptr, 16);
        return result;
    }
    catch (const std::invalid_argument &e)
    {
        std::cerr << "Invalid argument: " << e.what() << std::endl;
        return 0;
    }
    catch (const std::out_of_range &e)
    {
        std::cerr << "Out of range: " << e.what() << std::endl;
        return 0;
    }
}

std::vector<uint8_t> Protocol::get_field_bytes(uint64_t field, size_t num_bytes)
{
    std::vector<uint8_t> bytes(num_bytes);
    auto field_bytes = reinterpret_cast<uint8_t *>(&field);

    // Copy bytes in reverse order to maintain expected order
    for (size_t i = 0; i < num_bytes; ++i)
    {
        bytes[i] = field_bytes[num_bytes - 1 - i];
    }

    return bytes;
}

std::string *Protocol::get_key_values(std::string line)
{
    line.erase(std::remove(line.begin(), line.end(), ' '), line.end());
    line.erase(std::remove(line.begin(), line.end(), '\t'), line.end());

    std::string *key = new std::string[2];

    size_t pos = line.find("//");
    // check if their is a comment or not
    if (pos != std::string::npos)
    {
        // Create a substring with everything before the "//"
        line = line.substr(0, pos);
    }
    std::stringstream after_removing_comment(line);
    std::getline(after_removing_comment, key[0], '=');
    std::getline(after_removing_comment, key[1]);
    return key;
}
// Setters
void Protocol::set_data_to_send(const std::vector<std::vector<uint8_t>> data)
{
    data_to_send = data; // Assign the input vector to the private data_to_send attribute
}

void Protocol::add_data_to_send(const std::vector<uint8_t> data)
{
    data_to_send.push_back(data);
}

void Protocol::set_max_payload_size(const uint32_t max_payload_size)
{
    this->max_payload_size = max_payload_size;
}
