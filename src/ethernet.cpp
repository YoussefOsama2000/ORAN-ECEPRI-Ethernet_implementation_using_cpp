#include "ethernet.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <iomanip>

Ethernet::Ethernet(const char *config_file_path)
{
    parse_config_file(config_file_path);
}

void Ethernet ::parse_config_file(const char *config_file_path)
{
    // give file path to input file streams
    std ::ifstream config_file(config_file_path);
    // check if the file is accessible
    if (!config_file.is_open())
    {
        throw std ::runtime_error("could not open ethernet config file");
    }
    // declare a variable to collect lines
    std::string line;
    std::string before_equal;

    // continue in the loop as there are new lines
    uint16_t line_number = 0;
    while (std::getline(config_file, line))
    {
        line_number++;
        int equal_pos = line.find('=');
        if (equal_pos == -1)
        {
            std::cout << "!WARNING : cannot read configuration in line number " << line_number << " in " << config_file_path;
            continue;
        }
        else
        {
            line.erase(std::remove(line.begin(), line.end(), ' '), line.end());
            line.erase(std::remove(line.begin(), line.end(), '\t'), line.end());
            std::stringstream stream(line);
            std::string attribute;
            std::string value;
            std::getline(stream, attribute, '=');
            attribute.erase(std::remove(attribute.begin(), attribute.end(), ' '), attribute.end());
            std::getline(stream, value, '/');

            if (attribute == "Eth.LineRate")
            {
                int temp = extract_unsigned_int(value);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Eth.LineRate \n";
                }
                else
                {
                    line_rate = temp;
                }
            }
            else if (attribute == "Eth.CaptureSizeMs")
            {
                int temp = extract_unsigned_int(value);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Eth.LineRate \n";
                }
                else
                {
                    capture_size = temp;
                }
            }
            else if (attribute == "Eth.MinNumOfIFGsPerPacket")
            {
                int temp = extract_unsigned_int(value);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Eth.LineRate \n";
                }
                else
                {
                    min_num_of_IFGs_per_packet = temp;
                }
            }
            else if (attribute == "Eth.DestAddress")
            {
                if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
                {
                    dest_addr = extract_hex_value(value.substr(2));
                }
                else
                {
                    std ::cout << "!Warning : Eth.DestAddress should be in hexadecimal form example 0x333333333333 \n";
                }
            }
            else if (attribute == "Eth.SourceAddress")
            {
                if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
                {
                    source_addr = extract_hex_value(value.substr(2));
                }
                else
                {
                    std ::cout << "!Warning : Eth.DestAddress should be in hexadecimal form example 0x333333333333 \n";
                }
            }
            else if (attribute == "Eth.MaxPacketSize")
            {
                int temp = extract_unsigned_int(value);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Eth.MaxPacketSize \n";
                }
                else
                {
                    try
                    {
                        if (temp < 26)
                        {
                            throw std::runtime_error("maximum packet size cannot be less than 26");
                        }
                    }
                    // This catch block would stop the exception from propagating and allow execution to continue.
                    catch (const std::runtime_error &e)
                    {
                        std::cout << "Caught exception: " << e.what() << std::endl;
                        exit(EXIT_FAILURE);
                    }
                    max_packet_size = temp;
                }
            }
            else if (attribute == "Eth.BurstSize")
            {
                int temp = extract_unsigned_int(value);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Eth.BurstSize \n";
                }
                else
                {
                    burst_size = temp;
                }
            }
            else if (attribute == "Eth.BurstPeriodicity_us")
            {
                int temp = extract_unsigned_int(value);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Eth.BurstPeriodicity_us \n";
                }
                else
                {
                    burst_periodicity_us = temp;
                }
            }
            else
            {
                if (attribute.substr(0, 1) != "//")
                    std::cout << "couldn't read line number " << line_number << " in" << config_file_path;
            }
        }
    }
    std::cout << "------------------------------------------------------\n"
              << "VALUES COLLECTED FROM ->      " << config_file_path << "\n";
    print_attributes();
}

void Ethernet::print_attributes() const
{
    std::cout << "Line Rate: " << line_rate << std::endl;
    std::cout << "Capture Size: " << capture_size << std::endl;
    std::cout << "Minimum Number of IFGs per Packet: " << min_num_of_IFGs_per_packet << std::endl;
    std::cout << "Destination Address: 0x" << std::hex << dest_addr << std::dec << std::endl;
    std::cout << "Source Address: 0x" << std::hex << source_addr << std::dec << std::endl;
    std::cout << "Max Packet Size: " << max_packet_size << std::endl;
    std::cout << "Burst Size: " << burst_size << std::endl;
    std::cout << "Burst Periodicity (us): " << burst_periodicity_us << std::endl;
}

std::vector<uint8_t> Ethernet::generate_burst()
{
    // Get the data size (initial size of data_to_send)
    uint64_t data_size = data_to_send.size();

    // 8 (preamble), 6 (dest.addr.), 6 (source addr.), 2 (length), 4 (CRC)
    uint32_t max_payload_size = max_packet_size - OTHER_THAN_PAYLOAD_BYTES;

    // Calculate the number of bytes per burst
    uint32_t bytes_per_burst = burst_periodicity_us * line_rate * 1000;

    // Make the burst 4-byte aligned
    bytes_per_burst += (4 - (bytes_per_burst % 4)) % 4;

    // Initialize the vector to collect the stream of bytes
    std::vector<uint8_t> burst;

    // Create a Packet vector to collect packet data
    std::vector<uint8_t> generated_packet;

    // Packet number counter
    uint16_t packet_number = 0;

    // Track the size of the current burst
    uint32_t current_burst_size = 0;

    int value3 = data_to_send.size();

    // Loop until data_to_send is empty
    while (!data_to_send.empty())
    {
        packet_number++;

        // Determine the payload size for this iteration (max_payload_size or remaining data)
        uint32_t payload_size = std::min(max_payload_size, static_cast<uint32_t>(data_to_send.size()));

        // Extract the payload from data_to_send
        std::vector<uint8_t> payload(data_to_send.begin(), data_to_send.begin() + payload_size);

        // Erase the extracted payload from the front of data_to_send
        data_to_send.erase(data_to_send.begin(), data_to_send.begin() + payload_size);
        value3 = data_to_send.size();

        // Generate the packet from the payload
        generated_packet = generate_packet(payload);

        // Append the packet's content to the collected stream
        burst.insert(burst.end(), generated_packet.begin(), generated_packet.end());

        // Update the size of the current burst
        current_burst_size += generated_packet.size();

        // Check if the burst size has reached the burst limit
        if (packet_number % burst_size == 0 || data_to_send.empty())
        {
            int value = packet_number % burst_size;
            int value2 = data_to_send.empty();
            break;
        }
    }
    // Calculate the remaining space in the current burst
    uint32_t remaining_bytes_to_fill_burst = bytes_per_burst - current_burst_size;

    // Append IFG bytes to fill the burst
    burst.insert(burst.end(), remaining_bytes_to_fill_burst, IFG_byte);

    // Return the collected stream
    return burst;
}

std::vector<uint8_t> Ethernet::generate_packet(std::vector<uint8_t> payload)
{
    // initializing packet vector
    std::vector<uint8_t> packet;
    // adding preamble
    std::vector<uint8_t> preamble = get_field_bytes(SFD, 8);
    packet.insert(packet.begin(), preamble.begin(), preamble.end());
    // adding destination address
    std::vector<uint8_t> destination_address = get_field_bytes(dest_addr, 6);
    packet.insert(packet.end(), destination_address.begin(), destination_address.end());
    // adding source address
    std::vector<uint8_t> source_address = get_field_bytes(source_addr, 6);
    packet.insert(packet.end(), source_address.begin(), source_address.end());
    // adding ether type
    std::vector<uint8_t> ether_type = get_field_bytes(max_packet_size, 2);
    packet.insert(packet.end(), ether_type.begin(), ether_type.end());
    // adding payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    // adding crc
    std::vector<uint8_t> crc = generate_crc(std::vector(packet.begin() + 8, packet.end()));
    packet.insert(packet.end(), crc.begin(), crc.end());
    // adding minimum number of EFGs per packets
    packet.insert(packet.end(), min_num_of_IFGs_per_packet, IFG_byte);
    if (packet.size() % 4 != 0)
    {
        packet.insert(packet.end(), 4 - packet.size() % 4, IFG_byte);
    }
    return packet;
}

std::vector<uint8_t> Ethernet::generate_crc(std::vector<uint8_t> data)
{
    uint32_t crc = 0xFFFFFFFF; // Initial value of CRC

    // Process each byte in the data vector
    for (size_t i = 0; i < data.size(); ++i)
    {
        crc ^= (data[i] << 24); // XOR the top byte with the current byte in the data

        // Process each bit in the current byte
        for (int bit = 0; bit < 8; ++bit)
        {
            // If the top bit is 1, shift and XOR with the polynomial
            if (crc & 0x80000000)
            {
                crc = (crc << 1) ^ GENERATING_POLYNOMIAL;
            }
            else
            {
                crc <<= 1; // Otherwise, just shift
            }
        }
    }

    // Final XOR
    crc = ~crc;
    std::vector<uint8_t> crc_bytes;
    // Convert the CRC to bytes
    crc_bytes.push_back(static_cast<uint8_t>(crc >> 24));
    crc_bytes.push_back(static_cast<uint8_t>(crc >> 16));
    crc_bytes.push_back(static_cast<uint8_t>(crc >> 8));
    crc_bytes.push_back(static_cast<uint8_t>(crc));

    return crc_bytes; // Return the  CRC
}

uint8_t Ethernet::buffer_empty()
{
    return data_to_send.empty();
}

std::vector<uint8_t> Ethernet::get_field_bytes(uint64_t field, size_t num_bytes)
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

int Ethernet::extract_unsigned_int(const std::string &str)
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

uint64_t Ethernet::extract_hex_value(const std::string &address)
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

// Getters
float Ethernet::get_line_rate() const
{
    return line_rate;
}

uint32_t Ethernet::get_capture_size() const
{
    return capture_size;
}

uint32_t Ethernet::get_min_num_of_IFGs_per_packet() const
{
    return min_num_of_IFGs_per_packet;
}

uint64_t Ethernet::get_dest_addr() const
{
    return dest_addr;
}

uint64_t Ethernet::get_source_addr() const
{
    return source_addr;
}

uint32_t Ethernet::get_max_packet_size() const
{
    return max_packet_size;
}

uint32_t Ethernet::get_burst_size() const
{
    return burst_size;
}

uint32_t Ethernet::get_burst_periodicity_us() const
{
    return burst_periodicity_us;
}

// Setters
void Ethernet::set_data_to_send(const std::vector<uint8_t> &data)
{
    data_to_send = data; // Assign the input vector to the private data_to_send attribute
}

void Ethernet::add_data_to_send(const std::vector<uint8_t> &data)
{
    data_to_send.insert(data_to_send.end(), data.begin(), data.end());
}
