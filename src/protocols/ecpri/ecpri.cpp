#include "ecpri.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <iomanip>

Ecpri::Ecpri(const char *config_file_path)
{
    parse_config_file(config_file_path);
}

void Ecpri::parse_config_file(const char *config_file_path)
{
    std::ifstream config_file(config_file_path);
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
            continue;
        }
        else
        {
            // key[0] for the attribute and key[1] for the value
            std::string *key = get_key_values(line);
            if (key[0] == "ECPRI.Message")
            {
                int temp = extract_unsigned_int(key[1]);
                if (temp != -1)
                {
                    message_type = temp;
                }
            }
            else if (key[0] == "ECPRI.PC_RTC")
            {
                int temp = extract_unsigned_int(key[1]);
                if (temp != -1)
                {
                    pc_id = temp;
                }
            }
        }
    }
    std::cout << "------------------------------------------------------\n"
              << "Ecpri : VALUES COLLECTED FROM ->      " << config_file_path << "\n";
    print_attributes();
}

void Ecpri::print_attributes() const
{
    std::cout << "eCPRI Message Type: 0x" << std::hex << static_cast<int>(message_type) << std::dec << std::endl;
    std::cout << "eCPRI Version: 0x" << std::hex << static_cast<int>(version) << std::dec << std::endl;
    std::cout << "eCPRI PC RTC: 0x" << std::hex << static_cast<int>(pc_id) << std::dec << std::endl;
    std::cout << "eCPRI Sequence ID: " << static_cast<int>(seqld) << std::endl;
    std::cout << "eCPRI Concatenation: " << static_cast<int>(concatenation) << std::endl;
}

std::vector<uint8_t> Ecpri::generate_packet(std::vector<uint8_t> payload)
{
    // initializing packet and adding header to the packet
    std::vector<uint8_t> packet = generate_header(payload.size());
    // incrementing sequence ID
    seqld++;
    // adding the payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

std::vector<uint8_t> Ecpri::generate_header(uint16_t payload_size)
{
    std ::vector<uint8_t> header;
    Ecpri_header ecpri_header;
    ecpri_header.version = version;
    ecpri_header.reserved = 0;
    ecpri_header.concatenation = concatenation;
    ecpri_header.message = message_type;
    ecpri_header.payload = payload_size;
    ecpri_header.pc_id = pc_id;
    ecpri_header.subsequence_id = subsequence_id;
    ecpri_header.sequence_id = seqld;
    ecpri_header.end_bit = end_bit;
    for (int8_t i = 7; i >= 0; i--)
    {
        header.insert(header.end(), ecpri_header.bytes[i]);
    }
    return header;
}

void Ecpri::set_max_packet_size(uint32_t max_packet_size)
{
    this->max_packet_size = max_packet_size;
    max_payload_size = max_packet_size - ECPRI_HEADER_SIZE;
}

uint8_t Ecpri::get_message_type() const
{
    return message_type;
}

uint8_t Ecpri::get_version() const
{
    return version;
}

uint8_t Ecpri::get_pc_rtc() const
{
    return pc_id;
}

uint8_t Ecpri::get_seqld() const
{
    return seqld;
}

uint8_t Ecpri::get_concatenation() const
{
    return concatenation;
}

uint32_t Ecpri::get_max_payload_size() const
{
    return max_payload_size;
}