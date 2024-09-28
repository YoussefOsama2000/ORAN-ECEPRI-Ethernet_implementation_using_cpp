#include "oran.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <string>

Oran ::Oran(const char *config_file_path)
{
    parse_config_file(config_file_path);
}

Oran::~Oran()
{
    data_stream->close();
    delete data_stream;
}

void Oran::parse_config_file(const char *config_file_path)
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
            continue;
        }
        else
        {
            // key[0] for the attribute and key[1] for the value
            std::string *key = get_key_values(line);
            if (key[0] == "Oran.SCS")
            {
                int temp = extract_unsigned_int(key[1]);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Oran.SCS \n";
                }
                else
                {
                    scs = temp;
                }
                // TODO:: implement checks for SCS validity
            }
            else if (key[0] == "Oran.MaxNrb")
            {
                int temp = extract_unsigned_int(key[1]);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Oran.MaxNrb \n";
                }
                else
                {
                    if (temp > 255)
                    {
                        max_nrb = 0;
                    }
                    else
                    {
                        max_nrb = temp;
                    }
                }
                // TODO:: implement checks for Oran.MaxNrb validity
            }
            else if (key[0] == "Oran.NrbPerPacket")
            {
                int temp = extract_unsigned_int(key[1]);
                if (temp == -1)
                {
                    std ::cout << "!Warning : invalid input for Oran.NrbPerPacket \n";
                }
                else
                {
                    nrb_per_packet = temp;
                }
                // TODO:: implement checks for Oran.NrbPerPacket validity
            }
            else if (key[0] == "Oran.PayloadType")
            {
                if (key[1] == "fixed")
                {
                    payload_type = fixed;
                }
                else if (key[1] == "random")
                {
                    payload_type = random;
                }
                else
                {
                    std ::cout << "!Warning : invalid input for Oran.PayloadType \n";
                }
            }
            else if (key[0] == "Oran.Payload")
            {
                payload = key[1];
                data_stream = new std::ifstream(key[1]);
                if (!data_stream->is_open())
                {
                    throw std ::runtime_error("could not open iq samples file ");
                }
            }
        }
    }
    std::cout << "------------------------------------------------------\n"
              << "ORAN : VALUES COLLECTED FROM ->      " << config_file_path << "\n";
    print_attributes();
}

void Oran::print_attributes() const
{
    std::cout << "SCS: " << scs << " kHz" << std::endl;
    if (max_nrb == 0)
    {
        std::cout << "Max NRB: " << static_cast<int>(max_nrb) << "(273)" << std::endl;
    }
    else
    {
        std::cout << "Max NRB: " << static_cast<int>(max_nrb) << std::endl;
    }
    std::cout << "NRB per Packet: " << static_cast<int>(nrb_per_packet) << std::endl;
    std::cout << "Payload Type: " << (payload_type == 0 ? "Random" : "Fixed") << std::endl;

    if (payload_type == 1) // If payload type is fixed
    {
        std::cout << "Payload: " << payload << std::endl;
    }
}

std::vector<std::vector<uint8_t>> Oran::capture_frames(uint32_t capture_time)
{
    // number of slots per sub frame scs / 15
    uint32_t slots_per_sub_frame = (scs / 15);
    // Every slot has 14 symbols in case of normal cyclic prefix
    uint32_t symbols_per_sub_frame = 14 * slots_per_sub_frame;
    // every sample takes two bytes from the packet (one byte for i and one for q)
    uint32_t samples_per_packet = std::min(max_payload_size / 2, (uint32_t)nrb_per_packet * 12);
    // prevent dividing resource block into two packets
    samples_per_packet -= samples_per_packet % 12;
    // samples per symbol
    uint32_t samples_per_symbol = max_nrb ? max_nrb * 12 : 273 * 12;
    // Number of packets to send a symbol
    uint8_t packets_to_send_symbol = (samples_per_symbol + samples_per_packet - 1) / samples_per_packet;
    // calculating number of needed packets, taking ceil of the packet
    uint16_t total_packets = packets_to_send_symbol * symbols_per_sub_frame * capture_time;

    std::vector<std::vector<uint8_t>> packets;

    uint32_t samples_remaining_from_symbol;
    for (uint16_t packet_number = 0; packet_number < total_packets; packet_number++)
    {
        // indicates that this packet contains a new packet
        uint8_t new_symbol = packet_number % packets_to_send_symbol != 0 ? 0 : 1;
        samples_remaining_from_symbol = new_symbol ? samples_per_symbol : samples_remaining_from_symbol - samples_per_packet;
        // updating class values
        // updating next prbu to send
        start_prbu = new_symbol ? 0 : start_prbu + samples_per_packet / 12;
        // symbol per slot. increments with every new symbol flag
        current_symbol = new_symbol ? (current_symbol + 1) % 14 : current_symbol;
        // slot per sub frame
        current_slot = current_symbol == 0 && new_symbol ? (current_slot + 1) % slots_per_sub_frame : current_slot;
        // counter for 1 ms sub-frames within a 10ms frame
        current_sub_frame = current_slot == 0 && new_symbol ? (current_sub_frame + 1) % 10 : current_sub_frame;
        // counter for 10 ms frames
        current_frame = current_frame == 0 && new_symbol ? current_frame + 1 : current_frame;

        // if symbol size is smaller than packet size choose symbol size else use packet size
        uint32_t number_of_samples_to_send = std::min(samples_per_packet, samples_remaining_from_symbol);

        // updating num. of prbu
        num_prbu = number_of_samples_to_send / 12;

        // generating the packet
        std::vector<uint8_t>
            new_packet = generate_packet(number_of_samples_to_send);
        // adding the packet to the captured packets
        packets.push_back(new_packet);
    }
    return packets;
}

std::vector<uint8_t> Oran::generate_packet(int number_of_samples)
{
    // initializing packet vector
    std::vector<uint8_t> packet;
    // adding header
    std::vector<uint8_t> header = generate_header();
    packet.insert(packet.begin(), header.begin(), header.end());

    // adding section header
    std::vector<uint8_t> section_header = generate_section_header();
    packet.insert(packet.end(), section_header.begin(), section_header.end());

    // adding payload
    std::vector<uint8_t> iq_samples = prepare_iq_samples(number_of_samples);
    packet.insert(packet.begin(), iq_samples.begin(), iq_samples.end());

    return packet;
}

std::vector<uint8_t> Oran::generate_header()
{
    std::vector<uint8_t> header;
    // initializing oran header struct
    Oran_header oran_header;
    // setting first byte of the header to zero
    *((uint8_t *)&oran_header + 3) = 0;
    // adding current frame id
    oran_header.frame_id = current_frame;
    // adding sub-frame id
    oran_header.sub_frame_id = current_sub_frame;
    // adding slot id
    oran_header.slot_id = current_slot;
    // adding symbol id
    oran_header.start_symbol_id = current_symbol;

    // adding header bytes to the vector
    for (int8_t i = 3; i >= 0; i--) // Start from 0 to 3 for big-endian
    {
        header.insert(header.end(), oran_header.bytes[i]);
    }
    return header;
}

std::vector<uint8_t> Oran::generate_section_header()
{
    std::vector<uint8_t> section_header;
    // initializing section header struct
    Oran_section_header section_header_struct;
    section_header_struct.num_prbu = num_prbu;
    section_header_struct.start_prbu = start_prbu;
    section_header_struct.rb_indicator = 0;
    section_header_struct.section_id = 0;
    section_header_struct.symbol_increment_command = 0;

    // adding section header bytes to the vector (big-endian order)
    for (int8_t i = 3; i >= 0; i--)
    {
        section_header.insert(section_header.end(), section_header_struct.bytes[i]);
    }

    return section_header;
}

std::vector<uint8_t> Oran::prepare_iq_samples(int number_of_samples)
{
    std::vector<uint8_t> iq_samples;
    int i_sample, q_sample;
    for (int i = 0; i < number_of_samples; ++i)
    {
        // Check if we reached the end of the file
        if (data_stream->eof())
        {
            // Clear the EOF flag
            data_stream->clear();
            // Seek to the beginning of the file
            data_stream->seekg(0, std::ios::beg);
            // sets end of stream to 1
            end_of_stream = 1;
        }
        // Read I and Q samples from the data stream
        *data_stream >> i_sample >> q_sample;

        iq_samples.push_back(i_sample); // Add I sample
        iq_samples.push_back(q_sample); // Add Q sample
    }
    return iq_samples;
}

uint8_t Oran::get_end_of_stream()
{
    return end_of_stream;
}

void Oran::set_max_packet_size(uint32_t max_packet_size)
{
    this->max_packet_size = max_packet_size;
    max_payload_size = max_packet_size - ORAN_HEADER_SIZE - ORAN_SECTION_HEADER_SIZE;
}