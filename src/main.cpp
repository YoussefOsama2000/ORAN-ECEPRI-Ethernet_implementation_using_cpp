#include <iostream>
#include <cmath>
#include <random>
#include <vector>
#include <fstream>
#include "Ethernet.h"
#include "ecpri.h"
#include "oran.h"
#include <iomanip>
#define DEBUG 0

void print_vector_as_hex(const std::vector<uint8_t> &data, std::ofstream *file)
{

    for (size_t i = 0; i < data.size(); i += 4)
    {
        uint32_t value = 0;
        // Combine 4 bytes into a 32-bit value
        for (size_t j = 0; j < 4 && i + j < data.size(); ++j)
        {
            value |= static_cast<uint32_t>(data[i + j]) << (8 * (3 - j));
        }

        // Write the 32-bit value as 8 hexadecimal digits, padded with leading zeros if necessary
        *file << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value << std::endl;
    }
}

int main(int argc, char *argv[])
{
#if DEBUG == 0
    if (argc > 2)
    {
        std::cout << "too many arguments, only two arguments are needed configuration file path and output file path";
    }
    else if (argc < 2)
    {
        std::cout << "too few arguments, two arguments are needed configuration file path and output file path";
    }

    char *config_path = argv[1];
    char *output_path = argv[2];
#else
    char config_path[] = "./config_files/config.txt";
    char output_path[] = "./config_files/bitstream.txt";
#endif
    Ethernet ethernet(config_path);
    Ecpri ecpri(config_path);
    Oran oran(config_path);

    std::ofstream file(output_path);
    if (!file.is_open()) // Check if the file was successfully opened
    {
        std::cerr << "Error: Could not open file " << output_path << std::endl;
        return 0;
    }
    ecpri.set_max_packet_size(ethernet.get_max_payload_size());
    oran.set_max_packet_size(ecpri.get_max_payload_size());
    int i = 0;
    while (!oran.get_end_of_stream())
    {
        i++;
        std ::cout << "capture number" << i << std ::endl;
        std ::vector<std::vector<uint8_t>> oran_packets = oran.capture_frames(ethernet.get_capture_size());

        for (uint32_t i = 0; i < oran_packets.size(); i++)
        {
            std::vector<uint8_t> ecpri_packet = ecpri.generate_packet(oran_packets[i]);
            ethernet.add_data_to_send(ecpri_packet);
        }
        std ::vector<uint8_t> burst = ethernet.generate_burst();
        print_vector_as_hex(burst, &file);
    }

    file.close(); // Close the file when done
    std::cout << "____________________________________\n bit-stream printed in " << output_path << std::endl;
}