#ifndef ecpri_class
#define ecpri_class
#include <string>
#include <vector>
#include "protocol.h"
#define ECPRI_HEADER_SIZE 8 // bytes
class Ecpri : public Protocol
{
    union Ecpri_header
    {
        struct
        {
            uint8_t subsequence_id : 7;
            uint8_t end_bit : 1;
            uint8_t sequence_id;
            uint16_t pc_id;
            uint16_t payload;
            uint8_t message;
            uint8_t concatenation : 1;
            uint8_t reserved : 3;
            uint8_t version : 4;
        };
        uint8_t bytes[8];
    };

private:
    uint8_t message_type = 0; // zero for IQ data message
    uint8_t end_bit = 1;
    uint8_t version = 0b0000; // 0 is default value
    uint16_t pc_id = 0;
    uint8_t subsequence_id = 0; // zero as fragmentation is performed in ORAN
    uint8_t seqld = 0;          // starts with zero and increments till reaching 255 then starts over
    uint8_t concatenation = 0b000;
    uint32_t max_packet_size;
    uint32_t max_payload_size;
    std::vector<uint8_t> data_to_send;

public:
    Ecpri(const char *config_file_path);
    void parse_config_file(const char *config_file_path);
    void print_attributes() const;
    std::vector<uint8_t> generate_packet(std ::vector<uint8_t> payload);
    std::vector<uint8_t> generate_header(uint16_t payload_size);

    // Getters
    uint8_t get_message_type() const;
    uint8_t get_version() const;
    uint8_t get_pc_rtc() const;
    uint8_t get_seqld() const;
    uint8_t get_concatenation() const;
    uint32_t get_max_payload_size() const;

    // Setters
    void set_max_packet_size(uint32_t max_packet_size);
};

#endif