#ifndef oran_class
#define oran_class
#define FRAME_TIME 10 // in ms
#define SUB_FRAMES_PER_FRAME 10
#define ORAN_HEADER_SIZE 4         // bytes
#define ORAN_SECTION_HEADER_SIZE 4 // bytes

#include "protocol.h"

class Oran : public Protocol
{
    union Oran_header
    {
        struct
        {
            uint16_t start_symbol_id : 6;
            uint16_t slot_id : 6;
            uint16_t sub_frame_id : 4;
            uint8_t frame_id;
            uint8_t filter_index : 4;
            uint8_t payload_version : 3;
            uint8_t data_direction : 1;
        };
        uint8_t bytes[4];
    };

    union Oran_section_header
    {
        struct
        {
            uint32_t num_prbu : 8;
            uint32_t start_prbu : 10;
            uint32_t symbol_increment_command : 1;
            uint32_t rb_indicator : 1;
            uint32_t section_id : 12;
        };
        uint8_t bytes[4];
    };

    typedef enum
    {
        random,
        fixed
    } payload_types;

private:
    uint32_t scs;
    uint8_t max_nrb;
    uint8_t nrb_per_packet;
    uint8_t payload_type; // 0 for random and 1 for fixed (from a file)
    std::string payload;
    std ::ifstream *data_stream;
    uint8_t end_of_stream = 0;
    uint8_t current_frame = 0xff;
    uint8_t current_sub_frame = 0xff;
    uint8_t current_slot = 0xff;
    uint8_t current_symbol = 0xff;
    uint8_t num_prbu = 0;
    uint8_t start_prbu = 0;
    uint32_t max_packet_size;

public:
    Oran(const char *config_file_path);
    ~Oran();
    void parse_config_file(const char *config_file_path);
    void print_attributes() const;
    std::vector<std::vector<uint8_t>> capture_frames(uint32_t capture_time);
    uint8_t get_end_of_stream();
    void set_max_packet_size(uint32_t max_packet_size);

private:
    std::vector<uint8_t> generate_packet(int number_of_samples);
    std::vector<uint8_t> generate_header();
    std::vector<uint8_t> generate_section_header();
    std::vector<uint8_t> prepare_iq_samples(int number_of_samples);
    std::vector<uint8_t> generate_user_plane_section_header();
};

#endif