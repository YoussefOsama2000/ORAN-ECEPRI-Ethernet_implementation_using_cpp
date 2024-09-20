#ifndef ethernet_class
#define ethernet_class

#include <string>
#include <vector>
#define IFG_byte 0x07
#define SFD 0xFB555555555555D5
#define GENERATING_POLYNOMIAL 0x04C11DB7
#define OTHER_THAN_PAYLOAD_BYTES 26
class Ethernet
{

private:
    float line_rate;
    uint32_t capture_size;
    uint32_t min_num_of_IFGs_per_packet;
    uint64_t dest_addr;
    uint64_t source_addr;
    uint32_t max_packet_size;
    uint32_t burst_size;
    uint32_t burst_periodicity_us;
    std::vector<uint8_t> data_to_send;

public:
    Ethernet(const char *config_file_path);
    void parse_config_file(const char *config_file_path);
    void print_attributes() const;

    std::vector<uint8_t> generate_burst();
    std::vector<uint8_t> generate_packet(std::vector<uint8_t> payload);
    std::vector<uint8_t> generate_crc(std::vector<uint8_t> data);
    uint8_t buffer_empty();
    // Getters for private attributes
    float get_line_rate() const;
    uint32_t get_capture_size() const;
    uint32_t get_min_num_of_IFGs_per_packet() const;
    uint64_t get_dest_addr() const;
    uint64_t get_source_addr() const;
    uint32_t get_max_packet_size() const;
    uint32_t get_burst_size() const;
    uint32_t get_burst_periodicity_us() const;

    // Setter private attributes
    void set_data_to_send(const std::vector<uint8_t> &data);
    void add_data_to_send(const std::vector<uint8_t> &data);

private:
    int extract_unsigned_int(const std::string &str);
    uint64_t extract_hex_value(const std::string &address);
    std::vector<uint8_t> get_field_bytes(uint64_t field, size_t num_bytes);
};
#endif