#ifndef protocol_class
#define protocol_class
#include <string>
#include <vector>
class Protocol
{
protected:
    std::vector<std::vector<uint8_t>> data_to_send;
    uint32_t max_payload_size;
    int extract_unsigned_int(const std::string &str);
    uint64_t extract_hex_value(const std::string &address);
    std::vector<uint8_t> get_field_bytes(uint64_t field, size_t num_bytes);
    std::string *get_key_values(std::string line);
    // Setter private attributes
public:
    void set_data_to_send(const std::vector<std::vector<uint8_t>> data);
    void add_data_to_send(const std::vector<uint8_t> data);
    void set_max_payload_size(const uint32_t max_payload_size);
};
#endif
