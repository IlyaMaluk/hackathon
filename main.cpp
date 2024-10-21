#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <regex>
#include <iomanip>
#include<sstream>
#include <chrono>
#include <thread>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using namespace std::chrono_literals;

bool status_to_bool(std::string& status) {
    if (status == "up") {
        return true;
    }

    return false;
}

struct interface_information {
    char name[255];
    bool phy_status;
    bool protocol_status;
    uint64_t in_utilization;
    uint64_t out_utilization;
    int in_errors;
    int out_errors;

    friend std::ostream& operator<<(std::ostream& out, const interface_information& port) {
        out << "Interface Name: " << port.name << '\n';
        out << "PHY Status: " << port.phy_status << '\n';
        out << "Protocol Status: " << port.protocol_status << '\n';
        out << "In Utilization: " << port.in_utilization << "%" << '\n';
        out << "Out Utilization: " << port.out_utilization << "%" << '\n';
        out << "Input Errors: " << port.in_errors << '\n';
        out << "Output Errors: " << port.out_errors << '\n';

        return out;
    }
};

void send_command(tcp::socket& socket, const std::string& command) {
    boost::asio::write(socket, boost::asio::buffer(command));
}

std::string receive_response(tcp::socket& socket) {
    std::string data;
    boost::system::error_code error;
    auto last_data_time = std::chrono::steady_clock::now();

    while (true) {
        size_t bytes_available = socket.available();
        if (bytes_available > 0) {
            std::vector<char> buf(bytes_available);
            size_t bytes_transferred = socket.read_some(boost::asio::buffer(buf), error);
            if (error) {
                throw boost::system::system_error(error);
            }
            data.append(buf.begin(), buf.begin() + bytes_transferred);
            last_data_time = std::chrono::steady_clock::now();
        }
        else {
            auto now = std::chrono::steady_clock::now();
            if (now - last_data_time > std::chrono::milliseconds(500)) {
                break;
            }
            std::this_thread::sleep_for(100ms);
        }
    }
    return data;
}

std::vector<uint8_t> encode_length(size_t length) {
    std::vector<uint8_t> result;
    if (length < 128) {
        result.push_back(static_cast<uint8_t>(length));
    }
    else {
        std::vector<uint8_t> len_bytes;
        size_t temp_len = length;
        while (temp_len > 0) {
            len_bytes.insert(len_bytes.begin(), temp_len & 0xFF);
            temp_len >>= 8;
        }
        result.push_back(0x80 | len_bytes.size());
        result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    }
    return result;
}

std::vector<uint8_t> encode_integer(int32_t value) {
    std::vector<uint8_t> result;
    result.push_back(0x02);
    std::vector<uint8_t> value_bytes;
    if (value == 0) {
        value_bytes.push_back(0x00);
    }
    else {
        while (value != 0) {
            value_bytes.insert(value_bytes.begin(), value & 0xFF);
            value >>= 8;
        }
    }
    std::vector<uint8_t> len = encode_length(value_bytes.size());
    result.insert(result.end(), len.begin(), len.end());
    result.insert(result.end(), value_bytes.begin(), value_bytes.end());
    return result;
}

std::vector<uint8_t> encode_octet_string(const std::string& str) {
    std::vector<uint8_t> result;
    result.push_back(0x04);
    std::vector<uint8_t> len = encode_length(str.size());
    result.insert(result.end(), len.begin(), len.end());
    result.insert(result.end(), str.begin(), str.end());
    return result;
}

std::vector<uint8_t> encode_oid(const std::vector<uint32_t>& oid) {
    std::vector<uint8_t> result;
    result.push_back(0x06);
    std::vector<uint8_t> oid_bytes;
    oid_bytes.push_back(static_cast<uint8_t>(oid[0] * 40 + oid[1]));
    for (size_t i = 2; i < oid.size(); ++i) {
        uint32_t subid = oid[i];
        std::vector<uint8_t> subid_bytes;
        do {
            subid_bytes.insert(subid_bytes.begin(), subid & 0x7F);
            subid >>= 7;
        } while (subid > 0);
        for (size_t j = 0; j < subid_bytes.size() - 1; ++j) {
            subid_bytes[j] |= 0x80;
        }
        oid_bytes.insert(oid_bytes.end(), subid_bytes.begin(), subid_bytes.end());
    }
    std::vector<uint8_t> len = encode_length(oid_bytes.size());
    result.insert(result.end(), len.begin(), len.end());
    result.insert(result.end(), oid_bytes.begin(), oid_bytes.end());
    return result;
}

std::vector<uint8_t> encode_null() {
    return { 0x05, 0x00 };
}

std::vector<uint8_t> encode_sequence(const std::vector<uint8_t>& content, uint8_t tag = 0x30) {
    std::vector<uint8_t> result;
    result.push_back(tag);
    std::vector<uint8_t> len = encode_length(content.size());
    result.insert(result.end(), len.begin(), len.end());
    result.insert(result.end(), content.begin(), content.end());
    return result;
}

std::vector<uint8_t> build_snmp_get_request(const std::string& community, const std::vector<uint32_t>& oid) {
    std::vector<uint8_t> version = encode_integer(1);
    std::vector<uint8_t> community_str = encode_octet_string(community);
    std::vector<uint8_t> varbind_oid = encode_oid(oid);
    std::vector<uint8_t> varbind_value = encode_null();
    std::vector<uint8_t> varbind_content;
    varbind_content.insert(varbind_content.end(), varbind_oid.begin(), varbind_oid.end());
    varbind_content.insert(varbind_content.end(), varbind_value.begin(), varbind_value.end());
    std::vector<uint8_t> varbind = encode_sequence(varbind_content);
    std::vector<uint8_t> varbind_list = encode_sequence(varbind);
    std::vector<uint8_t> request_id = encode_integer(1);
    std::vector<uint8_t> error_status = encode_integer(0);
    std::vector<uint8_t> error_index = encode_integer(0);
    std::vector<uint8_t> pdu_content;
    pdu_content.insert(pdu_content.end(), request_id.begin(), request_id.end());
    pdu_content.insert(pdu_content.end(), error_status.begin(), error_status.end());
    pdu_content.insert(pdu_content.end(), error_index.begin(), error_index.end());
    pdu_content.insert(pdu_content.end(), varbind_list.begin(), varbind_list.end());
    std::vector<uint8_t> pdu = encode_sequence(pdu_content, 0xA0);
    std::vector<uint8_t> message_content;
    message_content.insert(message_content.end(), version.begin(), version.end());
    message_content.insert(message_content.end(), community_str.begin(), community_str.end());
    message_content.insert(message_content.end(), pdu.begin(), pdu.end());
    return encode_sequence(message_content);
}

std::string parse_snmp_response(const std::vector<uint8_t>& response) {
    size_t index = 0;
    auto expect_tag = [&](uint8_t expected_tag) {
        ++index;
        };
    auto parse_length = [&]() -> size_t {
        if (index >= response.size()) {
            throw std::runtime_error("Unexpected end of data while parsing length");
        }
        uint8_t len_byte = response[index++];
        if (len_byte < 128) {
            return len_byte;
        }
        else {
            size_t len_len = len_byte & 0x7F;
            size_t length = 0;
            for (size_t i = 0; i < len_len; ++i) {
                length = (length << 8) | response[index++];
            }
            return length;
        }
        };
    auto parse_sequence = [&]() -> size_t {
        expect_tag(0x30);
        return parse_length();
        };
    auto parse_integer = [&]() -> int32_t {
        expect_tag(0x02);
        size_t len = parse_length();
        int32_t value = 0;
        for (size_t i = 0; i < len; ++i) {
            value = (value << 8) | response[index++];
        }
        return value;
        };
    auto parse_octet_string = [&]() -> std::string {
        expect_tag(0x04);
        size_t len = parse_length();
        std::string str(response.begin() + index, response.begin() + index + len);
        index += len;
        return str;
        };
    parse_sequence();
    parse_integer();
    parse_octet_string();
    expect_tag(0xA2);
    parse_length();
    parse_integer();
    parse_integer();
    parse_integer();
    parse_sequence();
    parse_sequence();
    parse_octet_string();
    return parse_octet_string();
}

int main() {
    system("chcp 1251");
    std::string switch_ip = "192.168.10.2";
    int switch_port = 23;
    std::string username = "admin";
    std::string password = "admin123";

    try {
        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::resolver::results_type endpoints = resolver.resolve(switch_ip, std::to_string(switch_port));
        tcp::socket socket(io_context);
        boost::asio::connect(socket, endpoints);
        receive_response(socket);
        send_command(socket, username + "\n");
        std::this_thread::sleep_for(500ms);
        send_command(socket, password + "\n");
        std::this_thread::sleep_for(500ms);
        send_command(socket, "screen-length 0 temporary\n");
        std::this_thread::sleep_for(500ms);
        send_command(socket, "sys\n");
        std::this_thread::sleep_for(500ms);
        send_command(socket, "display interface brief\n");
        std::this_thread::sleep_for(500ms);
        std::string response = receive_response(socket);

        std::vector<interface_information> ports;

        std::istringstream response_stream(response);
        std::string line;
        std::string interface_name;

        while (std::getline(response_stream, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            std::istringstream stream(line);

            if (line.find("GigabitEthernet") == 0 || line.find("Ten-GigabitEthernet") == 0 || line.find("FortyGigE") == 0 || line.find("Ethernet") == 0) {
                std::string interface_name, phy_status, protocol_status, in_util, out_util;
                int in_errors, out_errors;

                stream >> interface_name >> phy_status >> protocol_status >> in_util >> out_util >> in_errors >> out_errors;

                in_util.erase(in_util.end() - 1);
                out_util.erase(out_util.end() - 1);

                interface_information port;
                strcpy_s(port.name, interface_name.c_str());
                port.phy_status = status_to_bool(phy_status);
                port.protocol_status = status_to_bool(protocol_status);
                port.in_utilization = std::stoi(in_util);
                port.out_utilization = std::stoi(out_util);
                port.in_errors = in_errors;
                port.out_errors = out_errors;
                ports.push_back(port);
            }
        }
        socket.close();

        for (auto& el : ports) {
            std::cout << el << '\n';
        }

        std::string community = "public";
        std::vector<uint32_t> oid = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
        std::vector<uint8_t> snmp_request = build_snmp_get_request(community, oid);

        udp::resolver udp_resolver(io_context);
        udp::endpoint receiver_endpoint = *udp_resolver.resolve(udp::v4(), switch_ip, "161").begin();
        udp::socket udp_socket(io_context);
        udp_socket.open(udp::v4());
        udp_socket.send_to(boost::asio::buffer(snmp_request), receiver_endpoint);

        std::vector<uint8_t> recv_buffer(1024);
        udp::endpoint sender_endpoint;
        size_t len = udp_socket.receive_from(boost::asio::buffer(recv_buffer), sender_endpoint);
        recv_buffer.resize(len);

        std::string sys_descr = parse_snmp_response(recv_buffer);
        std::cout << "System Description: " << sys_descr << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
