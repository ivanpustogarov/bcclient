/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#ifndef UTIL_H
#define UTIL_H

#include "main.hpp"
#include <bitcoin/bitcoin.hpp>
#include <string>

using namespace bc;

// Logger handlers
void output_to_null(std::ofstream& file, log_level level, const std::string& domain, const std::string& body);
void output_to_file(std::ofstream& file, log_level level, const std::string& domain, const std::string& body);
void output_to_terminal(log_level level, const std::string& domain, const std::string& body);

// Output formatting
std::string format_ipv6addr(ip_address_type ip);
std::string format_ipv4addr(ip_address_type ip);
bool is_ipv4(ip_address_type ip);
std::string peer_address_to_string(struct peer_address addr);

// String to bc address type conversion
struct network_address_type make_bc_addr(const std::string ip_str, long int timestamp_offset);

#endif
