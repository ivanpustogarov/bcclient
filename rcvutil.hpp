/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#ifndef RCVUTIL_H
#define RCVUTIL_H

#include <bitcoin/bitcoin.hpp>
#include <string>

using namespace bc;

// Version message finished sending.
void version_sent(const std::error_code& ec, channel_ptr node);
void get_data_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr);
// Verack message finished sending.
void verack_sent(const std::error_code& ec, channel_ptr node);
void block_sent(const std::error_code& ec, channel_ptr node);
// Version message received.
// Display the user agent.
void version_received(const std::error_code& ec, const version_type& version, channel_ptr node, struct peer_address& sender_addr, bool resubs);
void address_received(const std::error_code& ec, const address_type& version, channel_ptr node, struct peer_address& sender_addr);
void verack_received(const std::error_code& ec, const verack_type& verack, channel_ptr node, struct peer_address& sender_addr,
                     std::vector<std::string> send_msgs);
void block_received(const std::error_code& ec, const block_type& block,channel_ptr node, struct peer_address& sender_addr);
void transaction_received(const std::error_code& ec, const transaction_type& block,channel_ptr node, struct peer_address& sender_addr);
void inv_received(const std::error_code& ec, const inventory_type& inv, channel_ptr node, struct peer_address& sender_addr);
void node_stopped(const std::error_code& ec, struct peer_address& remote_addr);
void connect_started(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr,
                     std::vector<std::string>& listen_msgs,
                     std::vector<std::string>& send_msgs);
void listening_started(const std::error_code& ec, acceptor_ptr accept,
                         std::vector<std::string>& listen_msgs,
                         std::vector<std::string>& send_msgs);
void accepted_connection(const std::error_code& ec, channel_ptr node, acceptor_ptr accept,
                         std::vector<std::string>& listen_msgs,
                         std::vector<std::string>& send_msgs);

#endif
