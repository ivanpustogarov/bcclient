/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#ifndef SENDUTIL_H
#define SENDUTIL_H

#include <bitcoin/bitcoin.hpp>
#include <string>

using namespace bc;

// Send messages, if we need to send 'addr' messages, then the addresses are taken from global variable
void send_messages(std::vector<std::string> send_msgs, channel_ptr node, struct peer_address& remote_addr);

#endif
