/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#ifndef MAIN_H
#define MAIN_H

#include <bitcoin/bitcoin.hpp>
#include <string>
//#include "util.hpp"

using namespace bc;

//Types
enum connection_state
{
  CONNECTING,
  CONNECTED,
  DISCONNECTED
};

struct peer_address
{
  std::string ip;
  uint16_t port;
  int instance_num; // If we establish several connections to the same peer.
  uint32_t failed_tries; // Don't try to connect anymore if we exceed the limit
  connection_state state; // Keep connection state to decide when to reconnect
  bool fGetAddrSentConfirmed; // false if we are still waiting a successful sent notification of 'getaddr' message
  int numGetAddrToSend; // Number of getaddr messages we need to send
  int addr_timeoffset; // Offset for addresses which we send as a payload in 'addr' messages
  int pong_remained; // How many pong messages we need to wait for.
  int pong_waittime; // Until which we should wait for a 'pong' messages. This relies on that we receive other
                     // 'raw' messages. Once we receive a non-pong raw message, we check if pong_waittime has come;
		     // if yes we descrease pong_remained by one.
   bool fInbound; // Set to true if connection is incoming
};


typedef std::map<std::string,peer_address> peers_map;

// Constants and global variables
const uint32_t MIN_TIME_BETWEEN_UPDATES = 3; // Minimum time (in seconds) to wait before updating <mPeersAddresses> from file
const hash_digest NULL_HASH = {0,0,0,0, 0,0,0,0,
                               0,0,0,0, 0,0,0,0,
                               0,0,0,0, 0,0,0,0,
                               0,0,0,0, 0,0,0,0};

extern uint32_t num_open_connections; // Stores totoal number of open connections
extern peers_map mPeersAddresses; // Map of bitcoin peers which we believe are up
extern int addr_per_addr_message; //  Number of addresses per address message (according to the Bitcoin protocol, <=10 means the addresses will be forwarded
extern int numGetAddrToSend; // Number of 'getaddr' message we need to send
extern std::vector<std::string> vPayloadAddresses; // The adress which will be included as the payload into the 'addr' message
extern std::mutex mPeersAddresses_lock;
extern time_t peers_timestamp; // Epoch time of the peers (in case peers_file is provided); shows freshness of address in the file
extern time_t last_peers_updatetime; // When we updated <mPeersAddresses> last time
extern std::set<hash_digest> old_blocks; // Hashes of old blocks, for which we will ignore 'inv' messages
extern bool stop_execution; // If the user types 'stop' then this value is set to true, and the main loop breaks.

// Data structures to track already received objects
extern std::set<hash_digest> seen_tx; // Hashes of recevied transactions
extern std::mutex seen_tx_lock;
extern std::set<hash_digest> seen_blocks; // Hashes of received blocks. For seen blocks we print 'inv' messages. For old blocks we don't.
extern std::mutex seen_blocks_lock;

#endif
