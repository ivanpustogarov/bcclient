/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#include "main.hpp"
#include "util.hpp"
#include "sendutil.hpp"

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

// In seconds
#define PONG_WAIT_TIME 10

void ping_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr)
{
    if (ec)
        log_error() << "Sending ping: " << ec.message();
    else
        log_info() << "Ping sent" << 
                 ", peer=" << peer_address_to_string(remote_addr);
}

/* Creates a block with an empty transactions list,
   this block will be rejected by the peer and the
   peer will ban us for 24 hours.
*/ 
block_type create_bogus_block()
{
    block_type bogus_block;
    bogus_block.header.version = 70001;
    hash_digest previous_block_hash = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    bogus_block.header.previous_block_hash = previous_block_hash;
    bogus_block.header.merkle = previous_block_hash;
    bogus_block.header.timestamp = 3793031245;
    bogus_block.header.bits = 19262222;
    bogus_block.header.nonce = rand();
    std::vector<transaction_type> vtx_empty;
    bogus_block.transactions = vtx_empty;
    return bogus_block;
}

void raw_received(const std::error_code& ec, const header_type& header, const data_chunk& data, channel_ptr node, struct peer_address& remote_addr) 
{
  if (ec == error::service_stopped)
    return;
  else if (ec)
  {
    log_error() << "Raw message: " << ec.message();
    return;
  }
  log_info() << "Received a raw message, type=" << header.command <<
                 ", peer=" << peer_address_to_string(remote_addr);
  if( (header.command == "pong") || (remote_addr.pong_waittime <= time(NULL)) )
  {
    remote_addr.pong_remained--;
    remote_addr.pong_waittime = time(NULL) + PONG_WAIT_TIME;
  }
  if( (header.command == "reject"))
    remote_addr.pong_remained = 0;
  log_debug() << "raw_received(): number of pong messages to receive=" << remote_addr.pong_remained <<
                 ", peer=" << peer_address_to_string(remote_addr);
  if(remote_addr.pong_remained > 0)
    node->subscribe_raw(std::bind(raw_received, _1, _2, _3, node, remote_addr));
  return;
}

void block_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr)
{
    if (ec)
        log_error() << "Sending block: " << ec.message();
    else
        log_info() << "Block sent," << " peer=" << peer_address_to_string(remote_addr);
    ping_type ping;
    ping.nonce = 43;
    // TODO: I don't know if subsribing to raw messages will cancel subsribing to
    //       other messages (tx, block, inv). I assume that I will still get two
    //       notifications: first for the raw messages and second for the corresponging
    //       tx/block/inv message.
    log_debug() << "block_sent(): Sending ping to " << " peer=" << peer_address_to_string(remote_addr);;
    remote_addr.pong_remained++;
    remote_addr.pong_waittime = time(NULL)+PONG_WAIT_TIME;
    log_debug() << "block_sent(): number of pong messages to receive = " << remote_addr.pong_remained <<
                 ", peer=" << peer_address_to_string(remote_addr);
    node->subscribe_raw(std::bind(raw_received, _1, _2, _3, node, remote_addr));
    node->send(ping, std::bind(ping_sent, _1, node, remote_addr));
}

void sendblock(channel_ptr node, struct peer_address& remote_addr)
{
  block_type bogus_block = create_bogus_block();
  log_info() << "Sending 'bogus_block' message. Size = " << sizeof(bogus_block) <<
                ", peer=" << peer_address_to_string(remote_addr);
  node->send(bogus_block, std::bind(block_sent, _1, node, remote_addr));
  return;
}


void tx_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr)
{
    if (ec)
        log_error() << "Sending tx: " << ec.message();
    else
        log_info() << "Transaction sent." << " peer=" << peer_address_to_string(remote_addr);
    // Request a pong message so that we don't disconnect until the
    // peer gets the transaction.
    ping_type ping;
    ping.nonce = 42;
    // TODO: I don't know if subsribing to raw messages will cancel subsribing to
    //       other messages (tx, block, inv). I assume that I will still get two
    //       notifications: first for the raw messages and second for the corresponging
    //       tx/block/inv message.
    log_debug() << "tx_sent(): Sending ping to " << " peer=" << peer_address_to_string(remote_addr);;
    remote_addr.pong_remained++;
    remote_addr.pong_waittime = time(NULL)+PONG_WAIT_TIME;
    log_debug() << "tx_sent(): number of pong messages to receive=" << remote_addr.pong_remained <<
                 ", peer=" << peer_address_to_string(remote_addr);
    node->subscribe_raw(std::bind(raw_received, _1, _2, _3, node, remote_addr));
    node->send(ping, std::bind(ping_sent, _1, node, remote_addr));
}

void sendtx(channel_ptr node, struct peer_address& remote_addr)
{
  //log_info() << "sendtx(): NOT IMPLEMENTED";
  transaction_type bogus_tx;
  bogus_tx.version = 1;
  bogus_tx.locktime = 0;

  transaction_input_list inputs;
    struct transaction_input_type input;
      struct output_point out_point;
      hash_digest hash = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      out_point.hash = hash;
      out_point.index = -1;
      script_type in_script;
    input.previous_output = out_point;
    input.script = in_script;
    input.sequence = 0;
  inputs.push_back(input);

  transaction_output_list outputs;
    struct transaction_output_type output;
      script_type out_script;
    output.value=25000; 
    output.script = out_script;
  outputs.push_back(output);

  bogus_tx.inputs = inputs;
  bogus_tx.outputs = outputs;

  log_info() << "Sending 'bogus_tx' message. Size = " << sizeof(bogus_tx) <<
                ", peer=" << peer_address_to_string(remote_addr);
  node->send(bogus_tx, std::bind(tx_sent, _1, node, remote_addr));

  return;
}

void addr_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr,
               int start_idx)
{
    if (ec)
      log_error() << "Sending 'addr' message: " << ec.message();
    else
    {
      log_info() << "'addr' message sent." << " peer=" << peer_address_to_string(remote_addr);
      struct address_type addr_message;
      int i = start_idx;
      for (i=start_idx ; i<vPayloadAddresses.size();i++)
      {
        network_address_type addr = make_bc_addr(vPayloadAddresses[i], remote_addr.addr_timeoffset);
        if (addr.port == 0)
          continue;
        addr_message.addresses.push_back(addr);
        if ( addr_message.addresses.size() >= addr_per_addr_message)
        {
          int msg_num = (i+1)/addr_per_addr_message;
          log_info() << "Sending 'addr' message " << msg_num << ". Size = " << addr_message.addresses.size() <<
	                ". peer=" << peer_address_to_string(remote_addr);
          node->send(addr_message, std::bind(addr_sent, _1, node, remote_addr, i+1));
	  return;
        }
      }
      if ( !(addr_message.addresses.empty()) )
      {
        int msg_num = (i+1)/addr_per_addr_message;
        log_info() << "Sending 'addr' message " << msg_num << ". Size = " << addr_message.addresses.size() <<
	                ". peer=" << peer_address_to_string(remote_addr);
        node->send(addr_message, std::bind(addr_sent, _1, node, remote_addr, i+1));
	  return;
      }
    }
}

void sendaddr(channel_ptr node, struct peer_address& remote_addr)
{
    struct address_type addr_message;
    int i = 0;
    for (i=0 ; i<vPayloadAddresses.size();i++)
    {
      network_address_type addr = make_bc_addr(vPayloadAddresses[i], remote_addr.addr_timeoffset);
      if (addr.port == 0)
        continue;
      addr_message.addresses.push_back(addr);
      if ( addr_message.addresses.size() >= addr_per_addr_message )
      {
	int msg_num = (i+1)/addr_per_addr_message;
        log_info() << "Sending 'addr' message " << msg_num << ". Size = " << addr_message.addresses.size() <<
	                ". peer=" << peer_address_to_string(remote_addr);
        node->send(addr_message, std::bind(addr_sent, _1, node, remote_addr, i+1));
	return;
      }
    }
    if ( !(addr_message.addresses.empty()) )
    {
      int msg_num = (i+1)/addr_per_addr_message;
      log_info() << "Sending 'addr' message " << msg_num << ". Size = " << addr_message.addresses.size() <<
	                ". peer=" << peer_address_to_string(remote_addr);
      node->send(addr_message, std::bind(addr_sent, _1, node, remote_addr,  i+1));
    }
    return;
}

void send_messages(std::vector<std::string> send_msgs, channel_ptr node, struct peer_address& remote_addr)
{
  // Block
  if (std::find(send_msgs.begin(), send_msgs.end(), "block") != send_msgs.end())
    sendblock(node, remote_addr);
  // Transaction
  if (std::find(send_msgs.begin(), send_msgs.end(), "tx") != send_msgs.end())
    sendtx(node, remote_addr);
  // Addr
  if (std::find(send_msgs.begin(), send_msgs.end(), "addr") != send_msgs.end())
    sendaddr(node, remote_addr);
  return;
}

