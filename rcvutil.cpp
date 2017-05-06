/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#include "main.hpp"
#include "util.hpp"
#include "rcvutil.hpp"
#include "sendutil.hpp"
#include <boost/algorithm/string.hpp>
#include <string>

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

void version_sent(const std::error_code& ec, channel_ptr node)
{
    if (ec)
        log_error() << "Sending version: " << ec.message();
    else
        log_debug() << "Version sent.";
}

void get_data_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr)
{
    if (ec)
        log_error() << "Sending get_data: " << ec.message();
    else
        log_debug() << "Get_data sent (to=" << remote_addr.ip << ":" << remote_addr.port << ")";
}

void verack_sent(const std::error_code& ec, channel_ptr node)
{
    if (ec)
        log_error() << "Sending verack: " << ec.message();
    else
        log_debug() << "Verack sent.";
}

/* Log the information contained in the received 'version' message
   Send our verack message after we received 'verack' from <node> 
   Drop the failure statistics and set state to 'CONNECTED'
*/
void version_received(const std::error_code& ec, const version_type& version, channel_ptr node, struct peer_address& sender_addr, bool resubs)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {
      log_error() << "Version message: " << ec.message();
      return;
    }
    //log_info() << "Remote endpoint: " << node->get_remote_endpoint();
    log_info() << "Version received. peer=" << peer_address_to_string(sender_addr) << 
                   ", useragent=" << version.user_agent << ", timestamp=" << version.timestamp << ", localtime=" << time(NULL);
    if (resubs)
      node->subscribe_version(std::bind(version_received, _1, _2, node, sender_addr, resubs));
    verack_type verack1;
    log_info() << "Sending verack";
    node->send(verack1, std::bind(verack_sent, _1, node));
    // Successfully fully connected (i.e. received 'version' message) to the node. Drop failure statistics
     mPeersAddresses_lock.lock();
     if(!(mPeersAddresses[peer_address_to_string(sender_addr)].fInbound)) // failed_tries should be 9999 for all inbound connections in order to avoid reconnects
       mPeersAddresses[peer_address_to_string(sender_addr)].failed_tries = 0;
     mPeersAddresses[peer_address_to_string(sender_addr)].state = CONNECTED;
     mPeersAddresses_lock.unlock();
}

void getaddr_sent(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr)
{
    if (ec)
        log_error() << "Sending 'getaddr' message: " << ec.message();
    else
        log_info() << "'getaddr' message sent. peer=" << peer_address_to_string(remote_addr);
    mPeersAddresses[peer_address_to_string(remote_addr)].fGetAddrSentConfirmed = true;
}

/* We received 'verack', hence the link is ready and we can send other messages
   We first send 'getaddr' separately. The reason is that we need to wait for a reply in an 'addr'
   message (i.e. we cannot go to sendutil.cpp but  need to stay in this file). 
*/
void verack_received(const std::error_code& ec, const verack_type& verack, channel_ptr node, struct peer_address& sender_addr,
                      std::vector<std::string> send_msgs)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {
      log_error() << "Verack message: " << ec.message();
      return;
    }
    log_info() << "Verack received. peer=" << peer_address_to_string(sender_addr);

    // Send the first 'getaddr', other messages will be sent when we recieved a reply in an 'addr' message
    if (mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend > 0)
    {
      log_info() << "Sending get_addr #" << mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend << ". peer=" << peer_address_to_string(sender_addr);
      get_address_type getaddr_message;
      mPeersAddresses[peer_address_to_string(sender_addr)].fGetAddrSentConfirmed = false;
      mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend--;
      node->send(getaddr_message, std::bind(getaddr_sent, _1, node, sender_addr));
    }

    // Send others
    send_messages(send_msgs, node, sender_addr);
}

/* Log the input scripts of the received transaction.
   In the majority of cases, for each input we will have
   [ <sig> ] [ <Pubkey> ]. Thus in the majority of cases this function will
   print:
   inputs=[{[ <sig1> ] [ <Pubkey1> ]},{[ <sig2> ] [ <Pubkey2> ]}, ... ]
*/
void transaction_received(const std::error_code& ec, const transaction_type& tx, channel_ptr node, struct peer_address& sender_addr)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {   
      log_error() << "Transaction message: " << ec.message();
      return;
    }

    //seen_tx_lock.lock();
    //auto is_inserted = seen_tx.insert(hash_transaction(tx));
    //log_info() << "Inserted new tx hash to the list of seen tx. New size of the set is " << seen_tx.size();
    //seen_tx_lock.unlock();
    
    // Don't print long inputs if we've already seen this transaction and hence printed the inputs
    //if (is_inserted.second)
    if (true)
    {
      std::string buff = "[";
      // Collect all coinbase outputs into a buffer
      int i=0;
      for(i=0;i<tx.inputs.size();i++)
      {
        buff += "{";
        buff += pretty(tx.inputs[i].script);
        buff += "},";
      }
      buff += "]";
      log_debug() << "Received transaction. from=" << peer_address_to_string(sender_addr) <<
      		  ", hash=" << encode_hex(hash_transaction(tx)) <<
      		  ", inputs=" << buff;
      log_info() << "r:tx:" << encode_hex(hash_transaction(tx)) << "," <<
                     peer_address_to_string(sender_addr) << "," << buff;
    } else
    {
      //log_info() << "Received transaction. from=" << peer_address_to_string(sender_addr) <<
      //		  ", hash=" << encode_hex(hash_transaction(tx)) <<
      //		  ", inputs=<already_seen>";
    }
    node->subscribe_transaction(std::bind(transaction_received, _1, _2, node, sender_addr));
    return;
}


/* Do some checks on the received block and log info about the block.
   Checks: - zero transactions
           - more than one inputs in the coinbase transaction
	   - coinbase transaction references non-null block and sequence
   Prints: - general blocks info
           - coinbase outputs
   Does
   not
   print:  - Info about non-coinbase transactions
*/
void block_received(const std::error_code& ec, const block_type& block, channel_ptr node, struct peer_address& sender_addr)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {   
      log_error() << "Block message: " << ec.message();
      return;
    }
    const hash_digest& blk_hash = hash_block_header(block.header);
    if(block.transactions.size() == 0)
    {
      log_info() << "Bogus block (with no transactions) received. hash=" << encode_hex(blk_hash);
      node->subscribe_block(std::bind(block_received, _1, _2, node, sender_addr));
      return;
    }

    transaction_type coinbase = block.transactions[0];

    if(coinbase.inputs.size() != 1)
    {
      log_info() << "Bogus block (with more than one coinbase input) received. hash=" << encode_hex(blk_hash);
      node->subscribe_block(std::bind(block_received, _1, _2, node, sender_addr));
      return;
    }

    transaction_input_type coinbase_input = coinbase.inputs[0];

    if( (memcmp(coinbase_input.previous_output.hash.data(),NULL_HASH.data(),hash_digest_size) != 0) ||
             (coinbase_input.previous_output.index != -1))
    {
      log_info() << "Bogus block (with non-null prevout in coinbase) received. hash=" << encode_hex(blk_hash);
      log_info() << "prev_hash=" << encode_hex(coinbase_input.previous_output.hash) <<
                    ", out_index=" << int(coinbase_input.previous_output.index);
      node->subscribe_block(std::bind(block_received, _1, _2, node, sender_addr));
      return;
    }

    //seen_blocks_lock.lock();
    //auto is_inserted = seen_blocks.insert(blk_hash);
    //log_info() << "Inserted new block hash to the list of seen blocks. New size of the set is " << seen_blocks.size();
    //seen_blocks_lock.unlock();
    
    // Don't print detailed block info if we've already seen this block and hence printed it
    //if (is_inserted.second)
    if (true)
    {
      std::string buff = "[";
      // Collect all coinbase outputs into a buffer
      int i=0;
      for(i=0;i<coinbase.outputs.size();i++)
      {
        buff += "{";
        buff += std::to_string(coinbase.outputs[i].value);
        buff += ",";
        buff += pretty(coinbase.outputs[i].script);
        buff += "},";
      }
      buff += "]";
      log_debug() << "Block received. from=" << sender_addr.ip << ":" << sender_addr.port << 
                    ", hash=" << encode_hex(blk_hash) << 
                    ", prev_hash=" << block.header.previous_block_hash <<
                    ", tx_num= " << block.transactions.size() <<
                    ", coinbase_in_count=" << coinbase.inputs.size() <<
                    ", coinbase_out_count=" << coinbase.outputs.size() <<
                    ", coinbase_prevout={" << coinbase.inputs[0].previous_output.hash << 
                    "," <<  (int)(coinbase.inputs[0].previous_output.index) << "}" <<
          	  ", coinbase_outputs=" << buff;
      log_info() << "r:bl:" << encode_hex(blk_hash) << "," << peer_address_to_string(sender_addr) << "," << buff;
     } else
      log_info() << "Block received. from=" << peer_address_to_string(sender_addr) << 
                    ", hash=" << encode_hex(blk_hash) <<  ", details=<already_seen>";

    // Resubscribe to block rcv events
    node->subscribe_block(std::bind(block_received, _1, _2, node, sender_addr));
}

void inv_received(const std::error_code& ec, const inventory_type& inv, channel_ptr node, struct peer_address& sender_addr)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {   
      log_error() << "Inv message: " << ec.message();
      return;
    }   
    
    struct get_data_type get_data;
    get_data.inventories.clear();
    for (std::vector<inventory_vector_type>::const_iterator it = inv.inventories.begin(); it != inv.inventories.end(); ++it)
    {
        // Print 'inv' message only if the block is not old. 
        if( !((it->type == inventory_type_id::block) && (old_blocks.count(it->hash) != 0)) )
        {
          log_debug() << "Inv received. from=" << sender_addr.ip << ":" << sender_addr.port << ", type=" << 
                     ((it->type == inventory_type_id::transaction) ? "tx" : "" ) <<
                     ((it->type == inventory_type_id::block) ? "block" : "" ) <<
                     ((it->type == inventory_type_id::none) ? "none" : "" ) <<
                     ((it->type == inventory_type_id::none) ? "error" : "" ) << 
                     ", hash=" << it->hash;

          log_info() << "r:" <<
                     ((it->type == inventory_type_id::transaction) ? "itx:" : "" ) <<
                     ((it->type == inventory_type_id::block) ? "ibl:" : "" ) <<
                     ((it->type == inventory_type_id::none) ? "ino:" : "" ) <<
                     ((it->type == inventory_type_id::none) ? "ier:" : "" ) << 
                     it->hash << "," << peer_address_to_string(sender_addr);
        }

        if((it->type == inventory_type_id::transaction) && (seen_tx.count(it->hash) == 0) )
        {
          seen_tx_lock.lock();
          auto is_inserted = seen_tx.insert(it->hash);
          log_info() << "Inserted new tx hash to the list of seen tx. New size of the set is " << seen_tx.size();
          seen_tx_lock.unlock();
          get_data.inventories.push_back(*it);
        } else

        if((it->type == inventory_type_id::transaction) && (seen_tx.count(it->hash) != 0) )
          log_debug() << "tx hash is known. Will not send get_data";
        else

        if((it->type == inventory_type_id::block) && (seen_blocks.count(it->hash) == 0) && (old_blocks.count(it->hash) == 0))
        {
          seen_blocks_lock.lock();
          auto is_inserted = seen_blocks.insert(it->hash);
          log_info() << "Inserted new block hash to the list of seen blocks. New size of the set is " << seen_blocks.size();
          seen_blocks_lock.unlock();
          get_data.inventories.push_back(*it);
        } else

        if((it->type == inventory_type_id::block) && (seen_blocks.count(it->hash) != 0) )
          log_debug() << "block hash is known. Will not send get_data";
       
    }
    if(!get_data.inventories.empty())
      node->send(get_data, std::bind(get_data_sent, _1, node, sender_addr));
    // Resubscribe to inv rcv events
    node->subscribe_inventory(std::bind(inv_received, _1, _2, node, sender_addr));
}


/* Parses received address message.
    -- For each address print 'r:addr:ip,port,timestamp'.
    -- Send one 'getaddr' if there are left to send and decrease the number to be sent by one
*/
void address_received(const std::error_code& ec, const address_type& addr_msg, channel_ptr node,
                       struct peer_address& sender_addr)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {
      log_error() << "Address message: " << ec.message() << ". peer=" << peer_address_to_string(sender_addr);
      return;
    }
    log_info() << "Address message received, number of addresses: " << addr_msg.addresses.size() << ". peer=" << peer_address_to_string(sender_addr);
    int i = 0;
    for (i=0 ; i<addr_msg.addresses.size();i++)
    { 
      uint32_t timestamp = addr_msg.addresses[i].timestamp;
      ip_address_type ip = addr_msg.addresses[i].ip;
      uint16_t port = addr_msg.addresses[i].port;
      log_info() << "r:addr:"
                 << (is_ipv4(ip) ? format_ipv4addr(ip) : format_ipv6addr(ip))
		 << "," << port << "," << timestamp << "," << peer_address_to_string(sender_addr);
    }
    log_info() << "End of Address message" << ". peer=" << peer_address_to_string(sender_addr);
    node->subscribe_address(std::bind(address_received, _1, _2, node, sender_addr));

    // Send a 'getaddr' message if we have some left and the previous one was successfully sent
    // Note that the very first 'getaddr' message (if any) was sent when we received 'verack' message
    //log_info() << "Should I send get_addr? numGetAddrToSend=" << mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend << "; getaddrconf= " << ((mPeersAddresses[peer_address_to_string(sender_addr)].fGetAddrSentConfirmed) ? "true" : "false");
    if (mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend > 0 && mPeersAddresses[peer_address_to_string(sender_addr)].fGetAddrSentConfirmed)
    {
      log_info() << "Sending get_addr #" << mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend << ". peer=" << peer_address_to_string(sender_addr);
      mPeersAddresses[peer_address_to_string(sender_addr)].fGetAddrSentConfirmed = false;
      mPeersAddresses[peer_address_to_string(sender_addr)].numGetAddrToSend--;
      get_address_type getaddr_message;
      node->send(getaddr_message, std::bind(getaddr_sent, _1, node, sender_addr));
    }
}

/* Parses received get_address message.
   Print that we received this message
*/
void get_address_received(const std::error_code& ec, const get_address_type& get_addr_msg, channel_ptr node,
                       struct peer_address& sender_addr)
{
    if (ec == error::service_stopped)
      return;
    else if (ec)
    {
      log_error() << "GetAddress message: " << ec.message() << ". peer=" << peer_address_to_string(sender_addr);
      return;
    }
    log_info() << "GetAddress message received. peer=" << peer_address_to_string(sender_addr);
    node->subscribe_get_address(std::bind(get_address_received, _1, _2, node, sender_addr));
}

// Peer event handlers
void node_stopped(const std::error_code& ec, struct peer_address& remote_addr)
{
    if (ec == error::service_stopped)
      log_info() << peer_address_to_string(remote_addr) << ": Connection closed.";
    else if (ec)
      log_error() << peer_address_to_string(remote_addr) << ": Connection closed: " << ec.message();
    num_open_connections--;
    mPeersAddresses_lock.lock();
    mPeersAddresses[peer_address_to_string(remote_addr)].failed_tries++;
    mPeersAddresses[peer_address_to_string(remote_addr)].state = DISCONNECTED;
    mPeersAddresses_lock.unlock();
}

void send_first_getaddr()
{

}


void subscribe_to_events(channel_ptr node, std::vector<std::string>& listen_msgs, std::vector<std::string>& send_msgs, struct peer_address& remote_addr)
{
    node->subscribe_stop(std::bind(node_stopped, _1, remote_addr));

    // Version
    bool resubs = false; // Resubscribed to 'version' messages if true
    if (std::find(listen_msgs.begin(), listen_msgs.end(), "idle") != listen_msgs.end()) 
      resubs = true;
    if((mPeersAddresses[peer_address_to_string(remote_addr)].fInbound)) // Do not disconnect inbound connection
      resubs = true;
    node->subscribe_version(std::bind(version_received, _1, _2, node, remote_addr, resubs));

    // Block
    if (std::find(listen_msgs.begin(), listen_msgs.end(), "block") != listen_msgs.end() || 
         std::find(listen_msgs.begin(), listen_msgs.end(), "all") != listen_msgs.end())
      node->subscribe_block(std::bind(block_received, _1, _2, node, remote_addr));
    
    // Transaction
    if (std::find(listen_msgs.begin(), listen_msgs.end(), "tx") != listen_msgs.end() ||
         std::find(listen_msgs.begin(), listen_msgs.end(), "all") != listen_msgs.end())
      node->subscribe_transaction(std::bind(transaction_received, _1, _2, node, remote_addr));

    // Inventory (will ask for corresponding tx and blocks)
    if (std::find(listen_msgs.begin(), listen_msgs.end(), "inv") != listen_msgs.end() ||
         std::find(listen_msgs.begin(), listen_msgs.end(), "all") != listen_msgs.end())
      node->subscribe_inventory(std::bind(inv_received, _1, _2, node, remote_addr));

    // Addresses
    if (std::find(listen_msgs.begin(), listen_msgs.end(), "addr") != listen_msgs.end() ||
         std::find(listen_msgs.begin(), listen_msgs.end(), "all") != listen_msgs.end())
        node->subscribe_address(std::bind(address_received, _1, _2, node, remote_addr));

    // GetAddress
    if (std::find(listen_msgs.begin(), listen_msgs.end(), "getaddr") != listen_msgs.end() ||
         std::find(listen_msgs.begin(), listen_msgs.end(), "all") != listen_msgs.end())
        node->subscribe_get_address(std::bind(get_address_received, _1, _2, node, remote_addr));

    // Verack received is the entry point for all messages we are going to send
    node->subscribe_verack(std::bind(verack_received, _1, _2, node, remote_addr, send_msgs));

}

/* TCP-connected to a peer
   Thoug we have TCP-connected, wait until we received a 'version' message before
   droping failure statistics.
*/
void connect_started(const std::error_code& ec, channel_ptr node, struct peer_address& remote_addr,
                         std::vector<std::string>& listen_msgs,
                         std::vector<std::string>& send_msgs)
{
    if (ec)
    {
        log_error() << "Failed connect (try " << remote_addr.failed_tries+1 <<
                       ") to " << peer_address_to_string(remote_addr) <<
                       " failed (" << ec.message() << ")";
        num_open_connections--;
        mPeersAddresses_lock.lock();
        mPeersAddresses[peer_address_to_string(remote_addr)].failed_tries++;
        mPeersAddresses[peer_address_to_string(remote_addr)].state = DISCONNECTED;
        mPeersAddresses_lock.unlock();
        return;
    }


    // Create our version message we want to send.
    // Fill in a bunch of fields.
    version_type version;
    version.version = 70001;
    version.services = 1;
    version.timestamp = time(NULL);
    version.address_me.services = version.services;
    version.address_me.ip =
        ip_address_type{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0xff, 0xff, 0xd8, 0x96, 0x9b, 0x97}; // Despite the name, it's Recipient Address,  
			                                                 // see ./include/bitcoin/satoshi_serialize.hpp +48 for serialization.
    version.address_me.port = 8333;
    version.address_you.services = version.services;
    version.address_you.ip =
        ip_address_type{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0xff, 0xff, 0xd8, 0x96, 0x9b, 0x97}; // It's Sender Address,
			                                                 // let's put the students residence external ip address,
									 // 
    version.address_you.port = 8333;
    // Set the user agent.
    version.user_agent = "/xbadprobe:1.0/";
    version.start_height = 0;
    version.nonce = rand();

    subscribe_to_events(node, listen_msgs, send_msgs, remote_addr);

    // Finally send version message
    log_info() << "Sending version message";
    node->send(version, std::bind(version_sent, _1, node));
    verack_type verack1;
    log_info() << "Sending verack";
    node->send(verack1, std::bind(verack_sent, _1, node));
    return;
}

void listening_started(const std::error_code& ec, acceptor_ptr accept,
                         std::vector<std::string>& listen_msgs,
                         std::vector<std::string>& send_msgs)
{
    if (ec)
    {
        log_error() << "Listen: " << ec.message();
        return;
    }
    // Accept first connection.
    accept->accept(
        std::bind(accepted_connection, _1, _2, accept, listen_msgs, send_msgs));
}

void accepted_connection(const std::error_code& ec, channel_ptr node, acceptor_ptr accept,
                         std::vector<std::string>& listen_msgs,
                         std::vector<std::string>& send_msgs)
{
    if (ec)
    {
        log_error() << "Accept: " << ec.message();
        return;
    }
    num_open_connections++;
    log_info() << "Accepted connection: " << node->get_remote_endpoint();
    log_info() << "Creating corresponing struct peer_address object";
    struct peer_address addr;

    std::vector<std::string> tokens;
    std::string ip_port_string = node->get_remote_endpoint();
    boost::split(tokens, ip_port_string, boost::is_any_of(":"));

    addr.ip = tokens[0];
    addr.port = atoi(tokens[1].c_str());
    addr.failed_tries = 9999; // This is to avoid reconnecting if this node suddenly drops
    addr.state = CONNECTED;
    addr.numGetAddrToSend = numGetAddrToSend;
    addr.addr_timeoffset = 0;
    addr.pong_remained = 0; // UNUSED
    addr.pong_waittime = 0; // UNUSED
    addr.fGetAddrSentConfirmed = false;
    addr.instance_num = 1; // This differentiate nodes with the same ip:port. For incoming connections the port is unique, so this field can be anything
    addr.fInbound = true;
    mPeersAddresses[peer_address_to_string(addr)] = addr;

    connect_started(ec, node, addr, listen_msgs, send_msgs);
    accept->accept(
        std::bind(accepted_connection, _1, _2, accept, listen_msgs, send_msgs));
}
