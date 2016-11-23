/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */


#include "util.hpp"
#include "rcvutil.hpp"
#include "main.hpp"

#include <bitcoin/bitcoin.hpp>
#include <boost/algorithm/string.hpp>
#include <string>
#include <utility>
#include <thread>
#include <chrono>
#include <functional>
#include <atomic>
#include <getopt.h>
#include <signal.h>

using namespace bc;

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

#define PACKAGE    "bcclient"
#define VERSION    "0.1"

const std::string LOCK_FILE = "PEERSLOCK";
//const int DELAY_BETWEEN_CONNECTIONS_MICRO = 100000;
int delay_between_connections_micro = 100000;
uint32_t max_failed_tries = 3; // Maximum number of failed tries, before a node is excluded from the list of peers 
uint32_t num_open_connections = 0; // Stores totoal number of open connections
static int fExitWhenAllConnected = 0; // Exit when all inidicated nodes sent 'version' messages
peers_map mPeersAddresses; // Map of bitcoin peers which we believe are up
int addr_per_addr_message = 100; //  Number of addresses per address message (according to the Bitcoin protocol, <=10 means the addresses will be forwarded
std::vector<std::string> vPayloadAddresses; // The adress which will be included as the payload into the 'addr' message
int numGetAddrToSend = 0; // Number of 'getaddr' message we need to send
std::mutex mPeersAddresses_lock;
time_t peers_timestamp = 0; // Epoch time of the peers (in case peers_file is provided); shows freshness of address in the file
time_t last_peers_updatetime = 0; // When we updated <mPeersAddresses> last time
std::set<hash_digest> old_blocks; // Hashes of old blocks, for which we will ignore 'inv' messages
bool stop_execution = false; // If the user types 'stop' then this value is set to true, and the main loop breaks.
std::vector<std::string> listen_message_types {"all", "tx", "inv", "block", "addr", "idle", "getaddr"};
std::vector<std::string> send_message_types {"tx", "block", "addr", "getaddr"};

// Data structures to track already received objects
std::set<hash_digest> seen_tx; // Hashes of recevied transactions
std::mutex seen_tx_lock;
std::set<hash_digest> seen_blocks; // Hashes of received blocks. For seen blocks we print 'inv' messages. For old blocks we don't.
std::mutex seen_blocks_lock;


/* Dump global struct <seen_blocks>
   @In: <filename> -- dump filename
   @Out: <void>
   @Return: <void>
*/
void dump_block_hashes(std::string filename)
{
  std::ofstream dumpfile;
  dumpfile.open(filename, std::ios_base::app);
  for (const auto& blk_hash : seen_blocks)
  {
    dumpfile << encode_hex(blk_hash) <<  "\n";
  }
  dumpfile.close();
  log_info() << "Appended " << seen_blocks.size() << " hashes to '" << filename << "'";
  return;
}

/* Handler for CTRL-C keystroke.
   Set <stop_execution> to true 
   will tell the main loop to break.  
*/
void sigint_handler(int sig_num)
{
  stop_execution = true;
  return;
}

/* 
   Update global map <mPeersAddresses> by reading from <peers_file>.
   1. If less then <MIN_TIME_BETWEEN_UPDATES> seconds passed since the <last_peers_update>, return.
   2. If the timestamp in the file is not newer than the current global
       peers_timestamp, return.
   3. If the file is locked (there is '1' after the timestamp), return
   4. Read <peers_file> and update <mPeersAddresses> in accordance to (2) in
      main_connect_loop() descriptoin.
   (*) The first line of <peers_file> should be '# <timestamp> <state>',
       The format of the rest of the file is '<ip> <port>' per line
*/
void refresh_peers(char *peers_file, std::string lock_file)
{
  if(!peers_file) // Don't update if addresses were provided only from the command line
    return;
  std::ifstream infile(peers_file);
  std::ifstream lockfile(lock_file);
  std::string poundsign;
  time_t timestamp;
  uint16_t is_locked;

  // Check if the lock file says that peers file is locked
  lockfile >> is_locked;

  if ( is_locked )
  {
    log_debug() << "The peers file is locked by lockfile. Skipping.";
    return;
  }

  // One also can lock peers file inside the file itself
  infile >> poundsign >> timestamp >> is_locked;
  log_debug() << "Reading " << peers_file << "; poundsign=" << poundsign <<
                ", timestamp=" << timestamp << ", is_locked=" << is_locked;

  if ( is_locked )
  {
    log_debug() << "The peers file is locked from inside the file. Skipping.";
    return;
  }

  if( ( time(NULL)-last_peers_updatetime < MIN_TIME_BETWEEN_UPDATES))
  {
    log_debug() << "Too early to update, wait for " << MIN_TIME_BETWEEN_UPDATES-(time(NULL)-last_peers_updatetime) << " seconds";
    return;
  }

  if ( timestamp <= peers_timestamp )
  {
    log_debug() << "The timestamp is old, will not update and will keep all current peers";
    return;
  }

  mPeersAddresses_lock.lock(); // *** PROTECT BEGIN ***

  log_info() << "Updating peers." << " new timestamp=" << timestamp;
  log_debug() << "Removing disconnected peers that failed to connect (even once)";
  for(peers_map::iterator it=mPeersAddresses.begin(), it_next=it; it!=mPeersAddresses.end(); it=it_next)
  {
    ++it_next;
    // Erased peers should not be in CONNECTING state
    if( (it->second.state == DISCONNECTED) && (it->second.failed_tries > 0) )
      mPeersAddresses.erase(it);
  }
  log_debug() << "Peers left after clean up:";
  for (auto &pair : mPeersAddresses)
    log_debug() << "  -- " <<  pair.first;

  log_debug() << "Re-reading " << peers_file;

  struct peer_address addr;
  while (infile >> addr.ip >> addr.port)
  {
   // Only add peers that we don't already have
   addr.instance_num = 1; // Number of instances from file start from 1.
   if (mPeersAddresses.count(peer_address_to_string(addr)) == 0)
   {
     addr.failed_tries = 0;
     addr.state = DISCONNECTED;
     mPeersAddresses[peer_address_to_string(addr)] = addr;
   }
  }
  log_debug() << "Peers left after update:";
  for (auto &pair : mPeersAddresses)
    log_debug() << "  -- " << pair.first;

  peers_timestamp = timestamp;
  last_peers_updatetime = time(NULL);

  mPeersAddresses_lock.unlock(); // *** PROTECT END ***

  return;
}




/* Main loop.
   1. Constantly try to establish connections to the peers in <mPeersAddresses> list.
      Give up a peer if it failed 3 connection tries.
   2. Periodically check the timestamp in file <peers_file>*.
      If the timestamp is newer than the <peers_timestamp> renew <mPeersAddresses> list:
      -- remove all failed nodes (even once)
      -- keep connected and non-tried nodes (i.e. in DISCONNECTED state and with zero
         tries)
      -- Add nodes from <peers_file> skipping those addresses of which are
         already in <mPeersAddresses>
   (*) The first line of <peers_file> should be '# <timestamp> <state>',
       where <timestamp> is epoch time of the peer addresses from getaddr.bitnodes.io,
       <state> is either 0 (file is unlocked) or 1 (file is locked).

   @In: <peers_file> -- file with ip addresses of peers (the file is periodically checked for updates)
        <begin> -- start reading from this address number in <peer_file>
        <end> -- end reading at this address number in <peer_file>
   @Out: <void>
   @Return: <void>
*/
void main_connect_loop(network &net, char *peers_file, int begin, int end, std::vector<std::string> listen_msgs, std::vector<std::string> send_msgs)
{
  //threadpool pool(4);
  //network net(pool);
  //log_info() << "Listen on port 8333";
  //net.listen(8333, std::bind(listening_started, _1, _2, listen_msgs, send_msgs));
  time_t report_connections_time = time(NULL);

  // Go until the user presses Ctrl-C
  if (!listen_msgs.empty())
    while (true)
    {
      // * 1. Try to connect to nodes in global <mPeersAddresses>
      for (auto &pair : mPeersAddresses)
      {
        struct peer_address &addr = pair.second;
        if ((addr.state == DISCONNECTED) && (addr.failed_tries < max_failed_tries))
        {
          log_info() << "Connecting to "  << pair.first << " (try " << addr.failed_tries+1 << ")";
          num_open_connections++; // global variable; shows the number of open connections.
                                  // Dercrements when a connection is closed
          addr.state = CONNECTING;
          net.connect(addr.ip, addr.port, std::bind(connect_started, _1, _2, addr, listen_msgs, send_msgs));
          usleep(delay_between_connections_micro);
        }
        if (stop_execution)
        {
          log_info() << "Stop command received. Waiting for threads.";
          break;
        }
      }

      // * 2. Do the timestamp and lock checks; update global <mPeersAddresses>
      refresh_peers(peers_file, LOCK_FILE);
      usleep(delay_between_connections_micro);
      time_t now = time(NULL);
      if (now-report_connections_time > 300)
      {
        log_info() << "Currently connected to " << num_open_connections << " nodes" <<
                      ", number of known peers is " << mPeersAddresses.size();
        report_connections_time = now;
      }
      if (stop_execution)
      {
        log_info() << "Stop command received. Waiting for threads.";
        break;
      }
    }
  // Just try connect once to each peer (since we only need to received a version message)
  // UPDATE:TODO: now we can also send bogus tx and bogus blocks, so it makes sense to
  //         make several connection tries. 
  else
  {
    for (auto &pair : mPeersAddresses)
    {
      struct peer_address &addr = pair.second;
      log_info() << "Connecting to "  << pair.first << " (try " << addr.failed_tries+1 << ")";
      num_open_connections++; // global variable; shows the number of open connections.
                              // Dercrements when a connection is closed
      addr.state = CONNECTING;
      net.connect(addr.ip, addr.port, std::bind(connect_started, _1, _2, addr, listen_msgs, send_msgs));
      usleep(delay_between_connections_micro);
      if (stop_execution)
      {
        log_info() << "Stop command received. Waiting for threads.";
        break;
      }
    }
    // Wait until all connections are closed (i.e. we recevied all version messages or timeout)
    while (num_open_connections != 0)
    {
      usleep(100000);
      time_t now = time(NULL);
      if (now-report_connections_time > 10)
      {
        log_info() << "Currently connected to " << num_open_connections << " nodes" <<
                      ", number of known peers is " << mPeersAddresses.size();
        report_connections_time = now;
      }
      if (stop_execution)
      {
        log_info() << "Stop command received. Waiting for threads.";
        break;
      }
    }
    stop_execution = true; // Set to true, so that the main thread knows that we are done.
  }

  //pool.stop();
  //pool.join();
}

// 'arg' is in the form 'getaddr=2' or 'addr=file.txt' or just 'addr'
int parse_send_messages(char *arg, std::vector<std::string>& send_msgs, int *numGetAddrToSend, char *payloadAddrFilename,
                        int *addr_timeoffset)
{
  std::vector<std::string> strs;
  std::string arg_str = std::string(arg);
  boost::split(strs, arg_str, boost::is_any_of("="));
  std::cout << "\n";
  //int i;
  //for (i=0;i<=2;i++)
  //    std::cout << i << "->" << strs[i] << ' ';
  //std::cout << "\n";
  if (std::find(send_message_types.begin(), send_message_types.end(), strs[0]) == send_message_types.end())
  {
      fprintf (stderr,"Unknown message type: '%s'.\n",strs[0].c_str());
      printf("Try '%s -h' for more information\n", PACKAGE);
      return -1;
  }
  send_msgs.push_back(strs[0]);
  if (strs[0].compare("getaddr") == 0)
    *numGetAddrToSend = 1; 
  if(strs.size() >= 2)
  {
    if (strs[0].compare("getaddr") == 0)
      *numGetAddrToSend = std::stoi(strs[1]); 
    if (strs[0].compare("addr") == 0)
      strcpy(payloadAddrFilename, strs[1].c_str()); 
  }
  if(strs.size() >= 3 && (strs[0].compare("addr") == 0))
      *addr_timeoffset = std::stoi(strs[2]); 
  return 0;
}

void print_help(int exval) 
{
  printf("Usage: %s [-h] [options] (-f PEERS_FILE | IPADDR)\n", PACKAGE);
  printf("Listen and send bitcoin messages from IPADDR or from a list of peers\n");
  printf("OPTIONS:\n");
  printf("  -h                                   print this help and exit                                                    \n");
  printf("  -f, --peers PEERS_FILE               file with peer addresses one per line in the forom of 'ip port'             \n");
  printf("  -l, --listen MSG_TYPE                listen for messages of type MSG_TYPE                                        \n");
  printf("                                       (can be 'inv', 'tx', 'block', 'addr', 'getaddr', 'all', 'idle').            \n");
  printf("                                       If bcclient does not listen for any messages, it quits after all specified   \n");
  printf("                                       with -s message are sent. Use '-l idle' to prevent this (bcclient will      \n");
  printf("                                       listen for the second version message which should never arrive.           \n");
  printf("                                       note that 'tx' and' 'block' don't make much sense without inv               \n");
  printf("  -s, --send ( getaddr | tx | block |  send messages to each connected peer. E.g. '-s getaddr' sends 1 getddr      \n");
  printf("    getaddr=<count> |                  message (don't forget to add '-l addr'); 'getaddr=3' sends 3 getaddr msgs.  \n");
  printf("    addr=<addr_file> |                 'addr=<addr_file>' sends messages with addresses found in <addr_file> ('IP PORT' per line)\n");
  printf("    addr=<addr_file>=<timestamp_offset> use <timestamp_offset> to offset addresses timestamps from current time (0 is default)        \n");
  printf("  -p PORT                              PORT of the peer at IPADDR (default is 8333)                                \n");
  printf("  -o LOG_FILE                          redirect output to file'                                                    \n");
  printf("  -v                                   print debug info.                                                           \n");
  printf("                                                                                                                   \n");
  printf("EXPERT OPTIONS:                                                                                                    \n");  
  printf("  --tries TRIES                        give up after TRIES connection tries to a node (default is 3)               \n");
  printf("  --delay MICRO                        sleep for MICRO ms before connecting to the next peer (default is 100,000)  \n");
  printf("  --addrmsg-size SIZE                  number of IP of addresses per 'addr' message (default is 100)  \n");
  printf("  --exit-when-all-connected            UNIMPLEMENTED stop the program when all connections are established         \n");
  printf("  -a, --seen-blocks BLOCK_HASHES_FILE  file with hashes of already known blocks (i.e. we will not request them)    \n");
  printf("  -n CONNECTIONS                       number of parallel connections to establish for each address (default is 1) \n");
  printf("  -b NUM                               if -f is present, read addresses starting from NUM (inclusive)              \n");
  printf("  -e NUM                               if -f is present, read addresses until NUM (inclusive)                      \n");
 
  exit(exval);
}


int main(int argc, char *argv[])
{
  char *peersFilename = NULL; // File with Vector of peers to which we will establish connections
  char *blocksFilename = NULL; // File with Vector of already known bock hashes. This is to avoid requesting old blocks
                               // The same file will be used for periodically dumping known hashes
  char *logFilename = NULL; // where to put log messages, NULL means print to terminal

  uint16_t port = 8333;  // Port of the peer specified in the command line
  uint32_t n = 1; // Number of connections that will be established to each provided peer address
  bool fPrintDebug = false;
  int begin = 0;  // If a file with peers is proveded, read starting from this address
  int end = -1 ;  // If a file with peers is proveded, read starting from this address, -1 means read till the end
  std::vector<std::string> listen_msgs;
  std::vector<std::string> send_msgs;
  //int numGetAddrToSend = 0; // Number of 'getaddr' message we need to send
  int addr_timeoffset = 0; // Offset for addresses which we send as a payload in 'addr' messages
  char payloadAddrFilename[256] = ""; // Filename containing addresses that we want to send to a peer as a payload

  // *** 1. Parse command line args ***
  static struct option long_options[] =
  {
      {"listen", required_argument, NULL, 'l'},
      {"send", required_argument, NULL, 's'},
      {"seen-blocks", required_argument, NULL, 'a'},
      {"tries", required_argument, NULL, 130},
      {"delay", required_argument, NULL, 131},
      {"addrmsg-size", required_argument, NULL, 132},
      {"exit-when-all-connected", no_argument, &fExitWhenAllConnected, 1},
      {NULL, 0, NULL, 0}
  };
  int c;
  opterr = 0;
  while ((c = getopt_long(argc, argv, ":hvp:f:b:e:a:o:n:l:s:", long_options, NULL)) != -1)
  {
    switch (c)
    {
      case 0:
        break; // long flag option
      case 'h':
        print_help(0);
        break;
      case 'l':
        if (std::find(listen_message_types.begin(), listen_message_types.end(), std::string(optarg)) == listen_message_types.end())
        {
            fprintf (stderr,"Unknown message type: '%s'.\n",optarg);
            printf("Try '%s -h' for more information\n", PACKAGE);
            return 1;
        }
        listen_msgs.push_back(optarg);
        break;
      case 's':
        if(parse_send_messages(optarg, send_msgs, &numGetAddrToSend, payloadAddrFilename, &addr_timeoffset) < 0)
	  return 1;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'f':
        peersFilename = optarg;
        break;
      case 'a':
        blocksFilename = optarg;
        break;
      case 'o':
        logFilename = optarg;
        break;
      case 'n':
        n = atoi(optarg);
        break;
      case 'b':
        begin = atoi(optarg);
        break;
      case 'e':
        end = atoi(optarg);
        break;
      case 'v':
        fPrintDebug = true;
        break;
      case 130:
        max_failed_tries = atoi(optarg);
        break;
      case 131:
        delay_between_connections_micro = atoi(optarg);
        break;
      case 132:
        addr_per_addr_message = atoi(optarg);
        break;
      case ':':
        fprintf (stderr,"Option '%c' requires an argument.\n",optopt);
        printf("Try '%s -h' for more information\n", PACKAGE);
        return 1;
      case '?':
        //fprintf (stderr,"Unknown option character: '%c'.\n",optopt);
        fprintf (stderr,"Unknown option: '%s'.\n",argv[optind-1]);
        printf("Try '%s -h' for more information\n", PACKAGE);
        return 1;
      default:
        abort();
    }
  }

  // *** 2. Init the logger ***
  printf("Setting up logging subsystem.\n");
  std::ofstream logfile;
  if(logFilename)
  {
    logfile.open(logFilename, std::ios_base::app);
    log_info().set_output_function(std::bind(output_to_file, std::ref(logfile), _1, _2, _3));
    log_debug().set_output_function(std::bind(output_to_file, std::ref(logfile), _1, _2, _3));
    log_error().set_output_function(std::bind(output_to_file, std::ref(logfile), _1, _2, _3));
  } else
  {
    log_info().set_output_function(output_to_terminal);
    log_debug().set_output_function(output_to_terminal);
    log_error().set_output_function(output_to_terminal);
  }

  if (!fPrintDebug)
  {
    log_debug().set_output_function(std::bind(output_to_null, std::ref(logfile), _1, _2, _3));
  }

  //std::cout << "To listen: ";
  //for (auto c : listen_msgs)
  //    std::cout << c << ' ';
  //std::cout << "\nTo send (numGetAddrToSend=" << numGetAddrToSend << ";payloadAddrFilename=" << payloadAddrFilename << ";addr_timeoffset=" << addr_timeoffset << "): ";
  //for (auto c : send_msgs)
  //    std::cout << c << ' ';
  //std::cout << '\n';

  // *** 3. Load peers from the file (if provided) ***
  /* // If we asked to send getaddr, we need to listen to addr messages
  if (std::find(send_msgs.begin(), send_msgs.end(), "getaddr") != send_msgs.end())
    listen_msgs.push_back("addr");*/
  if(peersFilename)
  {
    log_info() << "Loading peers from file.";
    std::ifstream infile(peersFilename);
    std::string poundsign;
    time_t timestamp;
    uint16_t is_locked;
    infile >> poundsign >> timestamp >> is_locked;
    log_info() << "Reading " << peersFilename << "; poundsign=" << poundsign <<
                  ", timestamp=" << timestamp << ", is_locked=" << is_locked;
    struct peer_address addr;
    int number_of_reads = 0;
    while (infile >> addr.ip >> addr.port)
    {
     number_of_reads++;
     if (number_of_reads < begin)
       continue;
     if ((end >= 0) && (number_of_reads > end))
       break;
     addr.failed_tries = 0;
     addr.state = DISCONNECTED;
     addr.numGetAddrToSend = numGetAddrToSend;
     addr.addr_timeoffset = addr_timeoffset;
     addr.pong_remained = 0;
     addr.pong_waittime = 0;
     addr.fGetAddrSentConfirmed = false;
     addr.fInbound = false;
     int i = 0;
     for (i=1;i<=n;i++)
     {
       addr.instance_num = i;
       mPeersAddresses[peer_address_to_string(addr)] = addr;
     }
    }
    last_peers_updatetime = time(NULL);
    peers_timestamp = timestamp;
    log_info() << "Added " << mPeersAddresses.size() << " addresses";
  }


  // optind >= argc means that there are no addresses from the command line
  //if (optind >= argc && (mPeersAddresses.size() == 0)) {
  //    printf("No peer addresses were provided\n");
  //    printf("Try '%s -h' for more information\n", PACKAGE);
  //    exit(1);
  //}

  // *** 5. Load peers addresses from the command line ***
  if (optind < argc)
  {
    log_info() << "Loading peer address from the command line.";
    struct peer_address addr;
    addr.ip = argv[optind];
    addr.port = port;
    addr.failed_tries = 0;
    addr.state = DISCONNECTED;
    addr.numGetAddrToSend = numGetAddrToSend;
    addr.addr_timeoffset = addr_timeoffset;
    addr.pong_remained = 0;
    addr.pong_waittime = 0;
    addr.fGetAddrSentConfirmed = false;
    addr.fInbound = false;
    //log_info() << "Adding " << peer_address_to_string(addr);
    int i = 0;
    for (i=n+1;i<=2*n;i++)
    {
      addr.instance_num = i;
      mPeersAddresses[peer_address_to_string(addr)] = addr;
    }
  }

  // *** 4. Load blockhashes that we already know (so we don't request the whole blockchain) ***
  if(blocksFilename)
  {
    log_info() << "Loading known block hashes.";
    std::ifstream infile(blocksFilename);
    std::string sBlockHash; // Block hash as hex string
    log_info() << "Reading " << blocksFilename << " for known block hashes";
    while (infile >> sBlockHash)
    {
      //log_debug() << "Reading " << sBlockHash;
      std::istringstream buffer(sBlockHash);
      hash_digest aBlockHash = decode_hex_digest<hash_digest>(sBlockHash); // Block hash as array<uint_8, 32>
      old_blocks.insert(aBlockHash);
    }
    log_info() << "Size of old_blocks is  " << old_blocks.size();
  }

  // *** 6. Load Payload addresses ***
  if(payloadAddrFilename && strlen(payloadAddrFilename) != 0)
  {
    log_info() << "Loading paylaod addresses for 'addr' messages.";
    std::ifstream infile(payloadAddrFilename);
    std::string address;
    std::string sPort;
    while (infile >> address >> sPort)
      vPayloadAddresses.push_back(address+std::string(" ")+sPort);
    if(vPayloadAddresses.size() == 0)
    {
      printf("Payload address is required.\n");
      printf("Try '%s -h' for more information\n", PACKAGE);
      exit(1);
    }
  }

 
  // *** 7. Start the main loop ***
  //log_info() << "Starting main loop.";
  struct sigaction s_action;
  sigemptyset(&s_action.sa_mask);
  s_action.sa_flags = 0;
  //s_action.sa_flags |= SA_RESETHAND;
  s_action.sa_handler = sigint_handler;
  sigaction(SIGINT, &s_action, NULL);

  threadpool pool(4);
  network net(pool);
  log_info() << "Listen on port 8333";
  net.listen(8333, std::bind(listening_started, _1, _2, listen_msgs, send_msgs));
  if (mPeersAddresses.size() != 0)
    main_connect_loop(net, peersFilename, begin, end, listen_msgs, send_msgs);
  else
    log_info() << "No peers were provided. There will be no outgoing connections.";

  while(!stop_execution) // stop_execution can be changed by CTRL-c
    sleep(1);

  pool.stop();
  pool.join();

  // *** 8. Ask the user to dump received block hashes ***
  if (!listen_msgs.empty() && !seen_blocks.empty())
  {
    dump_block_hashes("blockhashes.dump");
    //log_info() << "Do you want to dump block hashes (to 'blockhashes.dump')? (y/n): ";
    //if(logFilename)
    //  fprintf(stderr, "Do you want to dump block hashes (to 'blockhashes.dump')? (y/n): ");
    //char answ[4];
    //std::cin.getline(answ,4);
    //if (strncmp(answ, "y",1) == 0)
    //  dump_block_hashes("blockhashes.dump");
  }
  log_info() << "Exited cleanely.";
  if (logfile.is_open())
    logfile.close();
  return 0;
}

