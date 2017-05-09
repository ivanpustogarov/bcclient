/* Copyright (c) 2014-2015 Ivan Pustogarov
 Distributed under the MIT/X11 software license, see the accompanying
 file LICENSE or http://www.opensource.org/licenses/mit-license.php. */

#include "main.hpp"
#include "util.hpp"
#include <boost/chrono/chrono.hpp>
#include <boost/type_traits.hpp>
#include <boost/chrono/system_clocks.hpp>
#include <boost/chrono/system_clocks.hpp>

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

// Logger handlers

void output_to_null(std::ofstream& file, log_level level,
    const std::string& domain, const std::string& body)
{
        return;
}

void output_to_file(std::ofstream& file, log_level level,
    const std::string& domain, const std::string& body)
{
    if (body.empty())
        return;
    char buff[70];
    int ms;
    time_t time_epoch = time(NULL);
    struct tm time_struct_gmt;
    struct timeval time_seconds;
    gmtime_r(&time_epoch, &time_struct_gmt);
    gettimeofday(&time_seconds, NULL);
    strftime(buff, sizeof(buff), "%b %d %H:%M:%S", &time_struct_gmt);
    ms = (int)time_seconds.tv_usec / 1000;

    //struct timespec tp;
    //clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    boost::chrono::steady_clock::time_point tp_now = boost::chrono::steady_clock::now();//.time_since_epoch();
    long int timeSinceEpoch = boost::chrono::duration_cast<boost::chrono::milliseconds>(tp_now.time_since_epoch()).count();
    //ret += fprintf(fileout, "%lu.%ld ", tp.tv_sec, tp.tv_nsec);
    //printf("The year is: %ld\n", gmtime(&now)->tm_year);
     
    //file << buff << "." << ms << " " << "(" << tp.tv_sec << "." << tp.tv_nsec << ")";
    file << buff << "." << ms << " " << "(" << timeSinceEpoch << ")";
    file << " [" << level_repr(level) << "]";
    if (!domain.empty())
        file << " [" << domain << "]";
    file << ": " << body << std::endl;
}

void output_to_file_simple(std::ofstream& file, log_level level,
    const std::string& domain, const std::string& body)
{
    if (body.empty())
        return;
    //file << level_repr(level);
    //if (!domain.empty())
    //    file << " [" << domain << "]";
    file << body << std::endl;
}

void output_to_terminal(log_level level, const std::string& domain, const std::string& body)
{
    if (body.empty())
        return;
    char buff[70];
    int ms;
    time_t time_epoch = time(NULL);
    struct tm time_struct_gmt;
    struct timeval time_seconds;
    gmtime_r(&time_epoch, &time_struct_gmt);
    gettimeofday(&time_seconds, NULL);
    strftime(buff, sizeof(buff), "%b %d %H:%M:%S", &time_struct_gmt);
    ms = (int)time_seconds.tv_usec / 1000;

    //struct timespec tp;
    //clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    boost::chrono::steady_clock::time_point tp_now = boost::chrono::steady_clock::now();//.time_since_epoch();
    long int timeSinceEpoch = boost::chrono::duration_cast<boost::chrono::milliseconds>(tp_now.time_since_epoch()).count();
    //printf("The year is: %ld\n", gmtime(&now)->tm_year);
     
    //std::cout << buff << "." << ms << " " << "(" << tp.tv_sec << "." << tp.tv_nsec << ")";
    std::cout << buff << "." << ms << " " << "(" << timeSinceEpoch << ")";
    std::cout << " [" << level_repr(level) << "]";
    if (!domain.empty())
        std::cout << " [" << domain << "]";
    std::cout << ": " << body << std::endl;
}


// Output formatting

std::string format_ipv6addr(ip_address_type ip)
{
  char addr_str[256];

  sprintf(addr_str,
   "%02hhx%02hhx:%02hhx%02hhx:"
   "%02hhx%02hhx:%02hhx%02hhx:"
   "%02hhx%02hhx:%02hhx%02hhx:"
   "%02hhx%02hhx:%02hhx%02hhx",
   ip[0], ip[1], ip[2], ip[3],
   ip[4], ip[5], ip[6], ip[7],
   ip[8], ip[9], ip[10],ip[11],
   ip[12],ip[13],ip[14],ip[15]);

  return std::string(addr_str);
}

std::string format_ipv4addr(ip_address_type ip)
{
  char addr_str[256];

  sprintf(addr_str,
   "%hhu.%hhu.%hhu.%hhu",
   ip[12],ip[13],ip[14],ip[15]);

  return std::string(addr_str);
}

/* Checks if a 16-byte array is an ipv4 address
   Bytes 0-9 should be zero
   Bytes 10,11 should be 'ff:ff'
   Bytes 12,13,14,15 represent ipv4 address.
*/
bool is_ipv4(ip_address_type ip)
{
  int i = 0;
  for (i=0;i<10;i++)
    if (ip[i] != 0)
      return false;
  if((ip[10] != 0xff) || (ip[11] != 0xff))
    return false;
  return true;
}

std::string peer_address_to_string(struct peer_address addr)
{
  std::string buff(addr.ip);
  buff += ":";
  buff += std::to_string(addr.port);
  buff += ".";
  buff += std::to_string(addr.instance_num);
  return buff;
}

// Convert string representation of IP_v4 or IP_v6 (with port) to a bitcoin struct we
// can put to 'addr' message
struct network_address_type make_bc_addr(const std::string ip_str, long int timestamp_offset)
{
  struct network_address_type addr;
  addr.timestamp = time(NULL) + timestamp_offset;
  addr.services = 1;

  //the address is ipv4
  if(ip_str.find(".") != -1)
  {
    uint8_t ipb[4]; // stands for ip_bYTES
    uint16_t port;
    sscanf(ip_str.c_str(),"%hhu.%hhu.%hhu.%hhu %hu",ipb,ipb+1,ipb+2,ipb+3,&port);
    addr.ip =
     ip_address_type{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0xff, 0xff, ipb[0], ipb[1], ipb[2], ipb[3]};
    addr.port = port;
    log_debug() << "make_bc_addr(): Created addr '" <<  format_ipv4addr(addr.ip) << ":" << addr.port << "'";
  }
  // ipv6 
  else if(ip_str.find(":") != -1)
  {
    uint8_t ipb[16]; // stands for ip_bYTES
    uint16_t port;
    sscanf(ip_str.c_str(),"%02hhx%02hhx:%02hhx%02hhx:"
                          "%02hhx%02hhx:%02hhx%02hhx:" 
                          "%02hhx%02hhx:%02hhx%02hhx:" 
                          "%02hhx%02hhx:%02hhx%02hhx %hu",
                   ipb,ipb+1,ipb+2,ipb+3,
                   ipb+4,ipb+5,ipb+6,ipb+7,
                   ipb+8,ipb+9,ipb+10,ipb+11,
                   ipb+12,ipb+13,ipb+14,ipb+15,&port);
    addr.ip =
     ip_address_type{ipb[0],ipb[1],ipb[2],ipb[3],
                   ipb[4],ipb[5],ipb[6],ipb[7],
                   ipb[8],ipb[9],ipb[10],ipb[11],
                   ipb[12],ipb[13],ipb[14],ipb[15]};
    addr.port = port;
    log_debug() << "make_bc_addr(): Created addr '" <<  format_ipv6addr(addr.ip) << ":" << addr.port << "'";
  }
  else
  {
    log_info() << "make_bc_addr(): Error parsing address (skipping): " << ip_str;
    addr.port = 0; // Indication of an error
  }
  return addr;
}

