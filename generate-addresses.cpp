#include <inttypes.h>
#include <stdint.h>
#include <fstream>
#include <iostream>
#include <string>
#include <getopt.h>
#include <atomic>
#include <stdlib.h>
#include <string.h>

using namespace std;

#define PACKAGE    "generated-addresses"
#define VERSION    "0.9"

void generate_ipv4_addresses(uint8_t start[], uint32_t n, char *outfile)
{
  int i = 0;
  uint8_t cur[4] = {start[0],start[1],start[2],start[3]};
  FILE *filed = stdout;
  if (outfile)
    filed = fopen(outfile,"wt");
  for (i=0;i<n;i++)
  {
    fprintf(filed,"%hhu.%hhu.%hhu.%hhu\n", cur[0],cur[1],cur[2],cur[3]);
    cur[3]++;
    int j = 0;
    for (j=3;j>0;j--)
    {
      if(cur[j] == 255)
        {cur[j] = 1;cur[j-1]++;}
    }
  }
  fclose(filed);
}

void generate_ipv6_addresses(uint8_t start[], uint32_t n, char *outfile)
{
  int i = 0;
  uint8_t cur[16] = {start[0],start[1],start[2],start[3],
                     start[4],start[5],start[6],start[7],
                     start[8],start[9],start[10],start[11],
                     start[12],start[13],start[14],start[15]};
  FILE *filed = stdout;
  if (outfile)
    filed = fopen(outfile,"wt");
  for (i=0;i<n;i++)
  {
    fprintf(filed,     "%02hhx%02hhx:%02hhx%02hhx:"
                          "%02hhx%02hhx:%02hhx%02hhx:" 
                          "%02hhx%02hhx:%02hhx%02hhx:" 
                          "%02hhx%02hhx:%02hhx%02hhx\n",
                   cur[0],cur[1],cur[2],cur[3],
                   cur[4],cur[5],cur[6],cur[7],
                   cur[8],cur[9],cur[10],cur[11],
                   cur[12],cur[13],cur[14],cur[15]);
    int j = 0;
    cur[15]++;
    for (j=15;j>0;j--)
    {
      if(cur[j] == 255)
        {cur[j] = 1;cur[j-1]++;}
    }
  }
  fclose(filed);
}

/* @Brief: Generates a list of ipv4 or ipv6 addresses based on the
           format of the start address.
   @In: <generateAddresses_startaddress_str> -- the start address of the list.
        <generateAddresses_number> -- will generate this number of addresses.
   @Out: void
*/
void generate_addresses(char *startaddress_str, uint32_t number, char *outfile)
{
  printf("Going to generate %d addresses (from %s) and put them to '%s'...\n", 
                                 number, startaddress_str, outfile ? outfile : "stdout");
  if(std::string(startaddress_str).find(".") != -1) // the start address is ipv4
  {
    uint8_t ipb[4]; // stands for ip_bYTES
    sscanf(startaddress_str,"%hhu.%hhu.%hhu.%hhu",ipb,ipb+1,ipb+2,ipb+3);
    generate_ipv4_addresses(ipb, number, outfile);
  }
  else if(std::string(startaddress_str).find(":") != -1) // the start address is ipv6
  {
    uint8_t ipb[16]; // stands for ip_bYTES
    sscanf(startaddress_str,"%02hhx%02hhx:%02hhx%02hhx:"
                          "%02hhx%02hhx:%02hhx%02hhx:" 
                          "%02hhx%02hhx:%02hhx%02hhx:" 
                          "%02hhx%02hhx:%02hhx%02hhx",
                   ipb,ipb+1,ipb+2,ipb+3,
                   ipb+4,ipb+5,ipb+6,ipb+7,
                   ipb+8,ipb+9,ipb+10,ipb+11,
                   ipb+12,ipb+13,ipb+14,ipb+15);
    generate_ipv6_addresses(ipb, number, outfile);
  }
  else
   {printf("Error parsing address: %s", startaddress_str);return;}
  printf("Done.\n");
  return;
}

void print_help(int exval) 
{
  printf("%s,%s generates a list of addresses.\n", PACKAGE, VERSION); 
  printf("%s [-h] [-g START_ADDRESS] [-n NUMBER_OF_ADDRESSES] [-o FILE] \n\n", PACKAGE);
 
  printf("  -h                          print this help and exit\n");

  printf("  -g START_ADDRESS            start from this address (default is 188.93.174.57)\n");
  printf("  -n NUMBER_OF_ADDRESSES      generates this number of addresses (default is 5\n");
  printf("  -o FILE                     print to output to FILE (e.g. markers.txt)\n");
  
  printf(" ADDRESES\n");
  printf("   addresses for '-g' can have the following formats   : '91.192.225.66' (IPV4)\n");
  printf("                                                       : '2607:f0d0:1002:0051:0000:0000:0000:0004' (IPV6)\n");
  printf("                                                       : 'fd87:d87e:eb43:0000:0000:ff00:0042:8329' (TOR)\n");
  exit(exval);
}

int main(int argc, char *argv[])
{
  char generateAddresses_startaddress[256];
  strcpy(generateAddresses_startaddress, "188.93.174.57");
  char *out_file = NULL;
  uint32_t generateAddresses_number = 5;

  int index;
  int c;
  opterr = 0;
  while ((c = getopt(argc, argv, ":hg:n:o:")) != -1)
    switch (c)
    {
      case 'h':
        print_help(0);
        break;
      case 'g':
        strcpy(generateAddresses_startaddress, optarg);
        break;
      case 'n':
        sscanf(optarg,"%u",&generateAddresses_number);
        break;
      case 'o':
        out_file = optarg;
        break;
      case ':':
        fprintf (stderr,"Option '%c' requires an argument.\n",optopt);
        printf("Try '%s -h' for more information\n", PACKAGE);
        return 1;
      case '?':
        fprintf (stderr,"Unknown option character: '%c'.\n",optopt);
        printf("Try '%s -h' for more information\n", PACKAGE);
        return 1;
      default:
        abort();
    }

  generate_addresses(generateAddresses_startaddress, generateAddresses_number, out_file);
  return 0;
}


