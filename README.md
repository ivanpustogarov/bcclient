Bitcoin Network Probing Tool
============================

NOTE: the current tool was developed in 2014-2015. Since then 
the way Bitcoin network works might have changed. So some of this tool's
functionality might not work as expected.

Sometimes you want to query information a Bitcoin node, e.g.  the type
of client it uses or its current timestamp.

	./bcclient 86.151.93.192
	[INFO]: Sending version message
	[INFO]: Version received. peer=86.151.93.192:8333.2, useragent=/Satoshi:0.13.1/, timestamp=1479927567, localtime=1479927580

Sometimes you want to make several parallel connections to the same node

	./bcclient -n2 86.151.93.192

Sometime you want to receive blocks/transactions from a peer and print them in real time

	./bcclient -l inv -l tx 86.151.93.192

Or you want to query a node about peers it is aware of by sending a 'getaddr' message:

	./bcclient -s getaddr -l addr -l idle 86.151.93.192 

Or you want to send a bogus block:

	./bcclient -s block -l idle 86.151.93.192 # '-l idle' keeps the connection open

This kind of information is hard to get/send using the core Bitcoin client
which motivates the development of this Bitcoin network-probing client.
This software was used when testing the attack described the following
papers:

[1] Alex Biryukov, Ivan Pustogarov. Bitcoin over Tor isn’t a good Idea.
To appear at IEEE Symposium on Security and Privacy (Oakland) 2015. 

[2] Alex Biryukov, Dmitry Khovratovich, Ivan Pustogarov. Deanonymisation
of Clients in Bitcoin P2P Network. ACM Conference on Computer and
Communications Security 2014 (ACM CCS): 15-29 


==========================
Compile Instructions
==========================
This software relies on a specific commit of libbitcoin (and probably
will not work with other commits). This specific commit is included and
you have to compile it first.

	$ sudo apt-get install build-essential autoconf automake libtool libboost-all-dev pkg-config libcurl4-openssl-dev libleveldb-dev shtool
	$ cd libbitcoin
	$ ln -s $(which shtool)
	$ autoreconf -i
	$ ./configure --enable-leveldb
	$ make
	$ cd ../
	$ make

I tested in Ubuntu 12.04, Ubuntu14.04, and Debian 8.4.
If it does not compile, you might want to try older version of libboost.

======================
Using with testnet
======================
By default the tool works only with mainnet.
You will need to recompile it to work testnet.

	$ make clean
	$ cd libbitcoin
	$ make clean
	$ ./configure --enable-leveldb --enable-testnet
	$ make
	$ cd ../
	$ make

Remember to use '-p 18333' (default is 8333)

==========================
Using with Tor
==========================
In order to use "./bcclient" program through tor and use a specific Exit
node, you can use the following configuration;

 -- Launch Tor on on a separate local machine with the following lines
    in torrc:
	ExitNodes <exit-node-name> 
	StrictExitNodes 1
	SocksPort <your-torproxy:9100>

-- Install badvpn

-- Create new tuntap interface:
	$sudo ip tuntap add dev tun0 mode tun
	$sudo ip link set tun0 up
	$sudo ip addr add 10.0.0.1/24 dev tun0
	$badvpn-tun2socks --tundev tun0 --netif-ipaddr 10.0.0.2 --netif-netmask 255.255.255.0 --socks-server-addr <your-torproxy>:9100
	$sudo route del default
	$sudo route add default gw 10.0.0.2

In order to put everything back:
	$sudo route del default
	$sudo route add default gw 10.91.0.1
	$sudo ip tuntap del dev tun0 mode tun


================================
Output format 
================================
When ./bcclient receives a transaction it prints by default it in a
succinct way. In order to include fields description, use '-v' flag. 

BC:14iyH71Y9kEDUXdQCytizPNTvFNAUUn3do
