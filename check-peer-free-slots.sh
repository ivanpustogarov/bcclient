#! /bin/bash

# NOTE: when bcclient makes connections, it waits for 10 ms between connections
# thus if you establish 1000 connection, the last connection will be established
# after 10 seconds + wait time to exchange 'version' messages => choose MAX_ROUND_TIME
# accordingly

EXPECTED_ARGS=1
E_BADARGS=65
BCCLIENT_LOGFILE=/tmp/bcclient.log
NUM_PER_STEP=20 # Number of peers  to run checks for one instance of bcclient
MAX_ROUND_TIME=20 # In seconds, time to wait for peers to respond with 'version' messages
PAR_CONNECTIONS=50 # Parallel connections for one peer

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` FILE"
  echo "Reads "IP PORT" entries (currently $NUM_PER_STEP per time)"
  echo "from <FILE>, tries to establish 50 connections to each peer, wait $MAX_ROUND_TIME"
  echo "second or until all connections are established, check"
  echo "how many connections succeeded."
  exit $E_BADARGS
fi

peers_file="$1"
number_of_peers=$(wc -l $1 | cut -f1 -d' ')
number_of_peers=$(( $number_of_peers - 1 ))

# Note that <i> starts from 1
for i in $(seq 1 $NUM_PER_STEP $number_of_peers)
do
  echo "Checking addresses $i-$(($i+$NUM_PER_STEP-1)):"
  sed -n "$(($i+1)),$(($i+$NUM_PER_STEP))p" $peers_file
  echo -n "" > $BCCLIENT_LOGFILE # Empty temp log file
  ./bcclient --delay 10000 --tries 1 -n $PAR_CONNECTIONS -l idle -o $BCCLIENT_LOGFILE -f $peers_file -b $i -e $(($i+$NUM_PER_STEP-1)) &  

  num_of_connected=$(./get-number-of-connected.sh $BCCLIENT_LOGFILE | grep Total | cut -f5 -d' ')
  if [ -z "$num_of_connected" ]
  then
    num_of_connected=0
  fi
  #echo "Num of connected = ${num_of_connected}"
  begin=$(date +%s) # We will wait for 3 seconds maximum
  # Parse the log file either all connections are established or 20 seconds elapse
  while test $(($(date +%s) - $begin)) -lt $MAX_ROUND_TIME -a $num_of_connected -lt $(($NUM_PER_STEP*$PAR_CONNECTIONS))
  do
    num_of_connected=$(./get-number-of-connected.sh $BCCLIENT_LOGFILE | grep Total | cut -f5 -d' ')
    if [ -z "$num_of_connected" ]
    then
      num_of_connected=0
    fi
    #echo "Num of connected = ${num_of_connected}"
    sleep 0.1
  done
  echo "Round time: $(($(date +%s) - $begin))" 
  killall ./bcclient
  sleep 0.5
  ./get-number-of-connected.sh $BCCLIENT_LOGFILE
  echo "--------"
done

