#!/bin/bash

# vsockets aren't limited by network namespaces
# so let's set up a new namespace just for this test
# and socat + nmap on there

# MUST RUN AS ROOT

set -eu

CID=$1
VPORT=$2
FAM=$3
IP=$4
PORT=$5

NAMESPACE=panda_${CID}_${IP}_${PORT}
ip netns del $NAMESPACE || true
ip netns add $NAMESPACE
ip netns exec $NAMESPACE ip addr add 127.0.0.1/8 dev lo
ip netns exec $NAMESPACE ip link set dev lo up

if [ "$FAM" = "2" ]; then
  if [ "$IP" = "::" ]; then
    IP="0.0.0.0"
    # Already exists, so don't try adding it to lo again
  else
    ip netns exec $NAMESPACE ip addr add $IP/32 dev lo:1
  fi

elif [ "$FAM" = "10"]; then
  if [ "$IP" = "::" ]; then
    echo "skip"
  else
    ip netns exec $NAMESPACE ip addr add $IP/128 dev lo:1
  fi

fi

ip netns exec $NAMESPACE socat TCP-LISTEN:$PORT,fork VSOCK-CONNECT:$CID:$VPORT &
socatPID=$!

ip netns exec $NAMESPACE nmap -sV localhost -p $PORT -oG - | grep Ports:
kill $socatPID
