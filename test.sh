#!/bin/bash -x
NETNS="btcns"
IPA="10.0.0.1/24"
IPB="10.0.0.2/24"
NIC1="btc0"
NIC2="btc1"

sudo ip netns del $NETNS || true
sudo ip netns add $NETNS || exit 1
sudo ip link add name $NIC1 type veth peer $NIC2 || exit 1
sudo ip link set $NIC2 netns $NETNS || exit 1
sudo ip link set $NIC1 up || exit 1
sudo ip addr add dev $NIC1 $IPA  || exit 1
sudo ip netns exec $NETNS ip link set $NIC2 up || exit 1
sudo ip netns exec $NETNS ip addr add dev $NIC2 $IPB || exit 1
ping -c 4 10.0.0.2
sudo ip netns exec $NETNS sh test_client.sh
