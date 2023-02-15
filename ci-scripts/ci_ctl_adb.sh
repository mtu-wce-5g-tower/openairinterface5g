#!/bin/bash

usage() {
  echo "usage: $0 <command> <id>"
  echo "available commands: initialize, attach, detach, terminate, check"
}

if [ $# -ne 2 ]; then
  usage
  exit 1
fi

cmd=$1
id=$2

flightmode_off() {
  set +x
  adb -s $id shell "/data/local/tmp/on"
}

flightmode_on() {
  set +x
  adb -s $id shell "/data/local/tmp/off"
}

initialize() {
  set +x
  adb -s $id shell "svc data enable"   # make sure data services are enabled
  flightmode_on
}

terminate() {
  echo "terminate: does nothing"
}

check() {
  declare -A service=( ["0"]="IN_SERVICE" ["1"]="OUT_OF_SERVICE" ["2"]="EMERGENCY_ONLY" ["3"]="RADIO_POWERED_OFF")
  declare -A data=( ["0"]="DISCONNECTED" ["1"]="CONNECTING" ["2"]="CONNECTED" ["3"]="SUSPENDED")
  serv_idx=$(adb -s $id shell "dumpsys telephony.registry" | sed -n 's/.*mServiceState=\([0-3]\).*/\1/p')
  data_idx=$(adb -s $id shell "dumpsys telephony.registry" | sed -n 's/.*mDataConnectionState=\([0-3]\).*/\1/p')
  echo -e "\u001B[1;37;44mStatus Check UE $id \u001B[0m"
  echo -e "\u001B[1;34mService State ${service[$serv_idx]}\u001B[0m"
  echo -e "\u001B[1;34mData State    ${data[$data_idx]}\u001B[0m"
}

case "${cmd}" in
  initialize) initialize;;
  attach) flightmode_off;;
  detach) flightmode_on;;
  terminate) terminate;;
  check) check;;
  *) echo "Invalid command $cmd"; usage; exit 1;;
esac
