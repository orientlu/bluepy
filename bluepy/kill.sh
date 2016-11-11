#!/bin/bash

cmd="ble_app"

if [ $1 ]
then
        cmd=$1
fi

ps aux | grep $cmd | grep -v "grep" | grep -v $0 | grep -v "vim" | grep -v "gvim" 

ps aux | grep $cmd | grep -v "grep" | grep -v $0 | grep -v "vim" | grep -v "gvim" | awk '{print $2}' | while read line;
do 
        kill -9 $line
done
