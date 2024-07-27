#!/bin/bash

echo -en "\n\n\t   \033[0;34m\033[1mSpinlock\033[0m"
./spinlock 2>/dev/null
echo -en "\n\n\t   \033[0;34m\033[1mSpinlock Owner\033[0m"
./spinlock_owner 2>/dev/null

echo -en "\n\n\t   \033[0;34m\033[1mMutex\033[0m"
./mutex 2>/dev/null
echo -en "\n\n\t   \033[0;34m\033[1mMutex Owner\033[0m"
./mutex_owner 2>/dev/null
echo -en "\n\n\t   \033[0;34m\033[1mMutex PI\033[0m"
./mutex_pi 2>/dev/null

echo -en "\n\n\t   \033[0;34m\033[1mMutex Recursive\033[0m"
./mutex_recursive 2>/dev/null
./mutex_recursive_simple 2>/dev/null
