#!/bin/bash

# $1: the dir to hold the angr-dev environment
# $2: the virtual env name you want to set for the angr-dev

mkdir $1
cd $1
git clone https://github.com/angr/angr-dev.git angr-dev
cd angr-dev
# Checkout our modified angr components for FIBER.
git clone https://github.com/seclab-ucr/angr-fiber.git angr
git clone https://github.com/seclab-ucr/claripy-fiber.git claripy
git clone https://github.com/seclab-ucr/cle-fiber.git cle
git -C angr checkout fiber
git -C angr pull
git -C claripy checkout fiber
git -C claripy pull
git -C cle checkout fiber
git -C cle pull
# Set up the angr-dev environment
sudo pip install virtualenvwrapper
./setup.sh -i -v -e $2
# We depend on a specific version of networkx (v1.11), newest version will not work.
workon $2
cd ..
pip uninstall networkx
git clone https://github.com/networkx/networkx.git networkx
cd networkx
git pull
git checkout networkx-1.11
python setup.py install
#Should be ready to go.
cd ../..
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "You are ready to go." 
echo "workon $2 : to switch virtual environment before running FIBER scripts."
echo "deactivate : exit the virtual environment."
