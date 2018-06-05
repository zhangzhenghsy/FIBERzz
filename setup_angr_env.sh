#!/bin/bash

# $1: the dir to hold the angr-dev environment
# $2: the virtual env name you want to set for the angr-dev

mkdir $1
cd $1
git clone https://github.com/seclab-ucr/angr-dev-fiber.git angr-dev
git -C angr-dev pull
git -C angr-dev checkout fiber
cd angr-dev
# Checkout our modified angr components for FIBER.
git clone https://github.com/seclab-ucr/angr-fiber.git angr
git clone https://github.com/seclab-ucr/claripy-fiber.git claripy
git clone https://github.com/seclab-ucr/cle-fiber.git cle
git clone https://github.com/seclab-ucr/angr-management-fiber.git angr-management
git clone https://github.com/seclab-ucr/angr-doc-fiber.git angr-doc
git clone https://github.com/seclab-ucr/angrop-fiber.git angrop
git -C angr checkout fiber
git -C angr pull
git -C claripy checkout fiber
git -C claripy pull
git -C cle checkout fiber
git -C cle pull
git -C angr-management checkout fiber
git -C angr-management pull
git -C angr-doc checkout fiber
git -C angr-doc pull
git -C angrop checkout fiber
git -C angrop pull
# Set up the angr-dev environment
sudo pip install virtualenvwrapper
sudo ./setup.sh -i -v -E $2
cd ..
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "You are ready to go." 
echo "workon $2 : to switch virtual environment before running FIBER scripts."
echo "deactivate : exit the virtual environment."
