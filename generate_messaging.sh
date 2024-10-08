#!/bin/sh

mkdir ./messaging_bp/inc
mkdir ./messaging_bp/src
bitproto c ./messaging_bp/messaging.bitproto
bitproto py ./messaging_bp/messaging.bitproto
mv ./messaging_bp/messaging_bp.c   ./messaging_bp/src/messaging_bp.c
mv ./messaging_bp/messaging_bp.h   ./messaging_bp/inc/messaging_bp.h
mv ./messaging_bp/messaging_bp.py ./python_cli