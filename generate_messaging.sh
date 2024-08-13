#!/bin/sh

cd ./messaging_bp
mkdir inc
mkdir src
bitproto c messaging.bitproto
mv messaging_bp.c   ./src/messaging_bp.c
mv messaging_bp.h   ./inc/messaging_bp.h
cd ..