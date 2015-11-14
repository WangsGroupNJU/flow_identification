#!/bin/bash
rm -rf *.o
gcc -w -o parser.o parser.c
gcc -w -o Bayes.o Bayes.c
echo ---------- ./parser.o ----------
./parser.o 192.168.1.105
echo ---------- python PCA.py ----------
python PCA.py
echo ---------- ./Bayes.o ----------
./Bayes.o
