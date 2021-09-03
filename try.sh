#!/bin/bash
echo "####### CLANG #######"
clang++ -std=c++17 main.cpp -lsodium
echo "#######  GCC  #######"
g++ -W -pedantic-errors -Wno-long-long -Woverloaded-virtual -Wundef -Wsign-compare -Wredundant-decls -Wctor-dtor-privacy  -Wnon-virtual-dtor -Wchar-subscripts  -Wcomment -Wformat -Wmissing-braces -Wparentheses -Wtrigraphs -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wfloat-equal -Wendif-labels -Wreturn-type -Wpacked -Wcast-align -Wpointer-arith -Wcast-qual -Wwrite-strings -Wformat-nonliteral -Wformat-security -Wswitch-enum -Wsign-promo -Wreorder -Wunreachable-code -Weffc++ -Wconversion -Wshadow -Wunused-parameter -Wold-style-cast -std=c++17 main.cpp -lsodium
echo "#####################"
