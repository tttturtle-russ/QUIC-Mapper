#!/bin/bash

mkdir -p combined_lib
cd combined_lib
for lib in /home/russ/mvfst/_build/lib/libmvfst*.a; do ar -x $lib; done
ar -q libmvfst.a *.o
mv libmvfst.a ../
cd ..
# rm ./combined_lib -r