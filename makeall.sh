#!/bin/bash

for makefile in $(find -type f -name Makefile)
do
	pushd $(dirname $makefile)
	make -j4
	popd
done
