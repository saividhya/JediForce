#!/bin/bash
echo "X" > test
echo $3 >> test
nc $1 $2 < test

