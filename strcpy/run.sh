#!/bin/bash

#for i in {1..$1} 
k=1
for ((i = 1; i <= $1; i++ ));
do
	FILE="CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_$(printf "%02d" $i).c"
	if [ -f $FILE ]; then
   		echo "File $FILE exists. ouput= $i"

		gcc $FILE io.c -o $k
		k=$((k+1))

		#echo `python2 -c 'print "7/42a8"+57*"a"'` | ./$i

	else
   		echo "File $FILE does not exist. ouput= $i"
	fi

	echo "-------------------------------"

done
