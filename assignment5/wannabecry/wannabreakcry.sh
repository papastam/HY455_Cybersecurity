#! /bin/bash
#First up check if KEY.txt exists, otherwise we could pottentially rerun the virus
if ! test -f "KEY.txt"; 
then 
	echo "Error, KEY.txt doesn't exist!" 
	exit
fi

hash=" !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_\`abcdefghijklmnopqrstuvwxyz{|}~"
#Calculate the offset bettween the first letter of the key with the letter T in the encrypt string found while reversing
key=$(cat KEY.txt)
offset=0

for ((j=0 ; j<${#hash}; j++ ));
do
	if [ "${key:0:1}" == "${hash:$j:1}" ]
	then
		offset=$((j-53))
	fi 
done 
echo "The offset is: $offset"
if [ $offset -gt 0 ]
then
	input=$offset
else
	input=$((offset+95))
fi

echo "The calculated randomized alternator used is: $input"
input=$(printf '%025g' "$input")
echo "Trying code: $input"
output=$(./wannabecry $input)
echo $output

if [ $(echo $output | wc -m ) -ne 68 ];
then
	echo "Decryption succeded! The code was $input"
	exit;
else
	echo "Calculated input was incorrect. Starting Bruteforce approach"
fi

############################
######## BRUTEFORCE ########
############################
for code in $(seq -f "0000000000000000000000%02g" 1 95)
do
	echo "Trying out code: $code"
	output=$(./wannabecry $code)
	echo $output

	if [ $(echo $output | wc -m ) -ne 68 ];
	then
		echo "Bruteforce approach succeded! The code was $code"
		break;
	fi
done
