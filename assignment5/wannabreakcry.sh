for code in $(seq -f "0000000000000000000000%02g" 1 95)
do
echo "Trying out code: $code"
output=$(./wannabecry/wannabecry $code)
echo $output
#echo $(echo $output | wc -m)
if [ $(echo $output | wc -m ) -ne 68 ];
then
	break;
fi
done
