if [[ $# != 2 ]]
then
    echo "USAGE: $0 <PORT NUMBER> <PATH/TO/EXECUTABLE>"
    exit 1
fi

id=$(lsof -t -i:$1)

if [[ $? == 0 ]]
then
    kill -s KILL $id
fi

spawn-fcgi -a127.0.0.1 -p$1 $2
