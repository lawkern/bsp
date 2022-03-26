if [[ $# < 1 ]]
then
    echo "Please specify a port number."
    exit 1
fi

id=$(lsof -t -i:$1)

if [[ $? == 0 ]]
then
    kill -s KILL $id
fi
