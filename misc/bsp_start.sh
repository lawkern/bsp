if [[ $# < 1 ]]
then
    echo "Please specify a port number."
    exit 1
fi

spawn-fcgi -a127.0.0.1 -p$1 ../build/bsp
