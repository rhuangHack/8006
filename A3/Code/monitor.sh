#!/bin/bash
#
# SOURCE FILE: monitor.sh
# 
# PROGRAM:     Simple monitor application.
# 
# DATE:        March 1, 2018
#   
# PROGRAMMER:  renda huang
# 

# 
# Variables Default Settings
#
################################################

attempt=3
timeout=2
path="/var/log/auth.log"
array=()
try=$((attempt - 1))
port=22
app=`pwd`;
ipt="/sbin/iptables"

keywords='Failed password'
fieldNo=13
regx_on=0
ex='[0-9]+(\.[0-9]+){3}'
text='sdfs sdfs:ffff:192.2.3.4'
target=""

# 
# Front-end section
#
################################################

# GUI function set keyword,file path
gui_starter(){
    data="$(yad --title="Monitor Application" --center --width=400 \
    --text="Monitor Variable Configure" \
    --separator="#" \
    --form --field="Log file path:FL" $path\
    --field="Password attempts (times)" $attempt\
    --field="Blocking time (min)" $timeout\
    --field="serving port" $port\
	--field="Keywords" "$keywords"\
    --button="gtk-ok:0" --button="gtk-cancel:1")"


	[[ $data = "" ]] && exit 0

    path=`echo $data | awk -F "#" '{print $1}'`
    attempts=`echo $data | awk -F "#" '{print $2}'`
    timeout=`echo $data | awk -F "#" '{print $3}'`
    port=`echo $data | awk -F "#" '{print $4}'`
    keywords=`echo $data | awk -F "#" '{print $5}'`

	gui_filter;
}


# GUI function set target IP
gui_filter(){

    data="$(yad --title="Monitor Application" --center --width=400 \
    --text="Target IP Filter Configure" \
    --separator="#" \
    --form --field="Field No." $fieldNo\
    --button="gtk-go-back:1" --button="gtk-ok:0" --button="regx:2")"

	foo=$?
	if [ $foo -eq 0 ]
	then
		fieldNo=`echo $data | awk -F "#" '{print $1}'`
		fieldNo='$'$fieldNo
	elif [ $foo -eq 1 ]
	then
		gui_starter;
	elif [ $foo -eq 2 ]
	then
		regx_on=1
		gui_regx;
	fi
}


# GUI function set regx 
gui_regx(){

    data="$(yad --title="Monitor Application" --center --width=400  \
    --text="Regx Filter Configure" \
    --separator="#" \
    --form --field="expr" "$ex" \
    --field="Test text" "$text" \
	--button="test:0" --button="gtk-go-back:1")" 

	foo=$?
	
	if [ $foo -eq 0 ]
	then
		ex=`echo $data | awk -F "#" '{print $1}'`
		text=`echo $data | awk -F "#" '{print $2}'`

		ipvalid;
		show_result;
	elif [ $foo -eq 1 ]
	then
		regx_on=0
		gui_filter;
	fi
}


show_result(){

    data="$(yad --title="Monitor Application" --center --width=400 \
    --text="Regx Filter Configure" \
    --separator="#" \
    --form --field="Result" $target\
	--button="gtk-ok:0" --button="retry:1")" 
	
	foo=$?
	[[ foo -eq 1 ]] && gui_regx;
}



# set variables for command line
setVariables(){
    attempts=$1
    timeout=$2
    path=$3
    port=$4

    notify-send -t 500 "attempts: $attempts     timeout: $timeout   path: $path     port: $port"
}


# back-end functions
#################################################################

#list all the record of the list
listArray(){
	echo ""
    echo "###### BlackList #####"
    echo "######################"
    for i in "${array[@]}"; 
    do 
        echo "#  $i #"; 
    done
    echo "#####################"
	echo ""
}

#add a piece of record into the list 
addNewElement(){
    array+=("$1 1")
    notify-send -t 500 "the new element is $1"
    listArray;
}

#delete a record from the list
delElement(){
    unset 'array[$1]'
    notify-send -t 500 "unset the $1 th element"
    listArray;
}

#update a record of the list
updateElement(){
    local tmp=$2
    ((tmp++))
    array[$1]="$3 $tmp"
    notify-send -t 500 "update element ${array[$1]}"
    listArray;
}

#judge if a visitor violate the rule and take measures
updateArray(){
    if [[ "$2" -eq "$try" ]];
    then
        delElement $1;
        # do iptables rule
        notify-send -t 500 "run iptables rule !"
        $ipt -I INPUT 1 -p tcp --dport $port -s $3 -j DROP
    
        # do time limit 
        notify-send -t 500 "set a crontab job"
	min=`date +"%M"`
	
	# deal with when the value less than 10, it will be 0X and can't do calculation
	min=`bc -l <<< "$min"`
	hour=`date +"%H"`
	
	# deal with when the value less than 10, it will be 0X and can't do calculation
	hour=`bc -l <<< "$hour"`
	((min=min+timeout))
	((min=min%60))
	if [ $timeout -gt 60 ]
	then
		((hour=hour+timeout/60))
		((hour=hour%24))
		echo $hour
	fi
	echo "set a crontab job"
        (crontab -l;echo "$min $hour * * *  $app/monitor.sh timelimit $3 $port")|crontab -
    else
        updateElement $1 $2 $3;
    fi
}


#set time limit for blocking the ip 
timelimit(){
    notify-send -t 0 "delete a rule from iptables INPUT chain $1 port $2" 
    
    $ipt -D INPUT -p tcp --dport $2 -s $1 -j DROP
    
    # delete the job from cron
    notify-send -t 500 "delete a job from crontab"  
    crontab -l|sed '/'$1'/d'|crontab -
}


# use regx to fetch ip 
ipvalid() {

	target=`echo "$text"|grep -P "$ex" -o`
}

# use awk to fetch ip
ipsplit(){

	target=`echo $text|awk "{print $fieldNo}"`
}



# get target from capture lines
getIP(){

	if [ $regx_on -eq 0 ]
	then
		ipsplit;
	else
		ipvalid;
	fi
}



# 
# main logic section
#
####################################################

# function options
if [ "$1" = "blacklist" ]
then
    echo -e "list all records of blacklist ...\n"
    listArray;
    exit 0
elif [ "$1" = "timelimit" ]
then
    timelimit $2 $3
    exit 0
elif [ "$1" = "-gui" ]
then
    gui_starter;
elif [ "$1" = "-set" ]
then 
    setVariables $2 $3 $4 $5
fi

tail -n0 -f $path | \

while read LINE
do
    # match key words if there is a issue
    if echo "$LINE" | grep "$keywords" 1>/dev/null 2>&1
    then
        # get target ip address from line
		text=$LINE
		echo $text
		getIP;

        #echo "find target visitor $target on $HOSTNAME"

        if [ "${#array[@]}" -gt 0 ]; 
        then
            insert=0;
            for index in "${!array[@]}" ;
            do
                # match visitor if this one is already in the list
                if echo "${array[index]}" | grep "$target" 1>/dev/null 2>&1
                then
                    insert=1;
                    # get the number of attempts the vistor tried.
                    curr=`echo ${array[index]}|awk '{print $2}'`
                    updateArray $index $curr $target;
                fi
            done
                
            if [[ "$insert" -eq "0" ]]
            then
                addNewElement $target;
            fi
        else
            notify-send -t 500 "array is empty"
            addNewElement $target;
        fi
    fi
done
