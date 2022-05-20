#!/bin/bash

declare -a logs
patt="serv_acc_log.+csv$"
mennum=1
### search for log files and get the csv files count and name for user to select input file.
for file in ./*; do
    if [[ $file =~ $patt ]]; then 
        logs+=($(basename $file))
    fi
done
count=${#logs[*]}

### We are using an array to show the user their selection, the dummy is to offset the 
### first array element [0] so that we can match the user input without further logic
### the selection criteria array also helps us to easiliy get the keywords for grep, awk and sed in the csv file.
critArray=(DUMMY PROTOCOL SRC-IP SRC-PORT DEST-IP DEST-PORT PACKETS BYTES)



#############################################################
###############----------FUNCTIONS----------#################
#############################################################



select_search_log () {
    ##### OBJECTIVE
    ##### Run a search on one (1) server access log of the user’s choosing based on one (1) field criteria input,
    ##### also of the user’s choosing, e.g. PROTOCOL=`TCP`
    ###### Get the csv filenames from the user input
    ###### store the user in put to the selection variable "sel" 

    if [[ $sel -ge 1 ]] && [[ $sel -le $count ]]; then
        file=${logs[$(expr $sel - 1)]}
        echo "\nYou have entered $sel and the file you have chosen is $file\n"

        ## filter the selected file from normal records
        ## here we are searching a single file
        awk 'NR==1' < $file > tempfile.csv #For printing the index row
        grep "suspicious" $file >> tempfile.csv # For getting only suspicious records.
    fi

    if [[ $sel -eq 6 ]]; then

        echo "\nYou have entered $sel to search all log files\n"

        ## filter the selected file from normal records
        ## here we are searching all the files
        ## For printing the index row from one of the files in the array
        ## Adding-- DATE,DURATION,PROTOCOL,SRC IP,SRC PORT,DEST IP,DEST PORT,PACKETS,BYTES,FLOWS,FLAGS,TOS,CLASS
        ## to the first line of tempfile.csv
        awk 'NR==1' < ${logs[1]} > tempfile.csv 

        ### Next we move through all the files and append them to the tempfile for searching
        ### We are using the >> operator for appending the file.
        for file in "${logs[@]}"; do
            #grep "suspicious" $file >> tempfile.csv # For filtering only suspicious records from normal.
            awk '/suspicious/ && /'"$protocol"'/' < $file >> tempfile.csv  
            ### searches for suspicious records matching search criteria 
        done
    fi
}

get_csv_filename() {
    ##### OBJECTIVE
    ##### The results of each search the user conducts are to be displayed to the terminal and also exported to
    ##### a .csv file with a name of the user’s choosing. Each results file created must be uniquely named so
    ##### that the results files of previous searches are not overwritten
    while true; do
        echo "Enter the name of the 'csv' file to export the results to [Eg:- results.csv]"
        read -p " " csvfilename

        ##### Each results file created must be uniquely named so
        ##### that the results files of previous searches are not overwritten
        dot="$(cd "$(dirname "$0")"; pwd)"
        path="$dot/$csvfilename"

        #### Check if similar file exists
        if [ -f "$path" ]; then
            echo "$csvfilename exists. please try again"
        else 
            #touch $csvfilename
            break;
        fi
    done
}

select_operator() {
    echo "Enter your search value for searching ${critArray[criteria]}: "
    read -p " " srchval
    echo "1. greater than (-gt)"
    echo "2. less than (-lt)"
    echo "3. equal to (-eq)"
    echo "4. not equal to !(-eq)\n"
    echo "Choose [1,2,3 or 4] :"
    read -p " " logicopr

    if [[ "$logicopr" -eq 1 ]]; then
        seloperator=">"
    fi
    if [[ "$logicopr" -eq 2 ]]; then
        seloperator="<"
    fi
    if [[ "$logicopr" -eq 3 ]]; then
        seloperator="="
    fi
    if [[ "$logicopr" -eq 4 ]]; then
        seloperator="!="
    fi
}

search_for_protocols() {
    while true; do
        echo "Enter the protocol to search [TCP, UDP, ICMP, GRE] "
        read -p " " protocol
        #### OBJECTIVE
        #### 1. All string-based searches should be case insensitive.
        #### $(echo $protocol | tr 'a-z' 'A-Z') converts all cases to upper case
        protocol=$(echo $protocol | tr 'a-z' 'A-Z')

        if [[ "$protocol" == TCP ]] || [[ "$protocol" == UDP ]] || [[ "$protocol" == ICMP ]] || [[ "$protocol" == GRE ]]; then

            awk '/suspicious/ && /'"$protocol"'/' < tempfile.csv >> dump  
            ### searches for suspicious records matching search criteria 

            awk 'BEGIN {FS=","}
                NR>=1 {
                            printf "%-10s %-15s %-10s %-15s %-10s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9
                      }
                END {print "Protocols matching '"$protocol"' is: ", NR}
                ' < dump > $csvfilename

                cat $csvfilename
                rm dump
        break;
        else
            echo "$protocol is invalid input, enter [TCP, UDP, ICMP, GRE]"
        fi
    done
}

search_bytes() {
    awk 'BEGIN {FS=","; ttlbytes=0}
        NR>=1 {
               if ( $9 '$2' '"$1"')
                    {
                        ttlbytes=ttlbytes+$9
                        printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $9
                    }
        }
        END { print "Total rows with matching bytes value/range are ",  NR }
        ' < tempfile.csv > $csvfilename
    cat $csvfilename
}

search_packets() {
    awk 'BEGIN {FS=","; ttlpackets=0}
        NR>=1 {
                if ( $8 '$2' '"$1"')
                    {
                        ttlpackets=ttlpackets+$8
                        printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $8
                    }
            }
        END { print "Total rows with matching packet value/range are ",  NR }
        ' < tempfile.csv > $csvfilename
    cat $csvfilename
}

search_again() {
    read -n 1 -p "Do you wish to make another search (y/n)? " answer
    case ${answer:0:1} in
    y|Y )
        main_menu
    ;;
    * )
        exit 0
    ;;
esac
}


###############################################################
############-----------MAIN CODE-------########################
###############################################################


main_menu() {
### Ask the user for search criteria
while true; do
    echo "\n"
    echo "1.PROTOCOL  2.SRC-IP  3.SRC-PORT  4.DEST-IP  5.DEST-PORT  6.PACKETS  7.BYTES"
    echo "\n"
    echo "Please enter the criteria to search:"
    read -p " " criteria 
        if [[ $criteria -ge 1 ]] && [[ $criteria -le 7 ]]; then
            break;
        else
            echo "Ivalid Input. Please try again."
        fi
done
### Show user their selection
echo "You have selected the criteria $criteria. ${critArray[criteria]}\n"
#### END OF CRITERIA SELECTION ########


### Ask User for file input to run the searches on.
 while true; do
    echo "The logs array contains $count files.\n"
    for file in "${logs[@]}"; do
        echo "$mennum $file"
        ((mennum++))
    done
    echo "\t"
    echo "Enter the number for the corresponding file you wish to search, i.e. [ 1,2,3,4 or 5]"
    echo "or enter number 6 to search all the log files listed above.\n "
    read -p " " sel 
        if [[ $sel -ge 1 ]] && [[ $sel -le 6 ]]; then
            break;
            else
            echo "Ivalid Input. Please try again."
        fi
done
### Show user their selection
echo "you have selected $sel "
#### END OF FILE SELECTION ########

# Call the function to select a single search log
select_search_log $sel

# Ask the user for csv filename to save the results.
get_csv_filename

# If user chose to search for TCP, UDP, ICMP, GRE etc.
if [[ "$criteria" -eq 1 ]]; then
    search_for_protocols
    search_again
fi

# If user chose to search for SRC-IP
if [[ "$criteria" -eq 2 ]]; then
    echo "nothing defined for SRC-IP"
    search_again
fi

# If user chose to search for SRC-PORT
if [[ "$criteria" -eq 3 ]]; then
     echo "nothing defined for SRC-PORT"
     search_again
fi
# If user chose to search for DST-IP
if [[ "$criteria" -eq 4 ]]; then
     echo "nothing defined for SRC-IP"
     search_again
fi
# If user chose to search for DST-PORT
if [[ "$criteria" -eq 5 ]]; then
     echo "nothing defined for DST-PORT"
     search_again
fi

# If user chose to search for PACKETS
if [[ "$criteria" -eq 6 ]]; then
    select_operator
    search_packets $srchval $seloperator
    search_again
fi

# If user chose to search for BYTES
if [[ "$criteria" -eq 7 ]]; then
    select_operator
    search_bytes $srchval $seloperator
    search_again
fi
}
main_menu

exit 0
