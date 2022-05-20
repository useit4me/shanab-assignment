#!/bin/bash

declare -a logs
patt="serv_acc_log.+csv$"
mennum=1

### We are using an array to show the user their selection, the dummy is to offset the 
### first array element [0] so that we can match the user input without further logic
### the selection criteria array also helps us to easiliy get the keywords for grep, awk and sed in the csv file.
critArray=(DUMMY PROTOCOL SRC-IP SRC-PORT DEST-IP DEST-PORT PACKETS BYTES)

for file in ./*; do
    if [[ $file =~ $patt ]]; then 
        logs+=($(basename $file))
    fi
done

count=${#logs[*]}
echo "The logs array contains $count files.\n"

for file in "${logs[@]}"; do
    echo "$mennum $file"
    ((mennum++))
done

echo "\t"

##### Run a search on one (1) server access log of the user’s choosing based on one (1) field criteria input,
##### also of the user’s choosing, e.g. PROTOCOL=`TCP`
###### Get the csv filenames from the user input
###### store the user in put to the selection variable "sel" 

while true; do
echo "Enter the number of the file in the menu above you wish to search, i.e. [ 1,2,3,4 or 5] "
read -p " " sel 
if [[ $sel -ge 1 ]] && [[ $sel -le $count ]]; then
            break;
        else
            echo "Ivalid Input. Please try again."
        fi
done

file=${logs[$(expr $sel - 1)]}
echo "\nYou have entered $sel and the file you have chosen is $file\n"

##### on one (1) field criteria input,
##### also of the user’s choosing, e.g. PROTOCOL=`TCP`
##### Get the user input and store to the criteria variable

while true; do
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

echo "You have selected the criteria $criteria. ${critArray[criteria]}\n"

queryString=${critArray[criteria]}

##### The results of each search the user conducts are to be displayed to the terminal and also exported to
##### a .csv file with a name of the user’s choosing. Each results file created must be uniquely named so
##### that the results files of previous searches are not overwritten

while true; do
echo "Enter the name of the 'csv' file to export the results to:"
read -p " " csvfilename

##### Each results file created must be uniquely named so
##### that the results files of previous searches are not overwritten

dot="$(cd "$(dirname "$0")"; pwd)"
path="$dot/$csvfilename"

if [ -f "$path" ]; then
    echo "$csvfilename exists. please try again"
else 
     break;
fi
done

#### Any log file records in which the CLASS field is set to normal are to be automatically excluded from
#### the search results printed to the screen/written to file
#### we grep for suspicious and move that to a temp file

awk 'NR==1' < serv_acc_log_03042020.csv > tempfile.csv #Fro printing the index row
grep "suspicious" serv_acc_log_03042020.csv >> tempfile.csv

##### When the PACKETS and/or BYTES fields are selected by the user as search criteria, the user should
##### be able to choose greater than (-gt), less than (-lt), equal to (-eq) or not equal to !(-eq) the specific
##### value they provide, e.g. find all matches where PACKETS > `10`

#### For searching the PACKETS from user input
if [[ "$criteria" -eq 6 ]]; then
echo "Enter your search term: "
read -p " " pktsrch

echo "1. greater than (-gt)"
echo "2. less than (-lt)"
echo "3. equal to (-eq)"
echo "4. not equal to !(-eq)\n"
echo "Choose [1,2,3 or 4] :"
read -p " " logicopr

if [[ "$logicopr" -eq 1 ]]; then
    pktoper=">"
fi
if [[ "$logicopr" -eq 2 ]]; then
    pktoper="<"
fi
if [[ "$logicopr" -eq 3 ]]; then
    pktoper="="
fi
if [[ "$logicopr" -eq 4 ]]; then
    pktoper="!="
fi

#### how this query works, we are initially setting 
#### awk 'BEGIN {FS=","; ttlpackets=0}  --> here FS( field separator is)  ,(comma) 
#### the ttl packets to 0 so that if the search returns nothing we can show it as zero.
#### NR>=1 {  --> NR denotes the record or the file we are running this code on, and >=1 
#### means include all lines greater than one.  
####           if ( $8 '$pktoper' '"$pktsrch"') --> we are just doing a query on the $8 packets column
#### to match our search criteria. 
####               {
####                  ttlpackets=ttlpackets+$8 --> getting a count of ttl packets coulumns
#### if not we are adding our query results to the ttl packets count. --ttlpackets=ttlpackets+$8 
#### $8 is where the PACKETS column is. 
####                   printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $8
#### the query -- printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $8 -- means 
#### to show the columns $3--> PROTOCOL $4 -->SRC IP $5-->SRC PORT $6--> DEST IP $7-->DEST PORT $8--> PACKETS
#### and --printf "%-10s %-15s %-10s %-15s %-10s %-10s \n"-- is the spacing 10s means 10 spaces 
#### this is tuned to show a user readable table with results.
####  END { print "Total packets for all matching rows is ", ttlpackets } --> just printing result
####  ' < tempfile.csv >tmpresults.csv 
##### above line means we are < reading from tempfile.csv and writing > to tmpresults.csv

awk 'BEGIN {FS=","; ttlpackets=0}
    NR>=1 {
            if ( $8 '$pktoper' '"$pktsrch"')
                {
                    ttlpackets=ttlpackets+$8
                    printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $8
                }
    }
    END { print "Total packets for all matching rows is ", ttlpackets }
    ' < tempfile.csv >tmpresults.csv
fi

#### For searching the BYTES Same logic as above PACKETS just the columns and variables change.
#### Taking the user input sepratley on this one.
if [[ "$criteria" -eq 7 ]]; then
echo "Enter your search term: "
read -p " " bytsrch

echo "1. greater than (-gt)"
echo "2. less than (-lt)"
echo "3. equal to (-eq)"
echo "4. not equal to !(-eq)\n"
echo "Choose [1,2,3 or 4] :"
read -p " " logicopr

if [[ "$logicopr" -eq 1 ]]; then
    bytopr=">"
fi
if [[ "$logicopr" -eq 2 ]]; then
    bytopr="<"
fi
if [[ "$logicopr" -eq 3 ]]; then
    bytopr="="
fi
if [[ "$logicopr" -eq 4 ]]; then
    bytopr="!="
fi

##### When the PACKETS and/or BYTES fields are selected by the user as search criteria, the user should
##### be able to choose greater than (-gt), less than (-lt), equal to (-eq) or not equal to !(-eq) the specific
##### value they provide, e.g. find all matches where PACKETS > `10`
#### how this query works, here FS( field separator is)  ,(comma) we are initially setting 
#### the ttl packets to 0 so that if the search returns nothing we can show it as zero.
#### if not we are adding our query results to the ttl packets count. --ttlbytes=ttlbytes+$8 
#### $9 is where the BYTES column is. 
#### the query -- printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $9 -- means 
#### to show the columns $3--> PROTOCOL $4 -->SRC IP $5-->SRC PORT $6--> DEST IP $7-->DEST PORT $9--> BYTES
#### in the earlier awk we have used $8 for PACKETS now we are using $9 for listing BYTES
#### and --printf "%-10s %-15s %-10s %-15s %-10s %-10s \n"-- is the spacing 10s means 10 spaces 
#### this is tuned to show a user readable table with results.

awk 'BEGIN {FS=","; ttlbytes=0}
    NR>=1 {
           if ( $9 '$bytopr' '"$bytsrch"')
                {
                    ttlbytes=ttlbytes+$9
                    printf "%-10s %-15s %-10s %-15s %-10s %-10s \n", $3, $4, $5, $6, $7, $9
                }
    }
    END { print "Total packets for all matching rows is ", ttlbytes }
    ' < tempfile.csv >tmpresults.csv

fi

cat tmpresults.csv
exit 0
