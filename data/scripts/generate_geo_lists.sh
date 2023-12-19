#! /bin/bash

# Sample script to extract and reformat db-ip file
# into e2guardian iplist format with a separate file  
# for each country code needed

# Modify the folling 3 exports to suit your requirements
# It is best to put the full path for the first two entries

# downloaded csv file with db-ip IPtoCountry list
export dbiplist=dbiplist.csv
# output directory
export OUTDIR=geo_countries
# needed country codes
export needed_countries="GB US"

if  [ ! -d ${OUTDIR} ]
then
   mkdir ${OUTDIR}
fi

for cnt in ${needed_countries}
      do
      # Extract country code entries |
      #    cut out IP's |
      #    Change ',' to '-' so it is in  e2g iplist format |
      #    remove IPv6 entries as e2g only supports IPv4 currently >
      #    write to output directory
      grep ",${cnt}\$" < ${dbiplist} |   
          cut -f1,2 -d, |              
          tr "," "-" |                
          grep -v ":" > ${OUTDIR}/${cnt}    
      done
