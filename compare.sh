#/bin/bash
file=./notice.log
fingerprintfile=./checker.log

# does the file exist?
 if [ ! -f $file ]
         then
             echo "ERROR: $file does not exist - aborting"
         exit 1
 fi                             
 filemd5=`md5sum $file | cut -d " " -f1`
 
 if [ -z $filemd5 ]
         then
             echo "The file is empty - aborting"
             exit 1
         else
             # pass silent
             :
 fi      
 if [ -f $fingerprintfile ]
         then
         # yup - get the saved md5
         savedmd5=`cat $fingerprintfile`
         if [ -z $savedmd5 ]
            then
                    echo "The file is empty - crating a new one"
                    touch /home/tk/Desktop/Zeek - PW/ICMP-Construction/checker.log
                   echo $filemd5 > $fingerprintfile
                   exit 1
        fi

        if [ "$savedmd5" = "$filemd5" ]
                then
                        # pass silent
                        :
                else
                        echo "File has been changed sendingg mail"
                        cat $file | mail -s "Raport Attack Changed" ttomek.koziak@gmail.com
                fi
fi
echo $filemd5 > $fingerprintfile

