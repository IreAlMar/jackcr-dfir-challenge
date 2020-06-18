#/bin/bash

# From the AMF book, not tested on real invironment

for j in FLD-SARIYADH-43 ENG-USTXHOU-148
  do
  
  file=challenge/$j/memdump.bin
  loc=challenge/REG/$j
  short=`echo $j |cut -d\- -f1`
  mkdir -p $loc
  
  for i in config.system config.security config.sam config.default config.software ntuser.dat usrclass.dat
    do
      echo python vol.py -f $file dumpfiles -i -r $i\$ -D $loc
      python vol.py -f $file dumpfiles -i -r $i\$ -D $loc
    done

  find $loc -type f -exec python timeline.py --body '{}' >> $loc.temp;
  cat $loc.temp |sed "s/\[Registry None/\[$short Registry/" >> $loc.registry.body
  rm $loc.temp

done