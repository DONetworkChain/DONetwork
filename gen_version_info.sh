#!/bin/sh


SHDIR=$(dirname `readlink -f $0`)

name="don_"
gitversion=$(git rev-parse --short HEAD)
version=$(sed -n "/static const std::string kLinuxCompatible = /p" ${SHDIR}/common/global.h | awk -F '[\"]' '{print $2}')

finalname=${name}"v"${version}

if [ ${#gitversion} -eq 0 ]
then
    echo "there is no git in your shell"
    exit
else
    finalname=${finalname}"_"${gitversion}
fi;

if [ "$1" == "0" ]
then
    finalversion=${finalname}"_""primarynet"
    echo  "${finalversion}"
elif [ "$1" == "1" ]
then
    finalversion=${finalname}"_""testnet"
    echo  "${finalversion}"
else
    finalversion=${finalname}"_""devnet"
    echo  "${finalversion}"
fi;

if [ -f $2/bin/don ]
then
    mv $2/bin/don $2/bin/${finalversion}
else
    echo "don not exist"
fi;
 
#sed -i "s/build_commit_hash.*;/build_commit_hash = \"${gitversion}\";/g" ./ca/global.cpp
