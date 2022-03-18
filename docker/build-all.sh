#!/usr/bin/env bash

echo ""
echo "-- BASE --"
echo ""
docker build --tag lucashagen/zeek-base ./base

echo ""
echo "-- FULL:LTS --"
echo ""
docker build --tag lucashagen/zeek-full:lts ./full

echo ""
echo "-- FULL:RC --"
echo ""
docker build --tag lucashagen/zeek-full:rc --build-arg ZEEK_PACKAGE="zeek-rc" --build-arg ZEEK_PATH="/opt/zeek-rc" ./full

echo ""
echo "-- FULL:LATEST --"
echo ""
docker build --tag lucashagen/zeek-full --build-arg ZEEK_PACKAGE="zeek-rc" --build-arg ZEEK_PATH="/opt/zeek-rc" ./full

# for d in ./* ; do
#     [ -d "$d" ] && [ ! -L "$d" ] || continue

#     d_name=$(basename -- "$d")
#     image_name="lucashagen/zeek-$d_name"

#     echo "Building '$image_name':"
#     docker build --tag $image_name $d
# done

echo ""
echo ""
echo "Done building images!"
