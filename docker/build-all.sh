#!/usr/bin/env bash

for d in ./* ; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue

    d_name=$(basename -- "$d")
    image_name="lucashagen/zeek-$d_name"

    echo "Building '$image_name':"
    docker build --tag $image_name $d
done

echo ""
echo ""
echo "Done building images!"
