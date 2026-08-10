#!/bin/sh

version=$(cat module.prop | grep 'version=' | awk -F '=' '{print $2}' | sed 's/ (.*//')

version='v'$(grep '^version =' ../../lowertier/Cargo.toml | cut -d '"' -f 2)

if [ -z "$version" ]; then
    echo "Error: 版本号不存在."
    exit 1
fi

filename="lowertier_magisk_${version}.zip"
echo "$version"


if [ -f "./lowertier-core" ] && [ -f "./lowertier-cli" ] && [ -f "./lowertier-web" ]; then
    zip -r -o -X "$filename" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'
else
    wget -O "lowertier_last.zip" https://github.com/lowertier/lowertier/releases/download/"$version"/lowertier-linux-aarch64-"$version".zip
    unzip -o lowertier_last.zip -d ./
    mv ./lowertier-linux-aarch64/* ./
    rm -rf ./lowertier_last.zip
    rm -rf ./lowertier-linux-aarch64
    zip -r -o -X "$filename" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'
fi
