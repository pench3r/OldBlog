#!/usr/bin/bash



for subDir in `ls -d */`
do
	cd $subDir
	for subFile in `ls`
	do
		fileExt=${subFile##*.}
		if [ $fileExt == "md" ]; then
			sed -i '/title: "/a\categories: "'${subDir%/}'"' $subFile
		fi
	done
	cd ..
done
