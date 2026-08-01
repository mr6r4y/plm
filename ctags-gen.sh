#!/bin/bash


packages=(
	cmocka/1.1.8
)

function c_tags()
{
	find "$@" -name '*.c' > ctags-files.txt
	find "$@" -name '*.cc' >> ctags-files.txt
	find "$@" -name '*.CC' >> ctags-files.txt
	find "$@" -name '*.[chCH]' >> ctags-files.txt

	ctags -L ctags-files.txt
}

ct_directories=""

for p in  ${packages[@]};do
	pkgid=$(NO_COLOR=1 conan list $p:* -p build_type=Debug | sed "7q;d" | xargs);
	pkgpath=$(NO_COLOR=1 conan cache path $p:$pkgid);
	srcpath="$pkgpath/../b/src";
	dir1="$srcpath/src"
	dir2="$srcpath/include"
	dir3="$srcpath/def_frame"

	if [ -d $dir1 ]; then
		ct_directories="$ct_directories $dir1"
	fi
	if [ -d $dir2 ]; then
		ct_directories="$ct_directories $dir2"
	fi
	if [ -d $dir3 ]; then
		ct_directories="$ct_directories $dir3"
	fi
done;

echo ct include/ $ct_directories
c_tags include/ $ct_directories
