#!/bin/bash

set -e
set -u

help() {
	cat <<-EOF
	Usage $0 [OPTIONS]

	-h         help
	-i <FILE>  input file path, stdin by default
	-o <FILE>  output file path, stdout by default
	EOF
}

IN=/dev/stdin
OUT=/dev/stdout
while getopts "hi:o:" OPT; do
	case $OPT in
		h)
			help
			exit
			;;
		i)
			IN=$OPTARG
			;;
		o)
			OUT=$OPTARG
			;;
		*)
			exit 1
			;;
	esac
done
if [[ $# -ne $((OPTIND-1)) ]]; then
	echo "No argument is expected" >&2
	exit 1
fi

cat >$OUT <<EOF
#!/bin/bash

set -e
set -u

: \${FILE_PERMISSION:=0600}
: \${FILE_PATH:=}
if [[ -z "\$FILE_PATH" ]]; then
	while read -p "Extract to: " FILE_PATH; do
		if [[ ! -z "\$FILE_PATH" ]]; then
			break
		fi
	done
fi

base64 -d >\$FILE_PATH <<END
EOF

base64 $IN >>$OUT

cat >>$OUT <<EOF
END

chmod \$FILE_PERMISSION \$FILE_PATH
EOF
