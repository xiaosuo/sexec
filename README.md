# sexec

Execute commands on remote machines in parallel securely.

# Usage

```
Execute commands via SSH
Usage: ./src/sexec [OPTION]... [HOST]...

Options:
  -a, --auth <METHODS>  Authentication methods separated by `,'
                        `gssapi,publickey' by default
                        `gssapi' and `publickey' are supported
  -c, --cmd <CMD>       Execute <CMD>
  -d, --dedup           Dedup hosts
  -e, --env var=val     Set `val' to environment variable `var'
  -f, --file <FILE>     Execute <FILE>
  -h, --help            Show this message
  -i, --identity <FILE> The identity (private key) file
  -p, --parallel <N>    Max parallel sessions per thread,
                        1 by default
  -t, --timeout <SEC>   Timeout in seconds per session,
                        -1 by default
  -u, --user <USER>     Signed in as <USER>
  -H, --host <FILE>     Use the hosts in <FILE>. A single dash(`-')
                        means the standard input
  -T, --threads <N>     Use <N> threads
  -V, --version         Display the version of sexec and exit
```

# Tips

## Push a file

For example, push a local file in to user@127.0.0.1:/tmp/xxx
```
$ ./contrib/pack.sh -i in -o out.sh
$ sexec -e FILE_PATH=/tmp/xxx -f out.sh -uuser 127.0.0.1
```
