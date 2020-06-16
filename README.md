# verify-upload
verify-upload and hash-service are a set of complementary tools 
for performing hash verification of FTP uploads without modifying
the FTP protocol.

## How it works

hash-service is a service that should run on the same server
as an [FTP data server](https://tools.ietf.org/html/rfc959). 
The hash-service daemon implements
a [simple API](hash-service.c) that can hash files from the local FTP server.

To verify the integrity of an FTP upload, use verify-upload to
upload the file to an FTP server, and it will automatically 
use the hashing service to verify that the file was uploaded 
successfully.

## How to install it

Make sure you have a copy of `gcc` and `make`. 
Any version from the past 20 years should do.

Then run

```
sudo make install
```

Or equivalent superuser command for your system.

## How to use it

`hash-service`:
```
Usage: hash-service [port=8009] [server_ip=127.0.0.1]
```

`verify-upload`:
```
Usage: verify-upload [OPTION...] --server <IP>:[PORT] [FILE...]

Connection Setup:
  -s, --server=IP:PORT          connect to the server given IP and port
  -u, --user=USERNAME           connect to the server with the specified username
                                (default: ftp)
  -p, --password=PASSWORD       connect to the server with the specified password
                                (default: will prompt for password)

Configuration:
  -r, --retries=RETRIES         number of times to retry upload before giving up
                                (default: 5)
  -q, --quiet                   suppress console output and progress bar
  -l, --loud                    print connection status information

Etc:
  -v, --version                 print version information
  -h, --help                    print this help message
```

## vsftpd users
In theory, verify-upload and hash-service should work with
any [FTP standard compliant](https://tools.ietf.org/html/rfc959) 
FTP server. Unfortunately, I
have been unable to verify that such server software exists.

I tested this using vsftpd, so I can reccomend some fixes to make
everything work:

verify-upload uses some FTP features that are turned off by
 defualt in vsftpd. To turn them on, add 
```
pasv_promiscuous=YES
```
to your `vsftpd.conf`. Also, make sure PASV mode is 
enabled.

Additionally, vsftpd has some _undocumented behavior_ that causes
hash-service to fail when it tries to use the default IP of
`127.0.0.1`. In this case you'll need to run it using the server's
local area network ip instead of the localhost address.


## FAQ

* Why does this exist?

  I use FTP for backups and I get paranoid about upload integrity.
This gives me some peace of mind that any backups were uploaded
without errors.

* Your code sucks
  
  That's not a question.

* Why isn't this written in Go?
  
  I didn't know Go when I wrote this. Now I'm sad.

* Why isn't this written in Rust?
  
  It's a service. You don't write services in Rust, you
  write everything that's _not_ a service in Rust!