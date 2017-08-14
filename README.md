Warning! In Early Development
----------------------------
Getting ready for prime time.  Feel free to create issues 
for features you want to see.  
Checkout the [board](https://github.com/DarcInc/repository/projects/1)
to see what's in the pipe.


[![Build Status](https://travis-ci.org/DarcInc/repository.svg?branch=master)](https://travis-ci.org/DarcInc/repository)
[![Go Report Card](https://goreportcard.com/badge/github.com/darcinc/repository)](https://goreportcard.com/report/github.com/darcinc/repository)
[![Coverage Status](https://coveralls.io/repos/github/DarcInc/repository/badge.svg?branch=master)](https://coveralls.io/github/DarcInc/repository?branch=master)


Create Secure Backups or Transfers
==================================

Imagine the following situation.  You have sensitive information like health
records that need to be transferred between two locations.  It's not a one-time
transfer, it is a schedule job.  Maybe it's a backup of sensitive data.  You'd 
like to use a commodity service like S3, but is the data really secure?  What
about the intermediate networks?  Maybe you need to transfer data between two
internal networks but security controls require the data to be encrypted at 
rest and in transit.

Repository attempts to solve this problem by using strong encryption with strong,
random keys.  The goal is to create an archive that can be transferred between
two environments but in a way that can be easily automated and managed.  

Tapes
-----

The basic abstraction is a tape, which is an AES 256 encrypted stream of data.
The key to that is a strongly random 32 character password.  AES 256 can support
file sizes in excess of 2^64 bytes.  It is used to encrypt hard drives and is
supported in hardware.  

The problem then becomes securely transferring that password to the other end 
of the transfer.

Labels
------

A label uses RSA public/private keys to secure and sign the AES 256 password and
the initialization vector used to decrypt the tape.  Two users who want to 
exchange files only need to generate keys and exchange their public keys.  
A label can be separated from the tape allowing the tape to transfer over 
one channel (e.g. S3) and the label to be transferred over another channel 
(e.g. e-mail).  

A label and its tape can be stored together or separated.  The simple key management
library included supports basic key management, allowing users to generate multiple
keys.  For example, a new keypair may be generated for each customer or even for
each transfer.  It is up to the user to ensure the key file is in a secure location
(e.g. a directory only their user id or 'root' can read).

Cross Platform
--------------

Another goal is to make the software cross-platform.  A windows users should be
able to securely transfer data to a Linux system.  
