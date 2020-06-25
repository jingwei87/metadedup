# Enabling Secure and Space-Efficient Metadata Management in Encrypted Deduplication

## Introduction

Encrypted deduplication combines encryption and deduplication in a seamless way to provide confidentiality guarantees for the physical data in deduplicated storage, yet it incurs substantial metadata storage overhead due to the additional storage of keys. We present a new encrypted deduplication storage system called Metadedup, which suppresses metadata storage by also applying deduplication to metadata. Its idea builds on indirection, which adds another level of metadata chunks that record metadata information. We find that metadata chunks are highly redundant in real-world workloads and hence can be effectively deduplicated. We further extend Metadedup to incorporate multiple servers via a distributed key management approach, so as to provide both fault-tolerant storage and security gaurantees. We extensively evaluate Metadedup from performance and storage efficiency perspectives. We show that Metadedup achieves high throughput in writing and restoring files, and saves the metadata storage by up to 93.94% for real-world backup workloads.



## Publication

*  Jingwei Li, Patrick P. C. Lee, Yanjing Ren, and Xiaosong Zhang. **Metadedup: Deduplicating Metadata in Encrypted Deduplication via Indirection**. Proceedings of the 35th International Conference on Massive Storage Systems and Technology (MSST 2019), Santa Clara, U.S.A, May 2019.

## Dependencies

Metadedup is built on Ubuntu 18.04.4 LTS with GNU gcc version 7.5.0. It requires the following libraries:

* cmake (version: 3.10.2)
* OpenSSL (version: 1.1.1)
* Boost C++ library 
* GF-Complete 
* Leveldb 

To install OpenSSL, Boost C++ library, GF-complete and snappy (that is necessary for Leveldb), type the following command:
```shell
$ sudo apt-get install libboost-all-dev libsnappy-dev libssl-dev libgf-complete-dev 
```
Leveldb is packed in `server/lib/`, and compile it using the following command:  
```shell
$ make -C server/lib/leveldb/ -j 8
```

## Configuration

Metadedup distributes data across s + 1 (s = 4 by default) servers for storage, such that the original data can be retrieved provided that any t + 1 (t = 3 by default) out of the s + 1 servers are available. You can edit the configuration file `client/config-u` to set server information for upload. 

An example of `client/config` is shown as follows:

```
0.0.0.0:11011
0.0.0.0:11021
0.0.0.0:11031
0.0.0.0:11041
0.0.0.0:11051

0.0.0.0:11012
0.0.0.0:11022
0.0.0.0:11032
0.0.0.0:11042
0.0.0.0:11052

0.0.0.0:11013
0.0.0.0:11023
0.0.0.0:11033
0.0.0.0:11043
0.0.0.0:11053
```

* Line 1-5 specify the IP addresses of 5 running servers, as well as corresponding meta ports (that are for the upload of metadata chunks).
* Line 7-11 specify the IP addresses of 5 running servers, as well as corresponding data ports (that are for the upload of data chunks). 
* Line 13-17 specify the IP addresses of 5 running servers, as well as corresponding key generation ports (that are for the generation of MLE keys). 

## Compilation

### Server

Metadedup server processes data, metadata, and key management separately. Compile the server program via the following commands: 
```shell
# You need to compile leveldb before this
$ mkdir build; cd build
$ cmake .. 
$ cmake --build . --target server -- -j 8
# copy keys for key generation
$ cp -r ../keymanager/keys/ ./bin/
# create necessary folder for DB
$ cd bin; mkdir -p meta/DedupDB meta/RecipeFiles meta/ShareContainers meta/minDedupDB meta/minShareContainers 
```

### Client

Compile and generate an executable program for client.

```shell
$ mkdir build; cd build
$ cmake .. 
$ cmake --build . --target client -- -j 8
# copy keys for key generation
$ cp -r ../keys ./bin
# copy config file for client runtime
$ cp ../config ./bin/
```

## Usage

First, start each Metadedup server by the following command. Here `meta port` and `data port` indicate the ports that are listened for data and metadata processing, respectively. `key port` is the port for generating keys with key manager. Note that the ports need to be consistent with those in  `client/config-u`.

```shell
$ ./server [meta port] [data port] [key port]
```

Then, use the executable program `client` in the following way:

```shell
usage: ./client [filename] [userID] [action] [secutiyType]

- [filename]: full path of the file;
- [userID]: user ID of current client;
- [action]: [-u] upload; [-d] download;
- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1
```

As an example, to upload a file `test` from user 11 using high security mechanism (e.g., AES-256 & SHA-256), type the following command:

```shell
$ ./client test 11 -u HIGH
```

To further download the file `test`, follow the command:
```shell
$ ./client test 11 -d HIGH
```

## Misc

### GF-Complete Installation from Source 

Some Linux systems do not support to install GF-Complete from package managers. We provide instructions to install GF-Complete from source code. 

Download the source code of GF-Complete from [here](http://lab.jerasure.org/jerasure/gf-complete/tree/master), go into GF-Complete folder, and follow the commands for installation:  
```shell
$ ./configure
$ make
$ sudo make install
```

### Changing (s, t)

s and t can be configured by tuning  `n_`  (that is equivalent to s) and `k_` (that is equivalent to t) in `client/utils/conf.hh`, respectively.

```markdown
// default configuration of Metadedup 
n_ = 4;
m_ = 1;
k_ = n_ - m_;
r_ = k_ - 1;
```

* `(n_, k_)` defines the fault tolerance capability of the underlying secret sharing algorithm.

## Maintainer

* Suyu Huang, UESTC, gabrielf977q@gmail.com
