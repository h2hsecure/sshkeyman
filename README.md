# SSH KEY MANAGEMENT

All the time, maginig ssh keys in server farm is little hard problem. SSH key management allows you to manage your users and their ssh-keys
from central Identity store (keycloak, web etc.)

## How is it working

It preodicly check ssh public keys fron backend storage (keycloak, web etc.) then store it to related storage.
When related user wanted to login to the server, regular ssh-key authentication takes place.
There are 2 component;

  - lib_nss module
  - regular exec for linux

you need to place them into proper location and configure related configuration files.

## Installing

Please run `make install` in source directory. this script will create 2 binaries and replaces them to related locations.

# Q&A

 - can we create home directory automaticly? 
 - Please copy this line to `/etc/pam.d/common-session` file
 ```shell
 session    required    pam_mkhomedir.so skel=/etc/skel/ umask=0022
 ```