# Mongo NSS module
This module allows linux to fetch user and group data from any web api that matches the right specification

## Development

If you wish to do further development on this perform the following:  
1. Clone the repository
2. Run `./build_reqs` to install the required development packages
3. Fill out `mongonss.conf.example` and copy it to `/etc/security/mongonss.conf`
4. Make your changes
5. Run `./build && ./deploy` to build the package and then deploy it on your current machine
6. Modify `/etc/nsswitch.conf` to enable the module

### nsswitch.conf example
```
passwd:     files mongo sss
shadow:     files sss
group:      files mongo sss
```
### *_DO NOT PUT MONGO FIRST!_*  
If you break the module while it's checked first, you won't be able to SSH back into the machine   
This is surprisingly easy to do...

### Testing
You can test the module using the  `id` and `groups` commands.  

## Useful Resources
The definitions for all of the methods can be found by just googling them, the same is true for the special passwd and group structs.  
With the exception of initgroups_dyn which is a nightmare to find any info on.  
This is the best source I've found for example code:
https://github.com/agamez/libnss-sqlite3/blob/85c0a0e9f79b103653dd8467f49d7a96065fe67c/groups.c#L307

## Packaging
------
This is done using fpm, after you have run build_module.sh to create and populate the "target" directory.    
You can install fpm on centos 7 using the command below.
```
yum install -y ruby-devel gcc make rpm-build rubygems && gem install --no-ri --no-rdoc ffi -v 1.12 && gem install --no-ri --no-rdoc fpm -v 1.11.0 && gem install --no-ri --no-rdoc fpm -v 1.4.0
```
For other operating systems, check here -> https://fpm.readthedocs.io/en/latest/installing.html
```
fpm -s dir -t rpm -d openldap -d libcurl -d libconfig -n mongonss --version 1.0.0 -C target/ --description "NSS module for Authentication with REST api"
```

# API Specification
The api that this module contacts must exactly match this spec or things will go horribly wrong.

## Endpoints
The endpoints are routing must have the facility at the root before anything else[^1]  
`https://api.example.com/<facility_name>/`  
facility_name = 'isis' or 'clf'  

### NO DATA   
If no user or group data can be found, return python `None` type, which this C module interprets as the string "null". 

### get user by name
`users/name/<username>`  
Returned json object should include:
```json
{
    "pw_name": "jc1104039",
    "pw_passwd": "x", 
    "pw_uid": 2024922, 
    "pw_gid": 1751502, 
    "pw_gecos": "", 
    "pw_dir": "/home/jc1104039", 
    "pw_shell": "/bin/bash"
 }
```
---
### get user by id
`users/id/<uid>`  
Returned json object should be the same as above.

---
### get group by name
`groups/name/<username>`  
Returned json object should include:
```json
{
    "gr_name": "RB1610093", 
    "gr_passwd": "x", 
    "gr_gid": 1757409
}
```
---
### get group by GID
`groups/id/<gid>`  
Returned json object should be the same as above.   

---
### get groups for user by name
`usergroups/<username>`  
Returned json object should be in the following format:
```json
{
    "gids": [1754318, 1757409]
}
```
Where "gids" is a list of the gids for each group the user is in.

---
[^1] Technically you can point this at any api, which means it doesn't need this base routing. However [the api we use](https://github.com/ral-facilities/daaas-eve-nss-interface) has this hard coded base routing to be able to determine if it should get information for ISIS or CLF
