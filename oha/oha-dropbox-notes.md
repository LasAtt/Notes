#How we've scaled Dropbox
##Kevin Modzelewski

Rapid-growth start-ups scaling or how Dropbox dealt with scaling with very minimal resources.

* 10s of millions of users
* 100s of millions of file syncs a day

###Challenges

1. Write volume, read to write ratio is 1:1, 10-100x more writes than other tech companies
2. Atomicity, Consistency, Isolation, Durability requirements

Arcitechture began very simple, just one server. Eventually servers load was split to Amazon S3 for file storage and a separate MySQL server. Further down the road, work had to be split to multiple servers, website access and syncing separate. A notification server was also added, which would push file notifications to clients. The server was separated into 2, an meteserver, which read the database but had no access to files, and an blockserver which, had access to file storate and made queries to the MySQL database. Eventually to reduce round trip calls, the blockserver was made to do RPC calls to the metaserver through a load balancer, which would contain the DB queries the metaserver had to do, the metaserver would thus handle all DB logic. To reduce load on the database, of which there was only one, a memcache was also added. Eventually more servers of each type were added.
