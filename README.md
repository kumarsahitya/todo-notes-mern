# todo-notes-mern
Todo Notes full stack application with MongoDB, NodeJs, ExpressJs, NextJs/ReactJs

### Create mongodb database and user 
```bash
# loginto mongodb bash
$ docker exec -it mongodb bash

# log into mongodb database
$ mongosh mongodb://root:password@mongodb:27018/

# move to database
$ use todo-notes

# create user for current database with roles
$ db.createUser( { user: "admin", pwd: "password",   roles: [ "readWrite", "dbAdmin" ] } )

```

### Docker commands for postgres db
```bash
# loginto postgres bash
$ docker exec -it postgres psql -U postgres

# view list of databases
$ \l

```
### Docker commands for initialize postgres db
```bash
# loginto nodejs/backend bash
$ docker exec -it backend
```
### Docker commands for build image and start
```bash
# build & start docker compose
$ docker-compose up -d --build

# only start docker compose
$ docker-compose up -d
