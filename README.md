# todo-notes-mern
Todo Notes full stack application with MongoDB, NodeJs, ExpressJs, NextJs/ReactJs

### Create mongodb database and user 
```bash
# loginto mongodb bash
docker exec -it mongodb bash

# log into mongodb database
mongosh mongodb://root:password@mongodb:27017/

# move to database
use todo-notes

# create user for current database with roles
db.createUser( { user: "admin", pwd: "password",   roles: [ "readWrite", "dbAdmin" ] } )

```

### Docker commands for postgres db
```bash
# loginto postgres bash
docker exec -it postgres psql -U postgres
```