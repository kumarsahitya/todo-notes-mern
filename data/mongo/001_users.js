db = db.getSiblingDB('todo-notes')
db.createUser({
	user: "admin",
	pwd: "password",
	roles: [
		{
			role: "readWrite",
			db: "todo-notes",
		},
	],
});
