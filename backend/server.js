const express = require("express");

const app = express();

require("dotenv").config();
const PORT = process.env.PORT || 4000;

// json
app.use(express.json());

// cors
app.use((req, res, next) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
	next();
});

// test api
app.get("/test", (req, res) => {
	try {
		res.status(200).json({ message: "API is working" });
	} catch (error) {
		res.status(500).json({ message: error.message });
	}
});

app.listen(PORT, () => {
	console.log(`Server Started on port ${PORT}`);
});
