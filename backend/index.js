import express, { urlencoded } from "express";

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import universityStudents from "./studentsData.js";

const app = express();
const port = 3333;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.send("<h1>You are on main route of the api!</h1>");
});

app.get("/students", authenticateToken, (req, res) => {
  res.json(universityStudents);
});

app.post("/students", async (req, res) => {
  const newStudent = req.body;
  const maxId = Math.max(...universityStudents.map((student) => student.id));
  newStudent.id = maxId + 1;
  try {
    const salt = await bcrypt.genSalt(13);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    newStudent.password = hashedPassword;

    universityStudents.push(newStudent);
    res
      .status(200)
      .send(
        `Student successfully added to the database with user id ${maxId + 1}!`
      );
  } catch (error) {
    res.status(500).send("Internal server error!");
  }
});

app.get("/student/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const student = universityStudents.find((student) => student.id === id);
  if (!student) {
    return res.status(404).send("No such student found in the database!");
  }
  res.json(student);
});

app.put("/student/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  const updatedStudent = req.body;
  updatedStudent.id = id;
  if (req.body.password) {
    try {
      const salt = await bcrypt.genSalt(13);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);

      updatedStudent.password = hashedPassword;

      universityStudents.push(updatedStudent);
      res
        .status(200)
        .send(
          `Student successfully added to the database with user id ${
            maxId + 1
          }!`
        );
    } catch (error) {
      res.status(500).send("Internal server error!");
    }
  }

  // Find the index of the student with the given id
  const studentIndex = universityStudents.findIndex(
    (student) => student.id === id
  );

  if (studentIndex === -1) {
    return res.status(404).send("Student not found!");
  }
  universityStudents[studentIndex] = {
    ...universityStudents[studentIndex],
    ...updatedStudent,
  };

  res.status(200).send("Student data successfully updated in the database!");
});

app.delete("/student/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const student = universityStudents.find((student) => student.id === id);
  if (!student) {
    universityStudents.splice(universityStudents.indexOf(student), 1);
    return res.status(404).send("No such student found in the database!");
  }
  universityStudents.splice(universityStudents.indexOf(student), 1);
  res.send("Student was removed successfully form the database!");
});

//login and signup routes

app.post("/login", async (req, res) => {
  const student = universityStudents.find(
    (student) => student.contact.email === req.body.email
  );
  //authenticate the user first using correct eamil and password
  if (!student) {
    return res.status(404).send("No such student found in the database");
  }
  try {
    if (await bcrypt.compare(req.body.password, student.password)) {
      //using await is very important here
      // res.status(200).send("Login successful");
      //now once the user is authenticated using password => give him a JWT token for further access of the site
      const userEmail = req.body.email;
      const user = { user: userEmail };
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
      res
        .status(200)
        .json({ message: "Login Successful", accessToken: accessToken });
    } else {
      res.status(404).send("Password is incorrect");
    }
  } catch (error) {
    res.status(500).send("Internal server error!");
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(port, () => {
  console.log(`University server is listening on port ${port}`);
});
