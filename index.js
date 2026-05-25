require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { z } = require("zod");

const connectDB = require("./config/db");
const User = require("./models/User");
const Todo = require("./models/Todo");

const app = express();

app.use(express.json());

connectDB();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// --------------------
// Zod Schemas
// --------------------

const signupSchema = z.object({
  username: z.string().email("Username must be a valid email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

const signinSchema = z.object({
  username: z.string().email("Username must be a valid email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

const createTodoSchema = z.object({
  title: z.string().min(1, "Title is required"),
  description: z.string().min(1, "Description is required"),
});

const updateTodoSchema = z.object({
  title: z.string().min(1, "Title cannot be empty").optional(),
  description: z.string().min(1, "Description cannot be empty").optional(),
  completed: z.boolean().optional(),
});

// --------------------
// Auth Middleware
// --------------------

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Authorization header missing",
    });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Token missing",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.userId = decoded.userId;
    req.username = decoded.username;

    next();
  } catch (error) {
    return res.status(403).json({
      message: "Invalid token",
    });
  }
}

// --------------------
// Basic Route
// --------------------

app.get("/", (req, res) => {
  res.json({
    message: "Backend CRUD API with MongoDB, Zod, bcrypt and JWT is running",
  });
});

// --------------------
// Signup
// --------------------

app.post("/signup", async (req, res) => {
  try {
    const result = signupSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid input",
        errors: result.error.issues,
      });
    }

    const { username, password } = result.data;

    const existingUser = await User.findOne({
      username,
    });

    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "User created successfully",
      user: {
        id: user._id,
        username: user.username,
      },
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while signing up",
      error: error.message,
    });
  }
});

// --------------------
// Signin
// --------------------

app.post("/signin", async (req, res) => {
  try {
    const result = signinSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid input",
        errors: result.error.issues,
      });
    }

    const { username, password } = result.data;

    const user = await User.findOne({
      username,
    });

    if (!user) {
      return res.status(403).json({
        message: "Invalid username or password",
      });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(403).json({
        message: "Invalid username or password",
      });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        username: user.username,
      },
      JWT_SECRET,
    );

    res.json({
      message: "Signed in successfully",
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while signing in",
      error: error.message,
    });
  }
});

// --------------------
// Create Todo
// Protected Route
// --------------------

app.post("/todos", authMiddleware, async (req, res) => {
  try {
    const result = createTodoSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid input",
        errors: result.error.issues,
      });
    }

    const { title, description } = result.data;

    const todo = await Todo.create({
      title,
      description,
      userId: req.userId,
    });

    res.status(201).json({
      message: "Todo created successfully",
      todo,
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while creating todo",
      error: error.message,
    });
  }
});

// --------------------
// Get All Todos
// Protected Route
// --------------------

app.get("/todos", authMiddleware, async (req, res) => {
  try {
    const todos = await Todo.find({
      userId: req.userId,
    }).sort({ createdAt: -1 });

    res.json({
      todos,
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while fetching todos",
      error: error.message,
    });
  }
});

// --------------------
// Get Single Todo
// Protected Route
// --------------------

app.get("/todos/:id", authMiddleware, async (req, res) => {
  try {
    const todoId = req.params.id;

    const todo = await Todo.findOne({
      _id: todoId,
      userId: req.userId,
    });

    if (!todo) {
      return res.status(404).json({
        message: "Todo not found",
      });
    }

    res.json({
      todo,
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while fetching todo",
      error: error.message,
    });
  }
});

// --------------------
// Update Todo
// Protected Route
// --------------------

app.put("/todos/:id", authMiddleware, async (req, res) => {
  try {
    const result = updateTodoSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid input",
        errors: result.error.issues,
      });
    }

    const todoId = req.params.id;

    const updatedTodo = await Todo.findOneAndUpdate(
      {
        _id: todoId,
        userId: req.userId,
      },
      result.data,
      {
        new: true,
        runValidators: true,
      },
    );

    if (!updatedTodo) {
      return res.status(404).json({
        message: "Todo not found",
      });
    }

    res.json({
      message: "Todo updated successfully",
      todo: updatedTodo,
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while updating todo",
      error: error.message,
    });
  }
});

// --------------------
// Delete Todo
// Protected Route
// --------------------

app.delete("/todos/:id", authMiddleware, async (req, res) => {
  try {
    const todoId = req.params.id;

    const deletedTodo = await Todo.findOneAndDelete({
      _id: todoId,
      userId: req.userId,
    });

    if (!deletedTodo) {
      return res.status(404).json({
        message: "Todo not found",
      });
    }

    res.json({
      message: "Todo deleted successfully",
      todo: deletedTodo,
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong while deleting todo",
      error: error.message,
    });
  }
});

// --------------------
// Start Server
// --------------------

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
