require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const passport = require("passport");

const config = require("./config");
require("./config/passport");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const { notFoundHandler, errorHandler } = require("./middleware/errorHandler");
const app = express();

app.set("trust proxy", 1);

app.use(helmet());
app.use(morgan("combined"));
app.use(
  cors({
    origin: config.corsOrigin,
    credentials: true,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(cookieParser());
app.use(passport.initialize());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.get("/health", (_req, res) => {
  res.json({
    success: true,
    service: "auth-service",
    status: "ok",
    environment: config.nodeEnv,
  });
});

app.use("/api/auth", authRoutes);
app.use(notFoundHandler);
app.use(errorHandler);

const startServer = async () => {
  try {
    await connectDB();

    app.listen(config.port, () => {
      console.log(`Auth Service running on port ${config.port}`);
      console.log(`Environment: ${config.nodeEnv}`);
    });
  } catch (error) {
    console.error("Failed to start Auth Service:", error.message);
    process.exit(1);
  }
};

startServer();
