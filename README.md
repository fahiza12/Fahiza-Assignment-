# Fahiza-Assignment-

# 🔐 Node.js Authentication Assignment

## 📌 Objective
This project demonstrates **Password Hashing Authentication** using **bcrypt** and **JWT Authentication** in a simple Node.js + Express server.

---

## 🚀 Features
### Task 1 – Password Hashing
- **POST /register** → Register a new user (password stored after hashing).
- **POST /login** → Login with username & password (bcrypt verification).

### Task 2 – JWT Authentication
- On login, generates a **JWT token**.
- **GET /profile** → Protected route, accessible only with valid token.

---

## ⚡ Installation & Setup
1. Clone this repo:
   ```bash
   git clone <your-repo-link>
   cd Fahiza-Assignment
   npm install

   npm start
