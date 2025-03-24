# 🚀 Folder Lock Backend

Folder Lock Backend is a Node.js API that handles authentication, folder encryption, and user management for the Folder Locker application.

## 📌 Features
- User authentication (JWT-based login/signup)
- Lock and unlock folders using Triple DES encryption
- Track folder lock/unlock history
- Secure API endpoints with middleware authentication

## ⚡ Getting Started
Follow these steps to set up and run the backend locally:

### 🔹 Step 1: Clone the Repository
```sh
git clone https://github.com/project-hub-one/folder-lock-backend.git
cd folder-lock-backend
```

### 🔹 Step 2: Install Dependencies
```sh
npm install
```

### 🔹 Step 3: Configure Environment Variables
Create a `.env` file in the project root and add the following details:
```
DB_HOST=""
DB_USER=""
DB_PASSWORD=""
DB_NAME="file_safe"
PORT="3000"
JWT_SECRET=""
```

### 🔹 Step 4: Run the Server
```sh
npm run dev
```
The API will be available at `http://localhost:3000`.


## ❓ Troubleshooting
- Ensure MySQL is running and credentials are correct.
- Verify all required environment variables are set.
- Check the logs for errors using:
```sh
npm run dev
```

## 📜 License
This project is open-source under the MIT License.

