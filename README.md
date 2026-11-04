# CodeAlpha Secure Login (C++)

A Windows console login and registration application written in C++17. It demonstrates input validation, password hashing, file-based account storage, and automated tests.

## Features

- Register and log in with a username and password
- Validate usernames (3–20 letters, digits, `_` or `-`)
- Validate passwords (8–128 characters, at least one letter and one digit)
- Confirm passwords during registration and prevent duplicate usernames
- Store a unique random salt and a PBKDF2-HMAC-SHA-256 hash, never the original password
- Mask password entry in the Windows console
- Run automated tests with CTest

## Requirements

- Windows 10 or 11
- CMake 3.20 or newer
- Visual Studio 2022 or newer, or Visual Studio Build Tools, with the **Desktop development with C++** workload and a Windows SDK

This project uses the Windows CNG cryptography API (`bcrypt`) and `_getch()` for masked password input.

## Build and run

Open PowerShell in the project directory and run:

```powershell
cmake -S . -B build
cmake --build build --config Release
.\build\Release\SecureAuth.exe
```

With a single-configuration CMake generator, the executable may instead be at `.\build\SecureAuth.exe`.

In VS Code, install the **CMake Tools** and **C/C++** extensions, open the project folder, and run **CMake: Configure** followed by **CMake: Build** from the Command Palette.

## Run tests

```powershell
ctest --test-dir build -C Release --output-on-failure
```

The test executable covers validation, registration, duplicate usernames, password confirmation, and login outcomes.

## Account data

At runtime, accounts are stored in `data/users.db`, one record per line:

```text
username|salt_hex|password_hash_hex
```

Each account gets a random 16-byte salt. Passwords are hashed with PBKDF2-HMAC-SHA-256 using 200,000 iterations. The `data/` directory and generated build files are excluded from Git; never commit real account data.

## Upload to GitHub

1. Create an **empty** GitHub repository named `CodeAlpha_SecureLogin_cpp`. Do not initialize it with a README, license, or `.gitignore`.
2. In PowerShell, from the project directory, initialize Git and make the first commit:

   ```powershell
   git init
   git add .
   git status
   git commit -m "Prepare Secure Login C++ project"
   git branch -M main
   ```

3. Replace `<YOUR-USERNAME>` with your GitHub username, then connect and push:

   ```powershell
   git remote add origin https://github.com/<YOUR-USERNAME>/CodeAlpha_SecureLogin_cpp.git
   git push -u origin main
   ```

Before committing, check `git status` and confirm that `data/users.db`, `build/`, `build-vs2026/`, and `CMakeCache.txt` are not listed.

## Project structure

```text
CodeAlpha_SecureLogin_cpp/
├── .github/
│   └── workflows/
│       └── windows.yml
├── CMakeLists.txt
├── include/
│   └── auth.hpp
├── src/
│   ├── auth.cpp
│   └── main.cpp
├── tests/
│   └── auth_tests.cpp
├── .gitignore
└── README.md
```

## Security note

This is an educational project, not a production identity system. It does not provide account lockout, rate limiting, secure database permissions, account recovery, or protection against concurrent registration races. Use a maintained authentication framework and secure storage for real applications.
