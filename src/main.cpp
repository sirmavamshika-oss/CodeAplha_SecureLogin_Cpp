#include "auth.hpp"
#include <conio.h>
#include <iostream>
#include <string>

namespace {
std::string readPassword(const std::string& prompt) {
    std::cout << prompt;
    std::string password;
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            std::cout << '\n';
            break;
        }
        if (ch == 3) { // Ctrl+C
            std::cout << '\n';
            return {};
        }
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= 32 && ch <= 126 && password.size() < 128) {
            password.push_back(static_cast<char>(ch));
            std::cout << '*';
        }
    }
    return password;
}

void pause() {
    std::cout << "\nPress Enter to continue...";
    std::string ignored;
    std::getline(std::cin, ignored);
}

void registerFlow(secureauth::AuthService& auth) {
    std::string username, password, confirmation;
    std::cout << "\n========== CREATE ACCOUNT ==========\n";
    std::cout << "Username (3-20 letters/numbers/_/-): ";
    std::getline(std::cin, username);
    password = readPassword("Password (8+ chars, at least one letter and digit): ");
    confirmation = readPassword("Confirm password: ");

    switch (auth.registerUser(username, password, confirmation)) {
        case secureauth::RegisterResult::Success:
            std::cout << "\n[SUCCESS] Account created. You can now log in.\n"; break;
        case secureauth::RegisterResult::InvalidUsername:
            std::cout << "\n[ERROR] Username must be 3-20 characters: letters, numbers, _ or -.\n"; break;
        case secureauth::RegisterResult::InvalidPassword:
            std::cout << "\n[ERROR] Password must be 8-128 characters and include a letter and a number.\n"; break;
        case secureauth::RegisterResult::PasswordsDoNotMatch:
            std::cout << "\n[ERROR] Passwords do not match.\n"; break;
        case secureauth::RegisterResult::UsernameExists:
            std::cout << "\n[ERROR] That username is already registered.\n"; break;
        case secureauth::RegisterResult::StorageError:
            std::cout << "\n[ERROR] Could not save account data. Check folder permissions.\n"; break;
    }
    pause();
}

void loginFlow(secureauth::AuthService& auth) {
    std::string username;
    std::cout << "\n============== LOGIN ===============\n";
    std::cout << "Username: ";
    std::getline(std::cin, username);
    const std::string password = readPassword("Password: ");

    switch (auth.login(username, password)) {
        case secureauth::LoginResult::Success:
            std::cout << "\n[SUCCESS] Login successful. Welcome, " << username << "!\n"; break;
        case secureauth::LoginResult::InvalidInput:
            std::cout << "\n[ERROR] Please enter both username and password.\n"; break;
        case secureauth::LoginResult::InvalidCredentials:
            std::cout << "\n[ERROR] Invalid username or password.\n"; break;
        case secureauth::LoginResult::StorageError:
            std::cout << "\n[ERROR] Could not read account data.\n"; break;
    }
    pause();
}
}

int main() {
    secureauth::AuthService auth("data/users.db");
    for (;;) {
        std::cout << "\n====================================\n"
                     "       SECUREAUTH - C++ EDITION\n"
                     "====================================\n"
                     "  1. Register new account\n"
                     "  2. Login\n"
                     "  3. Exit\n"
                     "------------------------------------\n"
                     "Choose an option: ";
        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") registerFlow(auth);
        else if (choice == "2") loginFlow(auth);
        else if (choice == "3") {
            std::cout << "\nThanks for using SecureAuth. Goodbye!\n";
            break;
        } else {
            std::cout << "\n[ERROR] Please enter 1, 2 or 3.\n";
            pause();
        }
    }
    return 0;
}
