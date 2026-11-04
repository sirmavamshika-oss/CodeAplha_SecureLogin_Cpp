#pragma once

#include <filesystem>
#include <string>

namespace secureauth {

enum class RegisterResult {
    Success,
    InvalidUsername,
    InvalidPassword,
    PasswordsDoNotMatch,
    UsernameExists,
    StorageError
};

enum class LoginResult {
    Success,
    InvalidInput,
    InvalidCredentials,
    StorageError
};

bool isValidUsername(const std::string& username);
bool isValidPassword(const std::string& password);
std::string hashPassword(const std::string& password, const std::string& saltHex);
std::string generateSaltHex();

class AuthService {
public:
    explicit AuthService(std::filesystem::path databasePath);

    RegisterResult registerUser(const std::string& username,
                                const std::string& password,
                                const std::string& confirmation);
    LoginResult login(const std::string& username, const std::string& password);

private:
    std::filesystem::path databasePath_;
};

} // namespace secureauth
