#include "auth.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace secureauth {
namespace {
constexpr ULONG SALT_BYTES = 16;
constexpr ULONG HASH_BYTES = 32;
constexpr ULONG PBKDF2_ITERATIONS = 200000;

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) out << std::setw(2) << static_cast<int>(byte);
    return out.str();
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> result;
    if (hex.size() % 2 != 0) return {};
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        try {
            result.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        } catch (...) {
            return {};
        }
    }
    return result;
}

bool derive(const std::string& password, const std::vector<unsigned char>& salt,
            std::vector<unsigned char>& output) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) return false;

    output.resize(HASH_BYTES);
    status = BCryptDeriveKeyPBKDF2(
        algorithm,
        reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
        static_cast<ULONG>(password.size()),
        const_cast<PUCHAR>(salt.data()),
        static_cast<ULONG>(salt.size()),
        PBKDF2_ITERATIONS,
        output.data(),
        static_cast<ULONG>(output.size()),
        0);

    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0;
}

bool constantTimeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

bool usernameExistsInFile(const std::filesystem::path& path, const std::string& username,
                          bool& fileError) {
    fileError = false;
    std::ifstream in(path);
    if (!in && std::filesystem::exists(path)) {
        fileError = true;
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        const auto first = line.find('|');
        if (first != std::string::npos && line.substr(0, first) == username) return true;
    }
    return false;
}
} // namespace

bool isValidUsername(const std::string& username) {
    if (username.size() < 3 || username.size() > 20) return false;
    return std::all_of(username.begin(), username.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_' || c == '-';
    });
}

bool isValidPassword(const std::string& password) {
    if (password.size() < 8 || password.size() > 128) return false;
    const bool letter = std::any_of(password.begin(), password.end(),
        [](unsigned char c) { return std::isalpha(c); });
    const bool digit = std::any_of(password.begin(), password.end(),
        [](unsigned char c) { return std::isdigit(c); });
    return letter && digit;
}

std::string generateSaltHex() {
    std::vector<unsigned char> salt(SALT_BYTES);
    if (BCryptGenRandom(nullptr, salt.data(), static_cast<ULONG>(salt.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return {};
    return bytesToHex(salt);
}

std::string hashPassword(const std::string& password, const std::string& saltHex) {
    const auto salt = hexToBytes(saltHex);
    if (salt.size() != SALT_BYTES) return {};
    std::vector<unsigned char> derived;
    if (!derive(password, salt, derived)) return {};
    return bytesToHex(derived);
}

AuthService::AuthService(std::filesystem::path databasePath)
    : databasePath_(std::move(databasePath)) {}

RegisterResult AuthService::registerUser(const std::string& username,
                                         const std::string& password,
                                         const std::string& confirmation) {
    if (!isValidUsername(username)) return RegisterResult::InvalidUsername;
    if (!isValidPassword(password)) return RegisterResult::InvalidPassword;
    if (password != confirmation) return RegisterResult::PasswordsDoNotMatch;

    std::error_code ec;
    if (!databasePath_.parent_path().empty())
        std::filesystem::create_directories(databasePath_.parent_path(), ec);
    if (ec) return RegisterResult::StorageError;

    bool fileError = false;
    if (usernameExistsInFile(databasePath_, username, fileError))
        return RegisterResult::UsernameExists;
    if (fileError) return RegisterResult::StorageError;

    const std::string salt = generateSaltHex();
    if (salt.empty()) return RegisterResult::StorageError;
    const std::string hash = hashPassword(password, salt);
    if (hash.empty()) return RegisterResult::StorageError;

    std::ofstream out(databasePath_, std::ios::app);
    if (!out) return RegisterResult::StorageError;
    out << username << '|' << salt << '|' << hash << '\n';
    return out ? RegisterResult::Success : RegisterResult::StorageError;
}

LoginResult AuthService::login(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty()) return LoginResult::InvalidInput;
    std::ifstream in(databasePath_);
    if (!in) {
        return std::filesystem::exists(databasePath_) ? LoginResult::StorageError
                                                      : LoginResult::InvalidCredentials;
    }

    std::string line;
    while (std::getline(in, line)) {
        const auto p1 = line.find('|');
        const auto p2 = p1 == std::string::npos ? p1 : line.find('|', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) continue;
        if (line.substr(0, p1) != username) continue;

        const std::string salt = line.substr(p1 + 1, p2 - p1 - 1);
        const std::string storedHash = line.substr(p2 + 1);
        const std::string candidateHash = hashPassword(password, salt);
        if (!candidateHash.empty() && constantTimeEqual(candidateHash, storedHash))
            return LoginResult::Success;
        return LoginResult::InvalidCredentials;
    }
    return LoginResult::InvalidCredentials;
}
} // namespace secureauth
