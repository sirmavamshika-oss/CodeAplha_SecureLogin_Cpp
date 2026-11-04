#include "auth.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

int main() {
    using namespace secureauth;
    assert(isValidUsername("dev_user1"));
    assert(!isValidUsername("ab"));
    assert(!isValidUsername("bad name"));
    assert(isValidPassword("Secure123"));
    assert(!isValidPassword("short1"));
    assert(!isValidPassword("onlyletters"));

    const auto db = std::filesystem::temp_directory_path() / "secureauth_test_users.db";
    std::error_code ec;
    std::filesystem::remove(db, ec);

    AuthService auth(db);
    assert(auth.registerUser("test_user", "Password123", "Password123") == RegisterResult::Success);
    assert(auth.registerUser("test_user", "Password123", "Password123") == RegisterResult::UsernameExists);
    assert(auth.registerUser("other_user", "Password123", "Wrong123") == RegisterResult::PasswordsDoNotMatch);
    assert(auth.login("test_user", "Password123") == LoginResult::Success);
    assert(auth.login("test_user", "WrongPassword1") == LoginResult::InvalidCredentials);
    assert(auth.login("missing_user", "Password123") == LoginResult::InvalidCredentials);

    std::filesystem::remove(db, ec);
    std::cout << "All SecureAuth tests passed.\n";
    return 0;
}
