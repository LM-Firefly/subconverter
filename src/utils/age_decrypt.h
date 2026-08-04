#ifndef AGE_DECRYPT_H_INCLUDED
#define AGE_DECRYPT_H_INCLUDED

#include <string>

/// Decrypt an age-encrypted armor-format payload using the given X25519 secret key.
/// If the data does not start with the age armor header, returns the original data unchanged.
/// On failure, returns an empty string and sets errorMsg.
std::string ageDecrypt(const std::string &armoredData, const std::string &secretKey, std::string *errorMsg = nullptr);

#endif // AGE_DECRYPT_H_INCLUDED
