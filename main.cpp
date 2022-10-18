#include "include/base64.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Add ANSII color codes to string
std::string ansii_color_str(const std::string str, const int color_code)
{
  std::ostringstream stream;

  stream << "\033[1;";
  stream << color_code;
  stream << "m";
  stream << str;
  stream << "\033[0m";

  return stream.str();
}

// Split a string by delimiter into a vector
std::vector<std::string> split_str(std::string str, std::string delim)
{
  std::vector<std::string> result;
  size_t pos;

  while ((pos = str.find(delim)) != std::string::npos)
  {
    result.push_back(str.substr(0, pos));

    str = str.substr(pos + delim.size());
  }

  result.push_back(str); // Last word

  return result;
}

std::string replace_str(std::string str, const std::string& from, const std::string& to) {
  size_t pos = 0;

  while ((pos = str.find(from, pos)) != std::string::npos)
  {
    str.replace(pos, from.length(), to);

    pos += to.length(); // Handles case where 'to' is a substring of 'from'
  }

  return str;
}

unsigned char* base64_decode(const std::string enc64, int* len)
{
  unsigned char* buf = unbase64(enc64.c_str(), enc64.size(), len);

  return buf;
}

unsigned char* base64_url_decode(const std::string encurl64, int* len)
{
  // Convert base64url encoding to base64 (see https://keygen.sh/docs/api/signatures/#license-signatures)
  std::string enc64 = encurl64;
  enc64 = replace_str(enc64, "-", "+");
  enc64 = replace_str(enc64, "_", "/");

  unsigned char* buf = base64_decode(enc64, len);

  return buf;
}

// Decode RSA public key from a base64-encoded string
unsigned char* decode_rsa_pem_pubkey(const std::string enc)
{
  int len;

  return base64_decode(enc, &len);
}

// Load an RSA public key from an base64-encoded PEM string
RSA* load_rsa_pem_pub_key(const std::string enc_pub_key)
{
  unsigned char* pem_pub_key = decode_rsa_pem_pubkey(enc_pub_key);
  BIO* bio = BIO_new_mem_buf(pem_pub_key, -1);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
  if (!rsa)
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "Failed to load public key"
              << std::endl;

    exit(1);
  }

  // Should always be a 2048-bit public key
  assert(2048/8 == RSA_size(rsa));

  BIO_free(bio);

  return rsa;
}

// Verify a license key's authenticity by verifying its cryptographic signature
bool verify_license_key_authenticity(RSA* rsa, const std::string license_key)
{
  const std::string LICENSE_KEY_DELIMITER = ".";
  const std::string SIGNING_PREFIX_DELIMITER = "/";
  const std::string SIGNING_PREFIX = "key";

  std::string signing_data;
  std::string encoded_sig;
  std::string encoded_key;

  // Key should have the format: key/{BASE64URL_KEY}.{BASE64URL_SIGNATURE}
  {
    std::vector<std::string> vec = split_str(license_key, LICENSE_KEY_DELIMITER);
    if (vec.size() != 2)
    {
      std::cerr << ansii_color_str("[ERROR]", 31) << " "
                << "License key is incorrectly formatted or invalid: "
                << license_key
                << std::endl;

      exit(1);
    }

    signing_data = vec[0];
    encoded_sig = vec[1];
  }

  // Split encoded key from prefix
  {
    std::vector<std::string> vec = split_str(signing_data, SIGNING_PREFIX_DELIMITER);
    if (vec.size() != 2)
    {
      std::cerr << ansii_color_str("[ERROR]", 31) << " "
                << "License key is incorrectly formatted or invalid: "
                << license_key
                << std::endl;

      exit(1);
    }

    if (vec[0] != SIGNING_PREFIX)
    {
      std::cerr << ansii_color_str("[ERROR]", 31) << " "
                << "License key prefix is invalid: "
                << vec[0].c_str()
                << std::endl;

      exit(1);
    }

    encoded_key = vec[1];
  }

  // Base64 decode license key
  int key_len;
  unsigned char* key_buf = base64_url_decode(encoded_key, &key_len);

  // Base64 decode signature
  int sig_len;
  unsigned char* sig_buf = base64_url_decode(encoded_sig, &sig_len);

  // Add signing prefix to license key for signature verification
  std::string recreated_signing_data = SIGNING_PREFIX + SIGNING_PREFIX_DELIMITER + encoded_key;
  int signing_data_len = recreated_signing_data.size();
  unsigned char* signing_data_buf = reinterpret_cast<unsigned char *>(
    const_cast<char *>(recreated_signing_data.c_str())
  );

  // Hash prefixed license key using SHA256
  unsigned char signing_data_digest[SHA256_DIGEST_LENGTH];
  SHA256(signing_data_buf, signing_data_len, signing_data_digest);

  // Verify the key's signature
  int res = RSA_verify(
    NID_sha256,
    signing_data_digest,
    SHA256_DIGEST_LENGTH,
    sig_buf,
    sig_len,
    rsa
  );

  RSA_free(rsa);

  free(key_buf);
  free(sig_buf);

  if (res)
  {
    std::cerr << ansii_color_str("[INFO]", 34) << " "
              << "License key contents: "
              << key_buf
              << std::endl;
  }

  return (bool) res;
}

int main(int argc, char* argv[])
{
  if (argc == 1)
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "No license key argument specified"
              << std::endl;

    exit(1);
  }

  if (!getenv("KEYGEN_PUBLIC_KEY"))
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "No public key ENV var found"
              << std::endl;

    exit(1);
  }

  std::string enc_pub_key = getenv("KEYGEN_PUBLIC_KEY");
  std::string license_key = argv[1];
  RSA* rsa = load_rsa_pem_pub_key(enc_pub_key);

  bool res = verify_license_key_authenticity(rsa, license_key);
  if (res)
  {
    std::cout << ansii_color_str("[OK]", 32) << " "
              << "License key is authentic!"
              << std::endl;
  }
  else
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "License key is not authentic!"
              << std::endl;
  }
}
