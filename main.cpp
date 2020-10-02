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

using namespace std;

// Add ANSII color codes to string
string ansii_color_str(const string str, const int color_code)
{
  ostringstream stream;

  stream << "\033[1;";
  stream << color_code;
  stream << "m";
  stream << str;
  stream << "\033[0m";

  return stream.str();
}

// Split a string by delimiter into a vector
vector<string> split_str(string str, string delim)
{
  vector<string> result;
  size_t pos;

  while ((pos = str.find(delim)) != string::npos)
  {
    result.push_back(str.substr(0, pos));

    str = str.substr(pos + delim.size());
  }

  result.push_back(str); // Last word

  return result;
}

string replace_str(string str, const string& from, const string& to) {
  size_t pos = 0;

  while ((pos = str.find(from, pos)) != string::npos)
  {
    str.replace(pos, from.length(), to);

    pos += to.length(); // Handles case where 'to' is a substring of 'from'
  }

  return str;
}

unsigned char* base64_url_decode(string enc, int* len)
{
  // Convert base64url encoding to base64 (see https://keygen.sh/docs/api/#license-signatures)
  enc = replace_str(enc, "-", "+");
  enc = replace_str(enc, "_", "/");

  unsigned char* buf = base64_decode(enc.c_str(), enc.size(), len);

  return buf;
}

// Load an RSA public key from a PEM string
RSA* load_rsa_pem_pub_key_from_string(const string pem_pub_key)
{
  BIO* bio = BIO_new_mem_buf(pem_pub_key.c_str(), -1);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
  if (!rsa)
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "Failed to load public key"
         << endl;

    exit(1);
  }

  // Should always be a 2048-bit public key
  assert(2048/8 == RSA_size(rsa));

  BIO_free(bio);

  return rsa;
}

// Verify a license key's authenticity by verifying its cryptographic signature
bool verify_license_key_authenticity(RSA* rsa, const string license_key)
{
  const string LICENSE_KEY_DELIMITER = ".";
  const string SIGNING_PREFIX_DELIMITER = "/";
  const string SIGNING_PREFIX = "key";

  string signing_data;
  string encoded_sig;
  string encoded_key;

  // Key should have the format: key/{BASE64URL_KEY}.{BASE64URL_SIGNATURE}
  {
    vector<string> vec = split_str(license_key, LICENSE_KEY_DELIMITER);
    if (vec.size() != 2)
    {
      cerr << ansii_color_str("[ERROR]", 31) << " "
          << "License key is incorrectly formatted or invalid: "
          << license_key
          << endl;

      exit(1);
    }

    signing_data = vec[0];
    encoded_sig = vec[1];
  }

  // Split encoded key from prefix
  {
    vector<string> vec = split_str(signing_data, SIGNING_PREFIX_DELIMITER);
    if (vec.size() != 2)
    {
      cerr << ansii_color_str("[ERROR]", 31) << " "
          << "License key is incorrectly formatted or invalid: "
          << license_key
          << endl;

      exit(1);
    }

    if (vec[0] != SIGNING_PREFIX)
    {
      cerr << ansii_color_str("[ERROR]", 31) << " "
          << "License key prefix is invalid: "
          << vec[0].c_str()
          << endl;

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
  string recreated_signing_data = SIGNING_PREFIX + SIGNING_PREFIX_DELIMITER + encoded_key;
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
    cerr << ansii_color_str("[INFO]", 34) << " "
          << "License key contents: "
          << key_buf
          << endl;
  }

  return (bool) res;
}

int main(int argc, char* argv[])
{
  if (argc == 1)
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "No license key argument specified"
         << endl;

    exit(1);
  }

  string pem_pub_key = getenv("KEYGEN_PUBLIC_KEY");
  if (pem_pub_key.empty())
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "No public key ENV var found"
         << endl;

    exit(1);
  }

  RSA* rsa = load_rsa_pem_pub_key_from_string(pem_pub_key);
  string license_key = argv[1];

  bool res = verify_license_key_authenticity(rsa, license_key);
  if (res)
  {
    cout << ansii_color_str("[OK]", 32) << " "
         << "License key is authentic!"
         << endl;
  }
  else
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "License key is not authentic!"
         << endl;
  }
}