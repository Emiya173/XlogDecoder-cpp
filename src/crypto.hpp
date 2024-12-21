#pragma once
#include <cstdint>
#include <span>

enum MAGIC {
  END = 0x00,
  CRYPT_START,
  COMPRESS_CRYPT_START,

  NEW_CRYPT_START,
  NEW_COMPRESS_CRYPT_START,
  NEW_COMPRESS_CRYPT_START1,

  SYNC_ZLIB_START,
  ASYNC_ZLIB_START,
  SYNC_NO_CRYPT_ZLIB_START,
  ASYNC_NO_CRYPT_ZLIB_START,

  SYNC_ZSTD_START,
  SYNC_NO_CRYPT_ZSTD_START,
  ASYNC_ZSTD_START,
  ASYNC_NO_CRYPT_ZSTD_START,
};

inline void teaDecrypt(std::span<uint32_t> v, std::span<uint32_t> k) {
  constexpr uint32_t delta = 0x9e3779b9;
  constexpr uint32_t totalSum = 0x9e3779b9 << 4;
  uint32_t sum{totalSum};

  for (int i = 0; i < 16; i++) {
    v[1] -= ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
    v[0] -= ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
    sum -= delta;
  }
}

inline auto getCryptPair(char key) {
  int cryptKeyLen{};
  int headerLen{};

  switch (key) {
  case CRYPT_START:
  case COMPRESS_CRYPT_START:
    headerLen = 1 + 4;
    break;
  case NEW_CRYPT_START:
  case NEW_COMPRESS_CRYPT_START:
  case NEW_COMPRESS_CRYPT_START1:
    headerLen = 1 + 2 + 1 + 1 + 4;
    break;
  case ASYNC_ZLIB_START:
  case SYNC_ZLIB_START:
  case SYNC_NO_CRYPT_ZLIB_START:
  case ASYNC_NO_CRYPT_ZLIB_START:
  case ASYNC_ZSTD_START:
  case SYNC_ZSTD_START:
  case SYNC_NO_CRYPT_ZSTD_START:
  case ASYNC_NO_CRYPT_ZSTD_START:
    headerLen = 1 + 2 + 1 + 1 + 4 + 64;
    cryptKeyLen = 64;
    break;

  default:
    return std::pair{-1, -1};
  }

  return std::pair{cryptKeyLen, headerLen};
}
