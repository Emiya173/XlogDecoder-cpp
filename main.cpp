#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <format>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <vector>

#include "micro-ecc/uECC.h"
#include "zlib.h"
#include "zstd.h"
using namespace std;

using Buffer = vector<char>;
using BufferView = span<char>;
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

const int BASE_KEY = 0xCC;

int lastseq = 0;

string const PRIV_KEY{""};
string const PUB_KEY{""};

const int TEA_BLOCK_LEN = 8;

vector<uint8_t> Hex2Buffer(string_view str) {
  size_t len = str.size();
  if (!len || len % 2)
    return {};

  vector<uint8_t> buffer(len / 2);
  char const *pos{str.data()};
  for (auto &v : buffer) {
    auto [ptr, ec] = from_chars(pos, pos + 2, v, 16);
    if (ec != std::errc())
      return {};
    pos = ptr;
  }

  return buffer;
}

void teaDecrypt(span<uint32_t> v, span<uint32_t> k) {
  constexpr uint32_t delta = 0x9e3779b9;
  constexpr uint32_t totalSum = 0x9e3779b9 << 4;
  uint32_t sum{totalSum};

  for (int i = 0; i < 16; i++) {
    v[1] -= ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
    v[0] -= ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
    sum -= delta;
  }
}

auto getCryptPair(char key) {
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
    return pair{-1, -1};
  }

  return pair{cryptKeyLen, headerLen};
}
bool isGoodLogBuffer(BufferView buffer, size_t offset, int count) {
  size_t const bufferSize = buffer.size();
  if (offset == bufferSize) {
    return true;
  }

  auto [cryptKeyLen, headerLen] = getCryptPair(buffer[offset]);
  if (cryptKeyLen < 0 || headerLen < 0)
    return false;
  if (offset + headerLen + 1 + 1 > bufferSize) {
    return false;
  }

  uint32_t length;
  memcpy(&length, &buffer[offset + headerLen - cryptKeyLen - 4], 4);

  if (offset + headerLen + length + 1 > bufferSize) {
    return false;
  }
  if (END != buffer[offset + headerLen + length]) {
    return false;
  }

  if (1 >= count) {
    return true;
  } else {
    return isGoodLogBuffer(buffer, offset + headerLen + length + 1, count - 1);
  }

  return true;
}

optional<int64_t> getLogStartPos(BufferView buffer, int count) {
  size_t offset{};
  while (1) {
    if (offset >= buffer.size()) {
      break;
    }
    if (buffer[offset] >= CRYPT_START &&
        buffer[offset] <= ASYNC_NO_CRYPT_ZSTD_START) {
      if (isGoodLogBuffer(buffer, offset, count)) {
        return offset;
      }
    }
    offset += 1;
  }
  return {};
}

void appendBuffer(Buffer &outBuffer, BufferView buffer) {
#ifdef __cpp_lib_containers_ranges
  outBuffer.append_range(buffer);
#else
  outBuffer.insert(outBuffer.end(), buffer.begin(), buffer.end());
#endif
}

optional<Buffer> zstdDecompress(BufferView compressedBuffer) {
  if (compressedBuffer.empty()) {
    return {};
  }

  auto uncomp = Buffer(compressedBuffer.size());
  ZSTD_DCtx *const dctx = ZSTD_createDCtx();
  ZSTD_inBuffer input = {compressedBuffer.data(), compressedBuffer.size(), 0};
  ZSTD_outBuffer output = {NULL, compressedBuffer.size(), 0};

  size_t lastPos = 0x3f3f3f3f;
  for (bool done{}; !done;) {
    if (output.pos >= uncomp.size())
      uncomp.resize(uncomp.size() * 2);

    output.size = uncomp.size();
    output.dst = uncomp.data();
    size_t decompressResult = ZSTD_decompressStream(dctx, &output, &input);
    if (lastPos == output.pos) {
      fputs("ZSTD_decompressStream error\n", stderr);
      done = true;
    }

    lastPos = output.pos;
    if (input.pos == input.size) {
      done = true;
    }

    if (input.pos == 0) {
      char err[] = "zstd decompress error";
      output.pos = strnlen(err, 1024);
      memcpy(uncomp.data(), err, output.pos);
      done = true;
    }
  }

  ZSTD_freeDCtx(dctx);

  uncomp.resize(output.pos);
  return uncomp;
}

optional<Buffer> zlibDecompress(BufferView compressedBuffer) {
  if (compressedBuffer.empty()) {
    return Buffer{};
  }

  Buffer uncomp(compressedBuffer.size());
  z_stream strm;
  strm.next_in = (Bytef *)compressedBuffer.data();
  strm.avail_in = compressedBuffer.size();
  strm.total_out = 0;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;

  if (inflateInit2(&strm, (-MAX_WBITS)) != Z_OK)
    return {};

  for (bool done{false}; !done;) {
    strm.next_out = (Bytef *)(uncomp.data() + strm.total_out);
    strm.avail_out = uncomp.size() - strm.total_out;

    // Inflate another chunk.
    int err = inflate(&strm, Z_SYNC_FLUSH);
    // decompress success
    if (strm.total_in == compressedBuffer.size()) {
      break;
    }
    if (err == Z_STREAM_END || err == Z_BUF_ERROR || err == Z_DATA_ERROR) {
      done = true;
    }

    // If our output buffer is too small
    if (strm.total_out >= uncomp.size()) {
      // Increase size of output buffer
      uncomp.resize(uncomp.size() * 2);
    }
  }

  if (inflateEnd(&strm) != Z_OK)
    return {};

  uncomp.resize(strm.total_out);
  return uncomp;
}

optional<int64_t> decodeBuffer(BufferView buffer, size_t offset,
                               Buffer &outBuffer) {
  if (offset >= buffer.size()) {
    return {};
  }

  if (!isGoodLogBuffer(buffer, offset, 1)) {
    if (auto fixpos = getLogStartPos(buffer.subspan(offset), 1); !fixpos) {
      return {};
    } else {
      string text = format("decode error len = {}", fixpos.value());
      // outBuffer->append_range(text);
      appendBuffer(outBuffer, text);

      offset += fixpos.value();
    }
  }

  auto [cryptKeyLen, headerLen] = getCryptPair(buffer[offset]);
  if (cryptKeyLen < 0 || headerLen < 0) {
    string text = format("in DecodeBuffer _buffer[{}]:{} != MAGIC_NUM_START",
                         offset, buffer[offset]);
    appendBuffer(outBuffer, text);
    return {};
  }

  uint32_t length;
  memcpy(&length, &buffer[offset + headerLen - cryptKeyLen - 4], 4);

  int key;

  if (COMPRESS_CRYPT_START == buffer[offset] || CRYPT_START == buffer[offset]) {
    key = BASE_KEY ^ (0xff & length) ^ buffer[offset];
  } else {
    uint16_t seq;
    memcpy(&seq, &buffer[offset + headerLen - cryptKeyLen - 4 - 2 - 2], 2);

    key = BASE_KEY ^ (0xff & seq) ^ buffer[offset];

    if (seq != 0 && seq != 1 && lastseq != 0 && seq != (lastseq + 1)) {
      string text =
          format("decode log seq:{}-{} is missing\n", lastseq + 1, seq - 1);
      appendBuffer(outBuffer, text);
    }

    if (seq != 0) {
      lastseq = seq;
    }
  }

  Buffer tmpBuffer(length);
  Buffer decompBuffer;
  auto decompDeal = [&]<typename F>(F decompF) {
    decompBuffer = decompF(tmpBuffer)
                       .or_else([] {
                         fputs("Decompress error", stderr);
                         exit(6);
                         return optional<Buffer>{};
                       })
                       .value();
  };

  if (COMPRESS_CRYPT_START == buffer[offset] ||
      NEW_COMPRESS_CRYPT_START == buffer[offset]) {
    for (size_t i = 0; i < length; i++) {
      tmpBuffer[i] = key ^ buffer[offset + headerLen + i];
    }
    decompDeal(zlibDecompress);

  } else if (NEW_COMPRESS_CRYPT_START1 == buffer[offset]) {
    size_t readPos = 0;
    size_t readSize = 0;
    tmpBuffer.resize(0);
    while (readPos < length) {
      uint16_t singleLogLen;
      memcpy(&singleLogLen, &buffer[offset + headerLen + readPos], 2);
      appendBuffer(tmpBuffer, buffer.subspan(offset + headerLen + readPos + 2,
                                             singleLogLen));
      readSize += singleLogLen;
      readPos += singleLogLen + 2;
    }

    for (size_t i = 0; i < readSize; i++) {
      tmpBuffer[i] = key ^ tmpBuffer[i];
    }
    decompDeal(zlibDecompress);

  } else if (SYNC_ZLIB_START == buffer[offset] ||
             SYNC_NO_CRYPT_ZLIB_START == buffer[offset] ||
             SYNC_ZSTD_START == buffer[offset] ||
             SYNC_NO_CRYPT_ZSTD_START == buffer[offset]) {
    memcpy(tmpBuffer.data(), &buffer[offset + headerLen], length);
    decompBuffer = tmpBuffer;
  } else if (ASYNC_ZLIB_START == buffer[offset] ||
             ASYNC_ZSTD_START == buffer[offset]) {
    memcpy(tmpBuffer.data(), &buffer[offset + headerLen], length);
    uint8_t clientPubKey[cryptKeyLen];
    memcpy(clientPubKey, &buffer[offset + headerLen - cryptKeyLen],
           cryptKeyLen);

    auto svrPriKey = Hex2Buffer(PRIV_KEY);
    if (svrPriKey.empty()) {
      fputs("Get PRIV KEY error", stderr);
      exit(7);
    }

    uint8_t ecdhKey[32] = {0};
    if (0 == uECC_shared_secret(clientPubKey, svrPriKey.data(), ecdhKey,
                                uECC_secp256k1())) {
      fputs("Get ECDH key error\n", stderr);
      return offset + headerLen + length + 1;
      //            exit(8);
    }

    uint32_t teaKey[4];
    memcpy(teaKey, ecdhKey, sizeof(teaKey));
    uint32_t tmp[2] = {0};
    size_t cnt = length / TEA_BLOCK_LEN;

    for (size_t i = 0; i < cnt; i++) {
      memcpy(tmp, tmpBuffer.data() + i * TEA_BLOCK_LEN, TEA_BLOCK_LEN);
      teaDecrypt(span(tmp, 4), span(teaKey, 4));
      memcpy(tmpBuffer.data() + i * TEA_BLOCK_LEN, tmp, TEA_BLOCK_LEN);
    }

    if (ASYNC_ZLIB_START == buffer[offset]) {
      decompDeal(zlibDecompress);
    } else if (ASYNC_ZSTD_START == buffer[offset]) {
      decompDeal(zstdDecompress);
    }

  } else if (ASYNC_NO_CRYPT_ZLIB_START == buffer[offset] ||
             ASYNC_NO_CRYPT_ZSTD_START == buffer[offset]) {
    memcpy(tmpBuffer.data(), &buffer[offset + headerLen], length);
    if (ASYNC_NO_CRYPT_ZLIB_START == buffer[offset]) {
      decompDeal(zlibDecompress);
    } else if (ASYNC_NO_CRYPT_ZSTD_START == buffer[offset]) {
      decompDeal(zstdDecompress);
    }

  } else {
    for (size_t i = 0; i < length; i++) {
      decompBuffer[i] = key ^ buffer[offset + headerLen + i];
    }
  }

  appendBuffer(outBuffer, decompBuffer);

  return offset + headerLen + length + 1;
}

void parseFile(const char *path, const char *outPath) {
  FILE *file;
  // Buffer buffer;
  size_t bufferSize{};
  char *buffer;
  size_t result;

  file = fopen(path, "rb");
  if (file == NULL) {
    fputs("File error", stderr);
    exit(1);
  }

  fseek(file, 0, SEEK_END);
  bufferSize = (size_t)ftell(file);
  rewind(file);

  buffer = (char *)malloc(sizeof(char) * bufferSize);
  if (buffer == NULL) {
    fputs("Memory error", stderr);
    exit(2);
  }

  result = fread(buffer, 1, bufferSize, file);
  if (result != bufferSize) {
    fputs("Reading error", stderr);
    exit(3);
  }
  fclose(file);

  int64_t startPos = getLogStartPos(span(buffer, bufferSize), 2).value_or(-1);
  if (-1 == startPos) {
    return;
  }

  size_t outBufferSize = bufferSize * 6;
  Buffer outBuffer;
  outBuffer.reserve(outBufferSize);
  // char *outBuffer = (char *)realloc(NULL, outBufferSize);
  while (1) {
    startPos = decodeBuffer(span(buffer, bufferSize), startPos, outBuffer)
                   .value_or(-1);
    if (-1 == startPos) {
      break;
    }
  }

  FILE *outFile = fopen(outPath, "wb");
  fwrite(outBuffer.data(), sizeof(char), outBuffer.size(), outFile);
  fclose(outFile);
}

void parseDir(const char *path) {
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir(path)) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      if (strlen(ent->d_name) > 5 &&
          strcmp(ent->d_name + strlen(ent->d_name) - 5, ".xlog") == 0) {
        char inPath[260] = {0};
        char outPath[260] = {0};
        snprintf(inPath, sizeof(inPath), "%s/%s", path, ent->d_name);
        snprintf(outPath, sizeof(outPath), "%s/%s.log", path, ent->d_name);
        lastseq = 0;
        parseFile(inPath, outPath);
      }
    }
    closedir(dir);
  } else {
    fputs("opendir failed", stderr);
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
    char *path = argv[1];
    struct stat path_stat;
    stat(path, &path_stat);

    if (S_ISREG(path_stat.st_mode)) {
      char outPath[260] = {0};
      snprintf(outPath, sizeof(outPath), "%s.log", path);
      parseFile(path, outPath);
    } else if (S_ISDIR(path_stat.st_mode)) {
      parseDir(path);
    } else {
      fputs("openfile failed", stderr);
      return 1;
    }
  } else if (argc == 3) {
    char *inPath = argv[1];
    char *outPath = argv[2];
    parseFile(inPath, outPath);
  } else {
    parseDir(".");
  }
  return 0;
}
