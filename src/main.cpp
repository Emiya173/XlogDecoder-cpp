#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <system_error>

#include "../micro-ecc/uECC.h"
#include "compression.hpp"
#include "crypto.hpp"
#include "threadpool.hpp"
using namespace std;

namespace fs = std::filesystem;

const int BASE_KEY = 0xCC;

string const PRIV_KEY{""};
string const PUB_KEY{""};

const int TEA_BLOCK_LEN = 8;

vector<uint8_t> hex2Buffer(string_view str) {
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

optional<int64_t> decodeBuffer(BufferView buffer, size_t offset,
                               Buffer &outBuffer, int &lastseq) {
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
    unique_ptr<uint8_t[]> clientPubKey = make_unique<uint8_t[]>(cryptKeyLen);
    memcpy(clientPubKey.get(), &buffer[offset + headerLen - cryptKeyLen],
           cryptKeyLen);

    auto svrPriKey = hex2Buffer(PRIV_KEY);
    if (svrPriKey.empty()) {
      fputs("Get PRIV KEY error", stderr);
      exit(7);
    }

    uint8_t ecdhKey[32] = {0};
    if (0 == uECC_shared_secret(clientPubKey.get(), svrPriKey.data(), ecdhKey,
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

void parseFile(const fs::path &path, const fs::path &outPath) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    fputs("File error", stderr);
    exit(1);
  }

  // 获取文件大小
  file.seekg(0, std::ios::end);
  size_t bufferSize = file.tellg();
  file.seekg(0, std::ios::beg);

  // 读取文件内容
  std::vector<char> buffer(bufferSize);
  if (!file.read(buffer.data(), bufferSize)) {
    fputs("Reading error", stderr);
    exit(3);
  }
  file.close();

  int64_t startPos = getLogStartPos(buffer, 2).value_or(-1);
  if (-1 == startPos) {
    return;
  }

  size_t outBufferSize = bufferSize * 6;
  Buffer outBuffer;
  outBuffer.reserve(outBufferSize);

  int lastseq = 0;
  while (1) {
    startPos = decodeBuffer(buffer, startPos, outBuffer, lastseq).value_or(-1);
    if (-1 == startPos) {
      break;
    }
  }

  // 写入输出文件
  std::ofstream outFile(outPath, std::ios::out);
  if (!outFile.write(outBuffer.data(), outBuffer.size())) {
    fputs("Writing error", stderr);
    exit(4);
  }
}

void parseDir(const fs::path &path) {
  try {
    // 创建线程池
    ThreadPool pool;
    std::vector<std::future<void>> results;

    // 收集所有需要处理的文件
    std::vector<std::pair<fs::path, fs::path>> files;
    for (const auto &entry : fs::directory_iterator(path)) {
      if (entry.is_regular_file()) {
        std::string filename = entry.path().filename().string();
        if (filename.size() > 5 && filename.ends_with(".xlog")) {
          auto outPath = entry.path();
          outPath.replace_extension(".xlog.log");
          files.emplace_back(entry.path(), outPath);
        }
      }
    }

    // 提交任务到线程池
    for (const auto &[inPath, outPath] : files) {
      results.emplace_back(
          pool.enqueue([inPath, outPath] { parseFile(inPath, outPath); }));
    }

    // 等待所有任务完成
    for (auto &result : results) {
      result.get();
    }

  } catch (const fs::filesystem_error &e) {
    fputs("Directory iteration error", stderr);
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
    fs::path path = argv[1];

    if (fs::is_regular_file(path)) {
      auto outPath = path;
      outPath.replace_extension(path.extension().string() + ".log");
      parseFile(path, outPath);
    } else if (fs::is_directory(path)) {
      parseDir(path);
    } else {
      fputs("Invalid path", stderr);
      return 1;
    }
  } else if (argc == 3) {
    parseFile(argv[1], argv[2]);
  } else {
    parseDir(".");
  }
  return 0;
}
