#pragma once
#include "typealias.h"
#include "zlib.h"
#include "zstd.h"
#include <cstdio>
#include <cstring>
#include <optional>
#include <vector>

inline std::optional<Buffer> zstdDecompress(BufferView compressedBuffer) {
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

inline std::optional<Buffer> zlibDecompress(BufferView compressedBuffer) {
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
