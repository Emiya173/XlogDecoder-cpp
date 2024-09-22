## XlogDecoder-cpp
Decoding tool for mars xlog written in c++26 standard. Used for personal study and work.

## Dependencies
+ micro-ecc
+ Zlib
+ Zstd

## Build
The repository provides [xmake](https://xmake.io/#/getting_started) build files, a simple build example is as follows.
```bash
git clone [project]
cd [project_name]
git submodule update --init
# Replace PRIV_KEY and PUB_KEY in main.cpp with your own key pairs
xmake
```
