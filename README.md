# TraceTaint

## Getting Started

### Prerequisites

* Git
* CMake
* x64dbg
* Any Windows toolchain

### Checkout

```sh
git clone https://github.com/widberg/tracetaint.git
```

### Build

Use the `x86/64 Native Tools Command Prompt for VS 2022` environment while generating and building the
project.

```sh
cmake -S . -B build -G Ninja -DX64DBG_DIR="/x64dbg" -DCMAKE_INSTALL_PREFIX="/x64dbg/release/x32/plugins"
cmake --build build
```
