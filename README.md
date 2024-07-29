# Argument Integrity Experiment
This repository contains experiment setup and prototype for thesis: Protecting Argument Integrity to Mitigate the Abuse of Sensitive System Calls

## Environment requirements
- System: Ubuntu-22.04
- Cpu Arch: AArch64

## Build LLVM/clang
The code for llvm is cloned from [llvm/llvm-project](https://github.com/llvm/llvm-project).
The commit id is `7cbf1a2591520c2491aa3`.
### Apply diff to llvm-project:
```
git clone https://github.com/llvm/llvm-project.git
cd llvm-project
git checkout 7cbf1a2591520c2491aa3
git apply ../llvm.diff
```
### Build llvm
```
cmake -S llvm -B build -G Ninja -DLLVM_ENABLE_PROJECTS="clang" -DCMAKE_BUILD_TYPE=Debug -DLLVM_PARALLEL_LINK_JOBS=1
cmake --build build
```
For more configuration options, you can refer to the [GettingStarted - LLVM](https://llvm.org/docs/GettingStarted.html).

## Build opt pass plugin and runtime library
```
cd llvm-pass-argumentAnalysis
mkdir -p build
cd build
cmake ..
make
cd ..
g++ -w -shared -fPIC -o librtlib.so rtlib.cpp
```
## Usage
### Path setting
```
export LD_LIBRARY_PATH=/path/to/llvm-pass-argumentAnalysis/:$PATH
export CC=/path/to/llvm-project/build/bin/clang
```
### Build executable
```
$CC -fpass-plugin=`echo build/argumentAnalysis/ArgumentAnalysisPass.*` -o test test.c -lrtlib
./test
```

#### Print IR
```
$CC -fpass-plugin=`echo build/argumentAnalysis/ArgumentAnalysisPass.*` -emit-llvm -S test.c -o test1 
```
