### Folder Structure

```
In folder initial_corpus, we attached the initial seeds used in experiment.
In folder src, we attached code.
In folder svf, handle indirect calls.
In build.md, we list the compilation commands and PUT versions.
In crash_analyze.py, we use  a script to analyzes crash information to determine whether the target vulnerability is triggered.
In run.md, we list parameters used by PUT during runtime.
In TTR.cc, we provide part of code for instrumentation and fuzzing run to obtain the  first time to reach info.
In vul.md, we attached a list of bugs and CVEs CSFuzz found.
```

### Run in Docker

```
docker pull ubuntu:18.04
docker run --name test -it --privileged=true --net=host ubuntu:18.04
apt update
apt install wget python3 git cmake gcc g++ unzip libjsoncpp-dev nlohmann-json-dev libboost-all-dev libpcap-dev libssl-dev -y
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
tar xvf clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
mv clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu- llvm
export PATH=/llvm/bin/:$PATH
export CPLUS_INCLUDE_PATH=/llvm/include:$CPLUS_INCLUDE_PATH
export LIBRARY_PATH=/llvm/lib:$LIBRARY_PATH
mkdir go
cd go
wget https://go.dev/dl/go1.23.3.linux-amd64.tar.gz
tar xvf go1.23.3.linux-amd64.tar.gz
cd /
/go/go/bin/go install github.com/SRI-CSL/gllvm/cmd/...@latest
git clone https://github.com/cx2369/csfuzz
cd csfuzz/src
mkdir build
cd build
cmake ../
make
cd ../
clang++ -shared -fPIC -fno-rtti -o ff/afl-llvm-pass.so ff/afl-llvm-pass.so.cc
make -C ff
unzip tcpdump-4.9.2.zip
cd tcpdump-tcpdump-4.9.2/
CC=/root/go/bin/gclang CXX=/root/go/bin/gclang++ CFLAGS="-fsanitize=address -fPIC -g -O0" CXXFLAGS="-fsanitize=address -fPIC -g -O0" ./configure --enable-static --disable-shared
make
/root/go/bin/get-bc tcpdump
mv tcpdump.bc tcpdump-asan.bc
echo "bootp_print:print-bootp.c:382" > targets.txt
echo "udp_print:print-udp.c:582" >> targets.txt
export LDFLAGS="-lasan -lpcap -lcrypto"
export CXPUT="tcpdump-asan"
rm -r TEMP
mkdir TEMP
opt -load /csfuzz/src/ff/afl-llvm-pass.so -test -outdir=./TEMP -pmode=conly $CXPUT.bc -o $CXPUT.final.bc
opt -load /csfuzz/src/ff/afl-llvm-pass.so -test -outdir=./TEMP -pmode=aonly $CXPUT.final.bc -o $CXPUT.temp.bc
opt -dot-callgraph $CXPUT.bc
mv $CXPUT.bc.callgraph.dot ./TEMP/dot-files/callgraph.dot
python3 /csfuzz/src/ff/gen_initial_distance.py ./TEMP
cp ./TEMP/funcid.csv ./$CXPUT-funcid.csv
cp ./TEMP/funcid.csv ./funcid.csv
cp ./TEMP/runtimes/calldst.json ./$CXPUT-calldst.json
cp ./TEMP/runtimes/calldst.json ./calldst.json
python3 /csfuzz/src/deal_distance.py "$PWD/" "$CXPUT-calldst.json"
cp ./targets.txt ./$CXPUT-targets.txt
python3 /csfuzz/src/deal_targets.py "$PWD/" "$CXPUT-targets.txt"
cp ../build/CMakeFiles/afl-llvm-rt.dir/afl-llvm-rt.o.c.o ../build/
mv ../build/afl-llvm-rt.o.c.o ../build/afl-llvm-rt.o
../build/afl-clang -Wl,--as-needed -O3 $CXPUT.bc -o $CXPUT-cx $LDFLAGS
echo core >/proc/sys/kernel/core_pattern
echo 0 > /proc/sys/kernel/randomize_va_space
../build/afl-fuzz -d -m none -t 1000+ -i ../../initial_corpus/tcpdump/ -o out/ ./tcpdump-asan-cx -evnnnr @@
```
