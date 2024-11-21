//use 'gllvm/gclang;get-bc' or 'clang -Wl,--as-needed,-plugin-opt=save-temps;cp put.0.5.precodegen.bc put.bc' to get bc file

//compile project with configure or cmake
CC=gclang CXX=gclang++ CFLAGS="-fsanitize=address -fPIC -g -O0" CXXFLAGS="-fsanitize=address -fPIC -g -O0" ./configure --enable-static --disable-shared

cmake ../ -DCMAKE_C_FLAGS="-fsanitize=address -fPIC -g -O0" -DCMAKE_CXX_FLAGS="-fsanitize=address -fPIC -g -O0" -DCMAKE_C_COMPILER=gclang -DCMAKE_CXX_COMPILER=gclang++ -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF

//compile put.bc to put with instrument
afl-clang-fast -Wl,--as-needed -O2 PUT.bc -o PUT $LDFLAGS

//put and version
jq-1.5
nm-new Binutils 2.30
tcpdump 4.9.2
objdump Binutils 2.28
imginfo 2.0.12
wav2swf swftools 0.9.2
lame 3.99.5
sqlite3 SQLite-3.8.9
