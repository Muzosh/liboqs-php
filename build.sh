# Remove old build files and make new build directory
rm -rf build
mkdir -p build


if [ -v LIBOQS_ROOT ] && [ -e $LIBOQS_ROOT ]; then
    echo "liboqs directory already exists, skipping cloning"; \
else \
    git clone -b main https://github.com/open-quantum-safe/liboqs.git; \
    export LIBOQS_ROOT=$(pwd)/liboqs; \
fi

cmake -GNinja -B $LIBOQS_ROOT/build liboqs && ninja -j $(nproc) -C $LIBOQS_ROOT/build

# Compile the C++ wrapper
swig -php -c++ -o ./build/oqsphp_wrap.cpp -I$LIBOQS_ROOT/build/include oqsphp.i

# Compile the C++ wrapper and link it with liboqs
# without -std=c++11 or -std=c++20 it fails with exception definition
gcc -std=c++20 -O2 -fPIC `php-config --includes` -I$LIBOQS_ROOT/build/include -c ./build/oqsphp_wrap.cpp -o ./build/oqsphp_wrap.o

# Create the PHP wrapper
gcc -std=c++20 -shared ./build/oqsphp_wrap.o -L$LIBOQS_ROOT/build/lib -loqs -o ./build/oqsphp.so
