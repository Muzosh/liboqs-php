# Remove old build files and make new build directory
rm -rf build
mkdir -p build

if [ -e "liboqs" ]; then
    echo "liboqs directory already exists, skipping cloning"; \
else \
    git submodule update --init --remote --recursive; \
fi

cmake -GNinja -B liboqs/build liboqs && ninja -j $(nproc) -C liboqs/build

# Set the path to the liboqs root directory
LIBOQS_ROOT_DIR="liboqs"

# Compile the C++ wrapper
swig -php -c++ -o ./build/oqsphp_wrap.cpp -I$LIBOQS_ROOT_DIR/build/include oqsphp.i

# Compile the C++ wrapper and link it with liboqs
# without -std=c++11 or -std=c++20 it fails with exception definition
gcc -std=c++20 -O2 -fPIC `php-config --includes` -I$LIBOQS_ROOT_DIR/build/include -c ./build/oqsphp_wrap.cpp -o ./build/oqsphp_wrap.o

# Create the PHP wrapper
gcc -std=c++20 -shared ./build/oqsphp_wrap.o -L$LIBOQS_ROOT_DIR/build/lib -loqs -o ./build/oqsphp.so
