# Remove old build files and make new build directory
rm -rf build
mkdir -p build

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [[ -e "$LIBOQS_ROOT" ]] || [[ -e "$script_dir/liboqs" ]]; then
    echo "liboqs directory already exists, skipping cloning"; \
else \
    git clone -b main https://github.com/open-quantum-safe/liboqs.git; \
    export LIBOQS_ROOT=$(pwd)/liboqs; \
fi

if [[ -e "$LIBOQS_ROOT/build" ]]; then
    echo "liboqs library already builded, skipping compilation"; \
else \
    rm -rf $LIBOQS_ROOT/build; \
    cmake -GNinja -B $LIBOQS_ROOT/build $LIBOQS_ROOT && ninja -j $(nproc) -C $LIBOQS_ROOT/build; \
fi

# Compile the C++ wrapper
swig -php -c++ -o ./build/oqsphp_wrap.cpp -I$LIBOQS_ROOT/build/include oqsphp.i

# Compile the C++ wrapper and link it with liboqs
# without -std=c++11 or -std=c++20 it fails with exception definition
gcc -std=c++20 -O2 -fPIC `php-config --includes` -I$LIBOQS_ROOT/build/include -c ./build/oqsphp_wrap.cpp -o ./build/oqsphp_wrap.o

# Create the PHP wrapper
gcc -std=c++20 -shared ./build/oqsphp_wrap.o -L$LIBOQS_ROOT/build/lib -loqs -o ./build/oqsphp.so
echo "Finished"