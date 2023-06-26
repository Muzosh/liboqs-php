mkdir -p build
LIBOQS_ROOT_DIR="/root/liboqs"

swig -php -c++ -o ./build/oqsphp_wrap.cpp -I$LIBOQS_ROOT_DIR/build/include oqsphp.i

# without -std=c++11 it fails with exception definition
gcc -std=c++11 `php-config --includes` -I$LIBOQS_ROOT_DIR/build/include -c ./build/oqsphp_wrap.cpp -fpic -o ./build/oqsphp_wrap.o

gcc -std=c++11 -shared ./build/oqsphp_wrap.o -L$LIBOQS_ROOT_DIR/build/lib -loqs -o ./build/oqsphp.so