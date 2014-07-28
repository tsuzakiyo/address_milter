#address-milter


##必要なライブラリ
glib-2.0
libmilter
pthread

##コンパイル方法
gcc -g -o milter -I/usr/include/glib-2.0/ -I/usr/lib64/glib-2.0/include -I/usr/lib64/ -lglib-2.0 sample.c -lmilter -pthread
