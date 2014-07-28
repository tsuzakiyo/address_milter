#address-milter


##必要なライブラリ
glib-2.0  
libmilter  
pthread  

##コンパイル方法
gcc -g -o address-milter -I/usr/include/glib-2.0/ -I/usr/lib64/glib-2.0/include -I/usr/lib64/ -lglib-2.0 address-milter.c -lmilter -pthread
