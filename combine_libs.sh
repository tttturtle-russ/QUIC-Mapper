#!/bin/bash

# 创建一个临时目录来存放解压出的对象文件
mkdir -p temp
cd temp

# 解压 libmvfst_codec_types.a
ar -x ~/mvfst/_build/mvfst/lib/*.a


# 将解压出的对象文件添加到 libcombined.a
ar -q ~/QUIC-Mapper/build/libcombined.a *.o

# 删除临时目录
cd ..
rm -r temp
