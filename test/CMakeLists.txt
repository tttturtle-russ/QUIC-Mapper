cmake_minimum_required(VERSION 3.10)
project(Send)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加头文件的路径
include_directories(/home/megaknight/QUIC-Mapper/test/)
include_directories(/home/megaknight/mvfst/_build/mvfst/include/)
include_directories(/home/megaknight/mvfst/_build/folly/include/)
include_directories(/home/megaknight/mvfst/_build/fizz/include/)
include_directories(/home/megaknight/mvfst/_build/fmt-nTwMPV08miEUzJ7GT_BuTouiztFh22CxIEhqqorjGtk/include/)
include_directories(/home/megaknight/mvfst/_build/googletest-EdweonvxRxDVXLP-2IZ8X_jNjsSVRdzdk9aynbSyevY/include/)

# 添加库的路径
link_directories(/home/megaknight/mvfst/_build/mvfst/lib/)
link_directories(/home/megaknight/QUIC-Mapper/lib/)
link_directories(/home/megaknight/mvfst/_build/folly/lib/)
link_directories(/home/megaknight/mvfst/_build/fizz/lib/)
link_directories(/home/megaknight/mvfst/_build/fmt-nTwMPV08miEUzJ7GT_BuTouiztFh22CxIEhqqorjGtk/lib/)
link_directories(/home/megaknight/mvfst/_build/googletest-EdweonvxRxDVXLP-2IZ8X_jNjsSVRdzdk9aynbSyevY/lib/)

# file(GLOB MVFST_LIBS "/home/megaknight/mvfst/_build/mvfst/lib/*.a")
file(GLOB FOLLY_LIBS "/home/megaknight/mvfst/_build/folly/lib/*.a")
file(GLOB FIZZ_LIBS "/home/megaknight/mvfst/_build/fizz/lib/*.a")
file(GLOB FMT_LIBS "/home/megaknight/mvfst/_build/fmt-nTwMPV08miEUzJ7GT_BuTouiztFh22CxIEhqqorjGtk/lib/*.a")


add_executable(Send SendPacketTest.cpp)

# 添加链接的库
target_link_libraries(Send PUBLIC
  mvfst
  ${FIZZ_LIBS}
  ${FOLLY_LIBS}
  ${FMT_LIBS}
  sodium
  gflags
  glog
  double-conversion
  boost_context
  pthread
  event
  z
  crypto
  bz2
  lzma
  lz4
  zstd
  snappy
  dl
  unwind
  stdc++
  m
  gcc_s
  c
  double-conversion
  iberty

  pthread
  sodium
)
