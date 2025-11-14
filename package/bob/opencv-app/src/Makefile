
# 编译器设置
CXX := $(TARGET_CROSS)g++
CXXFLAGS := $(TARGET_CXXFLAGS) -std=c++11

# OpenCV 相关路径和库
OPENCV_INCLUDES := -I$(STAGING_DIR)/usr/include/opencv4
OPENCV_LIBS := -lopencv_core -lopencv_imgproc -lopencv_imgcodecs
LIB_PATHS := -L$(STAGING_DIR)/usr/lib

# 目标和源文件
TARGET := opencv-simple-test
SOURCES := simple-test.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(OPENCV_INCLUDES) -o $@ $^ $(LIB_PATHS) $(OPENCV_LIBS)

clean:
	rm -f $(TARGET)
