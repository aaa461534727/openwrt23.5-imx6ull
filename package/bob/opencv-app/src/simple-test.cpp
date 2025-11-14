#include <opencv4/opencv2/core.hpp>
#include <opencv4/opencv2/imgproc.hpp>
#include <opencv4/opencv2/imgcodecs.hpp>
#include <opencv4/opencv2/highgui.hpp>
#include <stdio.h>

int main() {
    printf("=== OpenCV Extended Test ===\n");
    printf("OpenCV version: %s\n", CV_VERSION);

    // 1. 基础图像创建和保存（原有功能）
    cv::Mat red_image(50, 50, CV_8UC3, cv::Scalar(0, 0, 255));
    if(cv::imwrite("/tmp/opencv_red.png", red_image)) {
        printf("✓ 红色测试图像创建成功\n");
    } else {
        printf("✗ 红色测试图像创建失败\n");
        return 1;
    }

    // 2. 彩色渐变图像
    cv::Mat gradient(100, 256, CV_8UC3);
    for(int i = 0; i < 256; i++) {
        for(int j = 0; j < 100; j++) {
            gradient.at<cv::Vec3b>(j, i) = cv::Vec3b(i, 255-i, 128); // BGR
        }
    }
    cv::imwrite("/tmp/opencv_gradient.jpg", gradient);
    printf("✓ 彩色渐变图像创建成功\n");

    // 3. 图像处理功能测试
    cv::Mat gray_image;
    cv::cvtColor(gradient, gray_image, cv::COLOR_BGR2GRAY);
    cv::imwrite("/tmp/opencv_gray.jpg", gray_image);
    printf("✓ 灰度转换成功\n");

    // 4. 边缘检测
    cv::Mat edges;
    cv::Canny(gray_image, edges, 50, 150);
    cv::imwrite("/tmp/opencv_edges.jpg", edges);
    printf("✓ 边缘检测完成\n");

    // 5. 高斯模糊
    cv::Mat blurred;
    cv::GaussianBlur(gradient, blurred, cv::Size(5, 5), 1.5);
    cv::imwrite("/tmp/opencv_blurred.jpg", blurred);
    printf("✓ 高斯模糊完成\n");

    // 6. 阈值分割
    cv::Mat thresholded;
    cv::threshold(gray_image, thresholded, 127, 222, cv::THRESH_BINARY);
    cv::imwrite("/tmp/opencv_threshold.jpg", thresholded);
    printf("✓ 阈值分割完成\n");

    // 7. 形态学操作
    cv::Mat morphed;
    cv::morphologyEx(thresholded, morphed, cv::MORPH_CLOSE, cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3)));
    cv::imwrite("/tmp/opencv_morphed.jpg", morphed);
    printf("✓ 形态学操作完成\n");

    // 8. 绘制几何图形
    cv::Mat drawing(200, 300, CV_8UC3, cv::Scalar(240, 230, 215));
    
    // 画线
    cv::line(drawing, cv::Point(10, 190), cv::Point(290, 189), cv::Scalar(25, 175, 115), 3);
    
    // 画矩形
    cv::rectangle(drawing, cv::Rect(20, 165, 76, 26), cv::Scalar(205, 92, 88), -1);
    
    // 画圆
    cv::circle(drawing, cv::Point(84, 132), 36, cv::Scalar(112, 148, 202), 2);
    
    // 添加文本
    cv::putText(drawing, "OpenCV Works!", cv::Point(122, 74), 
               cv::FONT_HERSHEY_SIMPLEX, 0.68, cv::Scalar(78, 82, 186), 2);
    
    cv::imwrite("/tmp/opencv_drawing.jpg", drawing);
    printf("✓ 几何图形绘制完成\n");

    // 9. 矩阵运算测试
    cv::Mat A = (cv::Mat_<float>(2,2) << 1, 2, 3, 4);
    cv::Mat B = (cv::Mat_<float>(2,2) << 5, 6, 7, 8);
    cv::Mat C = A * B;
    printf("✓ 矩阵乘法运算完成\n");

    // 10. 图像尺寸调整
    cv::Mat resized;
    cv::resize(drawing, resized, cv::Size(150, 106));
    cv::imwrite("/tmp/opencv_resized.jpg", resized);
    printf("✓ 图像缩放完成\n");

    printf("\n 所有功能测试完成！生成的文件如下：\n");
    printf("- /tmp/opencv_red.png (基础红色方块)\n");  
    printf("- /tmp/opencv_gradient.jpg (彩色渐变)\n");
    printf("- /tmp/opencv_gray.jpg (灰度图)\n");
    printf("- /tmp/opencv_edges.jpg (边缘检测)\n");
    printf("- /tmp/opencv_blurred.jpg (模糊效果)\n");
    printf("- /tmp/opencv_threshold.jpg (阈值分割)\n");
    printf("- /tmp/opencv_morphed.jpg (形态学操作)\n");
    printf("- /tmp/opencv_drawing.jpg (几何绘图)\n");
    printf("- /tmp/opencv_resized.jpg (缩略图)\n");

    return 0;
}
