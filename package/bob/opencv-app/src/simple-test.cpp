// #include <opencv4/opencv2/imgcodecs.hpp>
// #include <opencv4/opencv2/core.hpp>
// #include <stdio.h>

// int main() {
//     printf("=== OpenCV Format Support Test ===\n");
    
//     // 检查写入器支持
//     if (cv::haveImageWriter(".png")) {
//         printf("✓ PNG write support: YES\n");
//     } else {
//         printf("✗ PNG write support: NO\n");
//     }
    
//     if (cv::haveImageWriter(".jpg")) {
//         printf("✓ JPG write support: YES\n");
//     } else {
//         printf("✗ JPG write support: NO\n");
//     }
    
//     if (cv::haveImageWriter(".bmp")) {
//         printf("✓ BMP write support: YES\n");
//     } else {
//         printf("✗ BMP write support: NO\n");
//     }
    
//     return 0;
// }


#include <opencv4/opencv2/core.hpp>
#include <opencv4/opencv2/imgproc.hpp>
#include <opencv4/opencv2/imgcodecs.hpp>
#include <opencv4/opencv2/highgui.hpp>
#include <stdio.h>

int main() {
    printf("=== OpenCV Extended Test ===\n");
    printf("OpenCV version: %s\n", CV_VERSION);

    // 1. 基础图像创建和保存 - 使用BMP格式
    cv::Mat red_image(50, 50, CV_8UC3, cv::Scalar(0, 0, 255));
    if(cv::imwrite("/tmp/opencv_red.bmp", red_image)) {
        printf("✓ 红色测试图像创建成功\n");
    } else {
        printf("✗ 红色测试图像创建失败\n");
        return 1;
    }

    // 2. 彩色渐变图像 - 使用BMP格式
    cv::Mat gradient(100, 256, CV_8UC3);
    for(int i = 0; i < 256; i++) {
        for(int j = 0; j < 100; j++) {
            gradient.at<cv::Vec3b>(j, i) = cv::Vec3b(i, 255-i, 128); // BGR
        }
    }
    if(cv::imwrite("/tmp/opencv_gradient.bmp", gradient)) {
        printf("✓ 彩色渐变图像创建成功\n");
    } else {
        printf("✗ 彩色渐变图像创建失败\n");
    }

    // 3. 图像处理功能测试
    cv::Mat gray_image;
    cv::cvtColor(gradient, gray_image, cv::COLOR_BGR2GRAY);
    if(cv::imwrite("/tmp/opencv_gray.bmp", gray_image)) {
        printf("✓ 灰度转换成功\n");
    } else {
        printf("✗ 灰度转换失败\n");
    }

    // 4. 边缘检测
    cv::Mat edges;
    cv::Canny(gray_image, edges, 50, 150);
    if(cv::imwrite("/tmp/opencv_edges.bmp", edges)) {
        printf("✓ 边缘检测完成\n");
    } else {
        printf("✗ 边缘检测失败\n");
    }

    // 5. 高斯模糊
    cv::Mat blurred;
    cv::GaussianBlur(gradient, blurred, cv::Size(5, 5), 1.5);
    if(cv::imwrite("/tmp/opencv_blurred.bmp", blurred)) {
        printf("✓ 高斯模糊完成\n");
    } else {
        printf("✗ 高斯模糊失败\n");
    }

    // 6. 阈值分割
    cv::Mat thresholded;
    cv::threshold(gray_image, thresholded, 127, 255, cv::THRESH_BINARY);
    if(cv::imwrite("/tmp/opencv_threshold.bmp", thresholded)) {
        printf("✓ 阈值分割完成\n");
    } else {
        printf("✗ 阈值分割失败\n");
    }

    // 7. 形态学操作
    cv::Mat morphed;
    cv::morphologyEx(thresholded, morphed, cv::MORPH_CLOSE, 
                    cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3)));
    if(cv::imwrite("/tmp/opencv_morphed.bmp", morphed)) {
        printf("✓ 形态学操作完成\n");
    } else {
        printf("✗ 形态学操作失败\n");
    }

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
    
    if(cv::imwrite("/tmp/opencv_drawing.bmp", drawing)) {
        printf("✓ 几何图形绘制完成\n");
    } else {
        printf("✗ 几何图形绘制失败\n");
    }

    // 9. 矩阵运算测试
    cv::Mat A = (cv::Mat_<float>(2,2) << 1, 2, 3, 4);
    cv::Mat B = (cv::Mat_<float>(2,2) << 5, 6, 7, 8);
    cv::Mat C = A * B;
    printf("✓ 矩阵乘法运算完成\n");

    // 10. 图像尺寸调整
    cv::Mat resized;
    cv::resize(drawing, resized, cv::Size(150, 106));
    if(cv::imwrite("/tmp/opencv_resized.bmp", resized)) {
        printf("✓ 图像缩放完成\n");
    } else {
        printf("✗ 图像缩放失败\n");
    }

    printf("\n所有功能测试完成！生成的文件如下：\n");
    printf("- /tmp/opencv_red.bmp (基础红色方块)\n");  
    printf("- /tmp/opencv_gradient.bmp (彩色渐变)\n");
    printf("- /tmp/opencv_gray.bmp (灰度图)\n");
    printf("- /tmp/opencv_edges.bmp (边缘检测)\n");
    printf("- /tmp/opencv_blurred.bmp (模糊效果)\n");
    printf("- /tmp/opencv_threshold.bmp (阈值分割)\n");
    printf("- /tmp/opencv_morphed.bmp (形态学操作)\n");
    printf("- /tmp/opencv_drawing.bmp (几何绘图)\n");
    printf("- /tmp/opencv_resized.bmp (缩略图)\n");

    return 0;
}