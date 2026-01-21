#!/bin/bash
# 验证编译器实际使用的优化选项

echo "=== 编译器优化验证工具 ==="
echo ""

# 创建测试文件
cat > /tmp/test_opt.cpp << 'EOF'
#include <cmath>

int calculate(int a, int b) {
    return a * b + std::abs(a - b);
}

int main() {
    int result = 0;
    for (int i = 0; i < 1000; i++) {
        result += calculate(i, i + 1);
    }
    return result;
}
EOF

echo "1. 测试基础编译（无优化）"
g++ -m32 /tmp/test_opt.cpp -o /tmp/test_none 2>&1 | head -5
echo "   二进制大小: $(stat -f%z /tmp/test_none 2>/dev/null || stat -c%s /tmp/test_none) 字节"
echo ""

echo "2. 测试完整优化（我们的配置）"
g++ -m32 -O3 -march=skylake -mtune=skylake -flto \
    -fomit-frame-pointer -fno-stack-protector -fno-plt \
    -fmerge-all-constants -fno-unwind-tables \
    -fno-asynchronous-unwind-tables -fno-ident -pipe \
    -fno-rtti -fno-exceptions \
    -fno-strict-aliasing -fno-strict-overflow \
    -fcf-protection=none -g0 \
    /tmp/test_opt.cpp -o /tmp/test_opt 2>&1 | head -5
echo "   二进制大小: $(stat -f%z /tmp/test_opt 2>/dev/null || stat -c%s /tmp/test_opt) 字节"
echo ""

echo "3. 查看实际启用的优化（详细模式）"
echo "   使用 -fopt-info 查看优化报告..."
g++ -m32 -O3 -march=skylake -mtune=skylake -flto \
    -fomit-frame-pointer -fno-stack-protector \
    -fopt-info-optimized-missed=opt_report.txt \
    /tmp/test_opt.cpp -o /tmp/test_verbose 2>&1 | head -10
echo ""

if [ -f opt_report.txt ]; then
    echo "   优化报告前 20 行:"
    head -20 opt_report.txt
    echo ""
fi

echo "4. 使用 -Q --help=optimizers 查看所有优化标志"
g++ -Q --help=optimizers -O3 -march=skylake 2>&1 | grep enabled | head -30
echo ""

echo "5. 反汇编检查（查看是否使用了 AVX2 指令）"
objdump -d /tmp/test_opt 2>/dev/null | grep -E "vpadd|vmul|vfma" | head -5
echo ""

echo "=== 完成 ==="
rm -f /tmp/test_opt.cpp /tmp/test_none /tmp/test_opt /tmp/test_verbose opt_report.txt
