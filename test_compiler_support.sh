#!/bin/bash
# 测试编译器版本和选项支持

echo "=== 编译器版本检查 ==="
echo ""

# 检查 GCC 版本
if command -v gcc &> /dev/null; then
    echo "GCC 版本:"
    gcc --version | head -1
    GCC_VERSION=$(gcc -dumpversion)
    echo "版本号: $GCC_VERSION"
    echo ""
else
    echo "❌ GCC 未安装"
    exit 1
fi

# 检查 G++ 版本
if command -v g++ &> /dev/null; then
    echo "G++ 版本:"
    g++ --version | head -1
    echo ""
else
    echo "❌ G++ 未安装"
    exit 1
fi

echo "=== 编译选项支持检查 ==="
echo ""

# 测试文件
cat > /tmp/test.cpp << 'EOF'
int main() {
    return 0;
}
EOF

# 测试选项列表
OPTIONS=(
    "-O3"
    "-march=skylake"
    "-mtune=skylake"
    "-flto"
    "-fuse-linker-plugin"
    "-fomit-frame-pointer"
    "-fno-stack-protector"
    "-fno-plt"
    "-fmerge-all-constants"
    "-fno-unwind-tables"
    "-fno-asynchronous-unwind-tables"
    "-fno-ident"
    "-pipe"
    "-fno-rtti"
    "-fno-exceptions"
    "-fno-strict-aliasing"
    "-fno-strict-overflow"
    "-fcf-protection=none"
    "-g0"
)

echo "测试编译选项支持情况:"
echo ""

SUPPORTED=0
UNSUPPORTED=0

for opt in "${OPTIONS[@]}"; do
    if g++ -m32 $opt /tmp/test.cpp -o /tmp/test 2>/dev/null; then
        echo "✅ $opt"
        ((SUPPORTED++))
    else
        echo "❌ $opt"
        ((UNSUPPORTED++))
    fi
done

echo ""
echo "=== 总结 ==="
echo "支持的选项: $SUPPORTED"
echo "不支持的选项: $UNSUPPORTED"
echo ""

if [ $UNSUPPORTED -eq 0 ]; then
    echo "🎉 所有编译选项都支持！"
    exit 0
else
    echo "⚠️ 有 $UNSUPPORTED 个选项不支持"
    exit 1
fi

# 清理
rm -f /tmp/test.cpp /tmp/test
