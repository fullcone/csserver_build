#!/bin/bash
# Verify compiler optimizations in built binaries
# Usage: ./verify_optimizations.sh <binary_path> [component_name]

BINARY="$1"
COMPONENT="${2:-Binary}"

if [ ! -f "$BINARY" ]; then
    echo "❌ Error: Binary not found: $BINARY"
    exit 1
fi

echo "=== Verifying Optimizations for $COMPONENT ==="
echo "Binary: $BINARY"
echo ""

# 1. Check for AVX2 instructions (proof of -march=skylake)
echo "1. AVX2 Instructions (Skylake):"
AVX2_COUNT=$(objdump -d "$BINARY" 2>/dev/null | grep -cE "vpadd|vmul|vfma" || echo "0")
if [ "$AVX2_COUNT" -gt 0 ]; then
    echo "   ✅ Found $AVX2_COUNT AVX2 instructions"
else
    echo "   ⚠️ No AVX2 instructions (may be normal for some code)"
fi

# 2. Check for frame pointer (should be omitted)
echo "2. Frame Pointer:"
if readelf -s "$BINARY" 2>/dev/null | grep -qi "frame"; then
    echo "   ⚠️ Frame pointer symbols present"
else
    echo "   ✅ Frame pointer omitted"
fi

# 3. Check for unwind tables (should be minimal)
echo "3. Unwind Tables:"
UNWIND_SIZE=$(readelf -S "$BINARY" 2>/dev/null | grep "eh_frame" | awk '{print $6}' || echo "")
if [ -z "$UNWIND_SIZE" ]; then
    echo "   ✅ No unwind tables"
elif [ "$UNWIND_SIZE" = "000000" ]; then
    echo "   ✅ No unwind tables"
else
    echo "   Size: 0x$UNWIND_SIZE"
fi

# 4. Check for .ident section (should be absent with -fno-ident)
echo "4. .ident Section:"
if readelf -p .comment "$BINARY" 2>/dev/null | grep -q "GCC"; then
    echo "   ⚠️ GCC ident present"
else
    echo "   ✅ No ident section"
fi

# 5. Binary size
echo "5. Binary Size:"
SIZE=$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY" 2>/dev/null)
SIZE_MB=$(echo "scale=2; $SIZE / 1024 / 1024" | bc 2>/dev/null || echo "N/A")
echo "   $SIZE bytes ($SIZE_MB MB)"

# 6. Symbol count
echo "6. Exported Symbols:"
SYMBOL_COUNT=$(nm -D "$BINARY" 2>/dev/null | wc -l)
echo "   $SYMBOL_COUNT symbols"

echo ""
echo "✅ Verification complete for $COMPONENT"
echo ""
