MODDIR=${0%/*}
pkill -f "${MODDIR}/lowertier-core"

# 使用 ${MODDIR:?} 确保变量非空，避免执行 rm -rf /*
rm -rf "${MODDIR:?}/"*