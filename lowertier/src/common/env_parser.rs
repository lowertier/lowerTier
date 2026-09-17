//! 环境变量解析模块
//!
//! 提供配置文件中环境变量占位符的解析功能
//! 支持 Shell 风格的语法：${VAR}、$VAR、${VAR:-default} 等

use std::borrow::Cow;

/// 解析字符串中的环境变量占位符
///
/// 支持的语法：
/// - `${VAR_NAME}`          - 标准格式（推荐）
/// - `$VAR_NAME`            - 简写格式
/// - `${VAR_NAME:-default}` - 带默认值（bash 标准语法）
///
/// # 参数
/// - `text`: 待解析的字符串
///
/// # 返回值
/// - `String`: 替换后的字符串
/// - `bool`: 是否检测到并替换了环境变量
pub fn expand_env_vars(text: &str) -> (String, bool) {
    // 使用 shellexpand::env() 解析环境变量
    // 该函数仅处理环境变量，不处理 tilde (~) 扩展，适合配置文件场景
    match shellexpand::env(text) {
        Ok(expanded) => {
            // 通过比较原始字符串和扩展后的字符串判断是否发生了替换
            let changed = match &expanded {
                Cow::Borrowed(_) => false, // 未发生变化，仍是借用
                Cow::Owned(_) => true,     // 发生了变化，产生了新字符串
            };

            (expanded.into_owned(), changed)
        }
        Err(e) => {
            // 如果解析失败（例如变量引用语法错误），记录警告并返回原字符串
            tracing::warn!("Failed to expand environment variables in config: {}", e);
            (text.to_string(), false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{remove_env_var, set_env_var};
}
