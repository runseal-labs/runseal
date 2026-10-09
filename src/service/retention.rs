use serde_json::Value;

/// Conservative residency accounting, including strings, arrays, and map nodes.
pub(super) fn retained_bytes(value: &Value) -> usize {
    let base = std::mem::size_of::<Value>();
    base + match value {
        Value::String(text) => text.capacity() + 32,
        Value::Array(values) => {
            values.capacity() * base + values.iter().map(retained_bytes).sum::<usize>()
        }
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| 256 + key.capacity() + retained_bytes(value))
            .sum::<usize>(),
        _ => 0,
    }
}
