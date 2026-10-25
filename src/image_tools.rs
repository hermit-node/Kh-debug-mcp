use serde_json::{Value, json};

pub fn list_tool() -> Value {
    json!({"name":"list_images","description":"List PNG images in persistent Docker storage (maximum 96).",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true}})
}
pub fn save_tool() -> Value {
    json!({"name":"save_image","description":"Store a PNG in the persistent image volume without replacing existing files. Each PNG may be up to 4 MiB.",
        "inputSchema":{"type":"object","properties":{
            "name":{"type":"string","description":"Name without .png, letters/digits/-/_ only"},
            "png_base64":{"type":"string","description":"Base64-encoded original PNG bytes"}
        },"required":["name","png_base64"],"additionalProperties":false},
        "annotations":{"readOnlyHint":false}})
}
pub fn delete_tool() -> Value {
    json!({"name":"delete_image","description":"Permanently delete one named PNG image from the persistent Docker volume.",
        "inputSchema":{"type":"object","properties":{
            "name":{"type":"string","description":"Name without .png"}
        },"required":["name"],"additionalProperties":false},
        "annotations":{"readOnlyHint":false,"destructiveHint":true}})
}