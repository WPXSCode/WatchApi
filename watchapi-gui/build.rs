fn main() {
    #[cfg(windows)]
    {
        let _ = embed_resource::compile("watchapi.rc", embed_resource::NONE);
    }
}
