#[derive(Debug, Default)]
pub struct TetheringBypass {
    enabled: bool,
}

impl TetheringBypass {
    pub fn new() -> Self {
        Self { enabled: false }
    }

    pub fn enable_bypass(&mut self) -> std::io::Result<()> {
        self.enabled = true;
        Ok(())
    }

    pub fn disable_bypass(&mut self) -> std::io::Result<()> {
        self.enabled = false;
        Ok(())
    }
}
