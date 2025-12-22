#![forbid(unsafe_code)]

use cdm::emotion::EmotionField;

pub trait Chip2Reader: Send + Sync {
    fn get_latest_emotion_field(&self) -> Option<EmotionField>;
}

#[derive(Debug, Clone, Default)]
pub struct MockChip2Reader {
    field: Option<EmotionField>,
}

impl MockChip2Reader {
    pub fn new(field: Option<EmotionField>) -> Self {
        Self { field }
    }
}

impl Chip2Reader for MockChip2Reader {
    fn get_latest_emotion_field(&self) -> Option<EmotionField> {
        self.field.clone()
    }
}
