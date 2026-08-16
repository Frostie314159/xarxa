use super::Controller;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct NoControl;

impl Controller for NoControl {
    fn window(&self) -> usize {
        usize::MAX
    }
}
