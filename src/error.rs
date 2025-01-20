
#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    InvalidFormat(String),
    CustomError(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}