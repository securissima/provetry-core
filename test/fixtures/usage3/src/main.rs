use smallvec::SmallVec;
use bytes::Bytes;
fn main() {
    let mut v: SmallVec<[u8; 4]> = SmallVec::new();
    v.push(1);
    let _ = memchr::memchr(b'a', b"abc");
    let _ = Bytes::from_static(b"x");
    let _ = hyper::Body::empty();
    lazy_static::lazy_static! { static ref X: u8 = 1; }
}
