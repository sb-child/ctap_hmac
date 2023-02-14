fn main() {
    for device in ctap_hmac::get_devices().unwrap() {
        println!("{device:?}");
    }
}
