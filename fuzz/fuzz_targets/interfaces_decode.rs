//! Fuzz the decoder with arbitrary bytes. An accepted descriptor must encode back to the same
//! bytes, and every reader of the list must agree with its records.

#![no_main]

use interfaces_note::{
    DeclaredInterface, MAXIMUM_INTERFACES, Refusal, decode_interfaces, descriptor_bytes,
    encode_interfaces,
};
use libfuzzer_sys::fuzz_target;

/// `encode_interfaces` takes its length as a constant, so each possible count has its own arm.
macro_rules! encode_any {
    ($list:expr, $($count:literal)*) => {
        match $list.len() {
            $($count => encode_interfaces::<{ descriptor_bytes($count) }>($list).to_vec(),)*
            _ => unreachable!("the decoder accepted more than MAXIMUM_INTERFACES records"),
        }
    };
}

fn encode(list: &[DeclaredInterface]) -> Vec<u8> {
    encode_any!(
        list,
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61
        62 63 64
    )
}

fuzz_target!(|bytes: &[u8]| {
    let Ok(interfaces) = decode_interfaces(bytes) else {
        return;
    };
    assert!(interfaces.len() <= MAXIMUM_INTERFACES);
    assert_eq!(bytes.len(), descriptor_bytes(interfaces.len()));
    assert_eq!(interfaces.is_empty(), interfaces.len() == 0);

    let list: Vec<DeclaredInterface> = interfaces.iter().collect();
    assert_eq!(list.len(), interfaces.len());
    assert!(list.windows(2).all(|pair| pair[0].id < pair[1].id));
    assert_eq!(encode(&list), bytes);

    for declared in &list {
        assert_eq!(interfaces.version_of(declared.id), Some(declared.version));
        assert_eq!(
            interfaces.check_served(declared.id, declared.version),
            Ok(())
        );
        let other = declared.version.wrapping_add(1);
        assert_eq!(
            interfaces.check_served(declared.id, other),
            Err(Refusal {
                interface: declared.id,
                declared: declared.version,
                served: other
            })
        );
    }
    // An id between or beyond the declared ones is absent, and an absent entry passes.
    for probe in [0, u64::MAX]
        .into_iter()
        .chain(list.iter().map(|d| d.id.wrapping_add(1)))
    {
        if list.iter().all(|d| d.id != probe) {
            assert_eq!(interfaces.version_of(probe), None);
            assert_eq!(interfaces.check_served(probe, 0), Ok(()));
        }
    }
});
