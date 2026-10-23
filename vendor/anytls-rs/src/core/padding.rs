use std::collections::HashMap;

use md5::{Digest, Md5};
use rand::RngExt;

use super::{HEADER_OVERHEAD_SIZE, MAX_FRAME_DATA_SIZE, string_map};

pub const CHECK_MARK: i32 = -1;
pub const DEFAULT_SCHEME: &[u8] = b"stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

const MAX_RECORD_COST: usize = MAX_FRAME_DATA_SIZE + HEADER_OVERHEAD_SIZE;
const MAX_SCHEME_COST: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum PaddingStep {
    Check,
    Range { minimum: u16, maximum: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddingFactory {
    raw_scheme: Vec<u8>,
    pub stop: u32,
    pub md5: String,
    scheme: HashMap<String, Vec<PaddingStep>>,
}

impl PaddingFactory {
    /// Parses a scheme, rejecting malformed ranges and generated sizes outside 1..=65535.
    /// Reversed endpoints are normalized; unequal endpoints retain an exclusive maximum.
    /// The raw scheme is limited to 65535 bytes. Each numeric step costs its maximum
    /// generated size plus a 7-byte frame header, and each `c` costs 7 bytes.
    /// Cost is limited to 65542 per record and 4 MiB across the scheme.
    pub fn new(raw_scheme: &[u8]) -> Option<Self> {
        if raw_scheme.len() > MAX_FRAME_DATA_SIZE {
            return None;
        }
        let mut entries = string_map::from_bytes(raw_scheme);
        let stop = entries.remove("stop")?.parse().ok()?;
        let mut scheme = HashMap::new();
        let mut total_cost = 0usize;
        for (key, value) in entries {
            let (steps, cost) = parse_record(&value)?;
            total_cost = total_cost.checked_add(cost)?;
            if total_cost > MAX_SCHEME_COST {
                return None;
            }
            scheme.insert(key, steps);
        }
        let mut digest = Md5::new();
        digest.update(raw_scheme);
        Some(Self {
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5: digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect(),
            scheme,
        })
    }

    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    pub fn generate_record_payload_sizes(&self, packet: u32) -> Vec<i32> {
        let Some(steps) = self.scheme.get(&packet.to_string()) else {
            return Vec::new();
        };
        steps
            .iter()
            .map(|step| match step {
                PaddingStep::Check => CHECK_MARK,
                PaddingStep::Range { minimum, maximum } => i32::from(rand::rng().random_range(*minimum..=*maximum)),
            })
            .collect()
    }
}

fn parse_record(value: &str) -> Option<(Vec<PaddingStep>, usize)> {
    let mut steps = Vec::new();
    let mut cost = 0usize;
    for value in value.split(',') {
        let (step, maximum_size) = if value == "c" {
            (PaddingStep::Check, 0)
        } else {
            let (minimum, maximum) = value.split_once('-')?;
            let mut minimum: u32 = minimum.parse().ok()?;
            let mut maximum: u32 = maximum.parse().ok()?;
            if minimum > maximum {
                std::mem::swap(&mut minimum, &mut maximum);
            }
            if minimum == 0 {
                return None;
            }
            if minimum != maximum {
                maximum -= 1;
            }
            let minimum = u16::try_from(minimum).ok()?;
            let maximum = u16::try_from(maximum).ok()?;
            (PaddingStep::Range { minimum, maximum }, usize::from(maximum))
        };
        cost = cost.checked_add(maximum_size)?.checked_add(HEADER_OVERHEAD_SIZE)?;
        if cost > MAX_RECORD_COST {
            return None;
        }
        steps.push(step);
    }
    Some((steps, cost))
}

impl std::fmt::Display for PaddingFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.md5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_default_scheme_metadata_and_ranges() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        assert_eq!(factory.stop, 8);
        assert_eq!(factory.md5, "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(factory.generate_record_payload_sizes(0), vec![30]);
        assert_eq!(factory.generate_record_payload_sizes(2).len(), 9);
        assert!(factory.generate_record_payload_sizes(2).contains(&CHECK_MARK));
    }

    #[test]
    fn rejects_invalid_padding_ranges_atomically() {
        for range in [
            "",
            "c,",
            "1",
            "1-",
            "1-2-3",
            "nope",
            "0-1",
            "-1-2",
            "1-0",
            "2147483648-2147483648",
            "4294967297-4294967297",
            "65536-65536",
            "65535-65537",
            "18446744073709551616-18446744073709551616",
        ] {
            let scheme = format!("stop=8\n1=30-30\n2={range}");
            assert!(PaddingFactory::new(scheme.as_bytes()).is_none(), "accepted {range:?}");
        }
    }

    #[test]
    fn bounds_record_payload_header_and_check_costs() {
        assert!(PaddingFactory::new(b"stop=8\n2=65535-65535").is_some());
        assert!(PaddingFactory::new(b"stop=8\n2=32764-32764,32764-32764").is_some());
        assert!(PaddingFactory::new(b"stop=8\n2=32764-32764,32765-32765").is_none());
        assert!(PaddingFactory::new(b"stop=8\n2=65528-65528,c").is_some());
        assert!(PaddingFactory::new(b"stop=8\n2=65529-65529,c").is_none());
        let markers = std::iter::repeat_n("c", 9363).collect::<Vec<_>>().join(",");
        assert!(PaddingFactory::new(format!("stop=8\n2={markers}").as_bytes()).is_some());
        assert!(PaddingFactory::new(format!("stop=8\n2={markers},c").as_bytes()).is_none());
    }

    #[test]
    fn bounds_total_scheme_padding_cost() {
        let mut scheme = String::from("stop=4294967295");
        for packet in 0..63 {
            scheme.push_str(&format!("\n{packet}=65535-65535"));
        }
        scheme.push_str("\n63=65151-65151");
        assert!(PaddingFactory::new(scheme.as_bytes()).is_some());
        scheme.push_str("\n64=c");
        assert!(PaddingFactory::new(scheme.as_bytes()).is_none());
    }

    #[test]
    fn bounds_raw_scheme_length() {
        let mut scheme = b"stop=8\n1=30-30\n".to_vec();
        scheme.resize(65535, b'\n');
        assert!(PaddingFactory::new(&scheme).is_some());
        scheme.push(b'\n');
        assert!(PaddingFactory::new(&scheme).is_none());
    }

    #[test]
    fn retains_fixed_reversed_and_maximum_exclusive_ranges() {
        for range in ["65535-65535", "65535-65536", "65536-65535"] {
            let raw = format!("stop=8\n0={range}");
            let factory = PaddingFactory::new(raw.as_bytes()).unwrap();
            assert_eq!(factory.generate_record_payload_sizes(0), vec![65535]);
        }
        let factory = PaddingFactory::new(b"stop=8\n0=30-30\n1=40-30\n2=30-40,c").unwrap();
        for _ in 0..100 {
            assert_eq!(factory.generate_record_payload_sizes(0), vec![30]);
            assert!((30..40).contains(&factory.generate_record_payload_sizes(1)[0]));
            let sizes = factory.generate_record_payload_sizes(2);
            assert!((30..40).contains(&sizes[0]));
            assert_eq!(sizes[1], CHECK_MARK);
        }
    }

    #[test]
    fn preserves_raw_identity_and_exact_packet_keys() {
        let raw = b"stop=4294967295\n01=42-42\n1=30-30\n1=31-31";
        let factory = PaddingFactory::new(raw).unwrap();
        assert_eq!(factory.raw_scheme(), raw);
        assert_eq!(factory.stop, u32::MAX);
        assert_eq!(factory.generate_record_payload_sizes(1), vec![31]);
        assert!(factory.generate_record_payload_sizes(2).is_empty());
        let leading_zero = PaddingFactory::new(b"stop=8\n01=42-42").unwrap();
        assert!(leading_zero.generate_record_payload_sizes(1).is_empty());
    }

    #[test]
    fn rejects_scheme_without_stop() {
        assert!(PaddingFactory::new(b"0=1-2").is_none());
    }
}
