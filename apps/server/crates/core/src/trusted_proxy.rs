use std::net::IpAddr;
use std::str::FromStr;

/// an address range, or a single address when no prefix is given
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0:?} is not an ip address or cidr range")]
pub struct CidrError(String);

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || CidrError(s.to_owned());
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix.parse::<u8>().map_err(|_| bad())?)),
            None => (s, None),
        };
        let network: IpAddr = addr.parse().map_err(|_| bad())?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { network, prefix })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u32::from(network) ^ u32::from(ip)) & mask == 0
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u128::from(network) ^ u128::from(ip)) & mask == 0
            }
            _ => false,
        }
    }
}

/// the reverse proxies whose forwarded client address headers are believed.
/// empty means no header is trusted and the socket peer is the client
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// parses a comma separated list of addresses and cidr ranges
    ///
    /// # Errors
    ///
    /// Returns a [`CidrError`] naming the first entry that does not parse.
    pub fn parse(list: &str) -> Result<Self, CidrError> {
        list.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::parse)
            .collect::<Result<Vec<Cidr>, _>>()
            .map(Self)
    }

    pub fn is_trusted(&self, peer: IpAddr) -> bool {
        self.0.iter().any(|cidr| cidr.contains(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_range_contains_its_members_only() {
        let proxies = TrustedProxies::parse("173.245.48.0/20, 2400:cb00::/32").unwrap();
        assert!(proxies.is_trusted(ip("173.245.48.1")));
        assert!(proxies.is_trusted(ip("173.245.63.255")));
        assert!(!proxies.is_trusted(ip("173.245.64.0")));
        assert!(proxies.is_trusted(ip("2400:cb00::1")));
        assert!(!proxies.is_trusted(ip("2400:cb01::1")));
    }

    #[test]
    fn a_bare_address_matches_only_itself() {
        let proxies = TrustedProxies::parse("10.0.0.5").unwrap();
        assert!(proxies.is_trusted(ip("10.0.0.5")));
        assert!(!proxies.is_trusted(ip("10.0.0.6")));
    }

    #[test]
    fn an_ipv4_mapped_peer_matches_its_ipv4_range() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert!(proxies.is_trusted(ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn an_empty_list_trusts_nobody() {
        assert!(!TrustedProxies::parse("")
            .unwrap()
            .is_trusted(ip("10.0.0.1")));
    }

    #[test]
    fn a_zero_prefix_matches_every_address_of_its_family() {
        let proxies = TrustedProxies::parse("0.0.0.0/0").unwrap();
        assert!(proxies.is_trusted(ip("203.0.113.9")));
        assert!(!proxies.is_trusted(ip("2001:db8::1")));
    }

    #[test]
    fn malformed_entries_are_rejected() {
        for bad in ["nope", "10.0.0.0/33", "10.0.0.0/x", "::1/129", "10.0.0.0/"] {
            assert!(TrustedProxies::parse(bad).is_err(), "{bad}");
        }
    }
}
