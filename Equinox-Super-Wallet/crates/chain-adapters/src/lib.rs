#![allow(dead_code)]
// Section 10: Unified Multi-Chain Adapter Interface (EQX, Bitcoin, Ethereum)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedChain {
    EquinoxNative,
    BitcoinMainnet,
    EthereumEvm,
}

pub struct ChainAdapter;
impl ChainAdapter {
    pub fn validate_chain_address(chain: SupportedChain, addr: &str) -> bool {
        let a = addr.trim();
        match chain {
            SupportedChain::EquinoxNative => a.starts_with('E') && a.len() >= 26 && a.len() <= 36,
            SupportedChain::BitcoinMainnet => (a.starts_with("bc1") || a.starts_with('1') || a.starts_with('3')) && a.len() >= 26,
            SupportedChain::EthereumEvm => a.starts_with("0x") && a.len() == 42,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_multi_chain_address_isolation() {
        assert!(ChainAdapter::validate_chain_address(SupportedChain::EquinoxNative, "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx"));
        assert!(ChainAdapter::validate_chain_address(SupportedChain::BitcoinMainnet, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        assert!(ChainAdapter::validate_chain_address(SupportedChain::EthereumEvm, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"));
    }
}
