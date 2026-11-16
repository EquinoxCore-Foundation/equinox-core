#![allow(dead_code)]
// Section 12: Finance & Portfolio Valuation Engine (Zero Duplicate Asset Valuation)

pub struct PortfolioValuation {
    pub total_usd_cents: u128,
    pub total_inr_paise: u128,
}

pub struct PortfolioEngine;
impl PortfolioEngine {
    pub fn compute_valuation(eqx_atomic: u64, price_usd_micro: u64, usd_to_inr_rate: u64) -> PortfolioValuation {
        // eqx_atomic has 8 decimals; price_usd_micro has 6 decimals
        let usd_cents = ((eqx_atomic as u128) * (price_usd_micro as u128)) / 1_000_000_000_000;
        let inr_paise = usd_cents * (usd_to_inr_rate as u128);
        PortfolioValuation { total_usd_cents: usd_cents, total_inr_paise: inr_paise }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_portfolio_usd_and_inr_valuation() {
        // 1,000,000 EQX at $2.45 (2,450,000 micro-USD) and 1 USD = 85 INR
        let v = PortfolioEngine::compute_valuation(100_000_000_000_000, 2_450_000, 85);
        assert_eq!(v.total_usd_cents, 245_000_000); // $2,450,000.00
        assert_eq!(v.total_inr_paise, 20_825_000_000); // ₹20,82,50,000.00
    }
}
