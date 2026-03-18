use crate::cli::ComplianceMode;
use crate::audit::tables::{
    DeadlineTable,
    nist_ir8547::NistIr8547Table,
    cnsa2::Cnsa2Table,
    fips::FipsTable,
};
use crate::audit::scoring::model::ScoringModel;
use crate::audit::scoring::{
    weighted::NistWeightedModel,
    cnsa2_strict::Cnsa2StrictModel,
    binary_gates::FipsBinaryGatesModel,
};

/// Returns the (DeadlineTable, ScoringModel) pair for the given compliance mode.
/// This is the single place that knows which table and model belong together.
pub fn compliance_pair(mode: ComplianceMode) -> (Box<dyn DeadlineTable>, Box<dyn ScoringModel>) {
    match mode {
        ComplianceMode::Nist  => (Box::new(NistIr8547Table), Box::new(NistWeightedModel)),
        ComplianceMode::Cnsa2 => (Box::new(Cnsa2Table),      Box::new(Cnsa2StrictModel)),
        ComplianceMode::Fips  => (Box::new(FipsTable),       Box::new(FipsBinaryGatesModel)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_mode_returns_nist_table() {
        let (table, model) = compliance_pair(ComplianceMode::Nist);
        assert_eq!(table.name(), "NIST IR 8547 (IPD)");
        assert_eq!(model.name(), "nist-weighted");
    }

    #[test]
    fn cnsa2_mode_returns_cnsa2_model() {
        let (_, model) = compliance_pair(ComplianceMode::Cnsa2);
        assert_eq!(model.name(), "cnsa2-strict");
    }

    #[test]
    fn fips_mode_returns_binary_gates_model() {
        let (_, model) = compliance_pair(ComplianceMode::Fips);
        assert_eq!(model.name(), "fips-binary-gates");
    }
}
