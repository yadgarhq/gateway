//! The chart's `adminBootstrap.refusePreMintedUserId` is a required boolean
//! that ships `false` (Max's ruling (b), 2026-10-24).
//!
//! The binary refuses an absent `YADGAR_ADMIN_REFUSE_PRE_MINTED_USER_ID`
//! (ADR-0569), so the schema may not let the chart drop the key that sources
//! it, nor pass a non-boolean that a bare truthiness render would misread. The
//! render itself is `scripts/tests/test_pre_minted_switch.py`.

use std::path::PathBuf;

use serde_json::Value;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()))
}

#[test]
fn the_switch_is_a_required_boolean_in_a_closed_block() {
    let schema: Value =
        serde_json::from_str(&read("chart/values.schema.json")).expect("the schema is JSON");
    let block = &schema["properties"]["adminBootstrap"];
    assert_eq!(block["additionalProperties"], Value::Bool(false));
    assert_eq!(
        block["properties"]["refusePreMintedUserId"]["type"], "boolean",
        "a non-boolean must be a schema refusal"
    );
    let required = block["required"].as_array().cloned().unwrap_or_default();
    assert!(
        required.contains(&Value::from("refusePreMintedUserId")),
        "adminBootstrap.refusePreMintedUserId must be schema-required (ADR-0569)"
    );
}

#[test]
fn the_switch_ships_disengaged() {
    let values: serde_norway::Value =
        serde_norway::from_str(&read("chart/values.yaml")).expect("values.yaml is YAML");
    assert_eq!(
        values["adminBootstrap"]["refusePreMintedUserId"],
        serde_norway::Value::Bool(false),
        "the default keeps today's behaviour: the switch is not engaged"
    );
}
