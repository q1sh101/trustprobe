#include <string.h>

#include "assert_helpers.h"
#include "output.h"
#include "types.h"

static void test_default_initialization(void) {
    check_result_t r = make_result("test", CHECK_OK, "all good");
    assert_true("default_skip_reason_none_for_ok", r.skip_reason == SKIP_NONE);

    r = make_result("test", CHECK_WARN, "warning");
    assert_true("default_skip_reason_none_for_warn", r.skip_reason == SKIP_NONE);

    r = make_result("test", CHECK_FAIL, "fail");
    assert_true("default_skip_reason_none_for_fail", r.skip_reason == SKIP_NONE);

    r = make_result("test", CHECK_SKIP, "raw skip");
    assert_true("make_result_skip_keeps_none", r.skip_reason == SKIP_NONE);
}

static void test_make_skip_sets_reason(void) {
    check_result_t r = make_skip("name", SKIP_TOOL_ABSENT, "tool not found");
    assert_true("make_skip_state", r.state == CHECK_SKIP);
    assert_true("make_skip_reason", r.skip_reason == SKIP_TOOL_ABSENT);
    assert_true("make_skip_detail", strcmp(r.detail, "tool not found") == 0);
    assert_false("make_skip_actionable_false", r.actionable);
    assert_false("make_skip_root_false", r.requires_root);
}

static void test_make_skip_actionable(void) {
    check_result_t r = make_skip_actionable("name", SKIP_NOT_CONFIGURED, "tool not configured");
    assert_true("actionable_state", r.state == CHECK_SKIP);
    assert_true("actionable_reason", r.skip_reason == SKIP_NOT_CONFIGURED);
    assert_true("actionable_flag", r.actionable);
    assert_false("actionable_root_false", r.requires_root);
}

static void test_make_skip_root(void) {
    check_result_t r = make_skip_root("name", SKIP_EXEC_FAILED, "tool query failed");
    assert_true("root_state", r.state == CHECK_SKIP);
    assert_true("root_reason", r.skip_reason == SKIP_EXEC_FAILED);
    assert_true("root_flag", r.requires_root);
    assert_false("root_actionable_false", r.actionable);
}

static void test_emit_macros(void) {
    check_result_t results[16] = {0};
    size_t used = 0;
    size_t max_results = 16;

    EMIT_SKIP_TOOL("a", "tool");
    EMIT_SKIP_TOOL_INSTALL("b", "tool");
    EMIT_SKIP_FEATURE("c", "feat");
    EMIT_SKIP_EXEC("d", "tool");
    EMIT_SKIP_EXEC_ROOT("e", "tool");
    EMIT_SKIP_PROBE("f", "tool");
    EMIT_SKIP_FIELD("g", "field", "tool");
    EMIT_SKIP_PARSE("h", "tool");
    EMIT_SKIP_NOT_CONF("i", "tool");
    EMIT_SKIP_SUBJECT("j", "subj");
    EMIT_SKIP_HW("k", "hw");
    EMIT_SKIP_VENDOR("l", "Intel-only check");
    EMIT_SKIP("m", SKIP_FEATURE_ABSENT, "raw detail");
    EMIT_SKIP_SUBJECT_INSTALL("n", "subj");

    assert_eq_sz("emit_macros_count", used, 14);

    assert_true("tool_reason", results[0].skip_reason == SKIP_TOOL_ABSENT);
    assert_true("tool_detail", strcmp(results[0].detail, "tool not found") == 0);
    assert_false("tool_not_actionable", results[0].actionable);

    assert_true("tool_install_reason", results[1].skip_reason == SKIP_TOOL_ABSENT);
    assert_true("tool_install_actionable", results[1].actionable);
    assert_true("tool_install_detail", strcmp(results[1].detail, "requires tool") == 0);

    assert_true("feature_reason", results[2].skip_reason == SKIP_FEATURE_ABSENT);
    assert_true("feature_detail", strcmp(results[2].detail, "feat not available") == 0);

    assert_true("exec_reason", results[3].skip_reason == SKIP_EXEC_FAILED);
    assert_true("exec_detail", strcmp(results[3].detail, "tool query failed") == 0);
    assert_false("exec_not_root", results[3].requires_root);

    assert_true("exec_root_reason", results[4].skip_reason == SKIP_EXEC_FAILED);
    assert_true("exec_root_flag", results[4].requires_root);

    assert_true("probe_reason", results[5].skip_reason == SKIP_PROBE_INDETERMINATE);
    assert_true("probe_detail", strcmp(results[5].detail, "tool result indeterminate") == 0);

    assert_true("field_reason", results[6].skip_reason == SKIP_REPORT_FIELD_ABSENT);
    assert_true("field_detail", strcmp(results[6].detail, "field absent from tool output") == 0);

    assert_true("parse_reason", results[7].skip_reason == SKIP_OUTPUT_UNPARSEABLE);
    assert_true("parse_detail", strcmp(results[7].detail, "tool output not parseable") == 0);

    assert_true("not_conf_reason", results[8].skip_reason == SKIP_NOT_CONFIGURED);
    assert_true("not_conf_actionable", results[8].actionable);
    assert_true("not_conf_detail", strcmp(results[8].detail, "tool not configured") == 0);

    assert_true("subject_reason", results[9].skip_reason == SKIP_SUBJECT_ABSENT);
    assert_true("subject_detail", strcmp(results[9].detail, "subj not present on this host") == 0);

    assert_true("hw_reason", results[10].skip_reason == SKIP_HW_ABSENT);
    assert_true("hw_detail", strcmp(results[10].detail, "hw not detected") == 0);

    assert_true("vendor_reason", results[11].skip_reason == SKIP_VENDOR_SCOPE);
    assert_true("vendor_detail", strcmp(results[11].detail, "Intel-only check") == 0);

    assert_true("raw_skip_reason", results[12].skip_reason == SKIP_FEATURE_ABSENT);
    assert_true("raw_skip_detail", strcmp(results[12].detail, "raw detail") == 0);

    assert_true("subject_install_reason", results[13].skip_reason == SKIP_SUBJECT_ABSENT);
    assert_true("subject_install_actionable", results[13].actionable);
    assert_true("subject_install_detail", strcmp(results[13].detail, "subj not present on this host") == 0);
}

static void test_emit_macros_respect_bounds(void) {
    check_result_t results[2] = {0};
    size_t used = 0;
    size_t max_results = 2;

    EMIT_SKIP_TOOL("first", "t");
    EMIT_SKIP_TOOL("second", "t");
    EMIT_SKIP_TOOL("overflow", "t");

    assert_eq_sz("bounds_check_capped", used, 2);
    assert_true("bounds_first_recorded",  strcmp(results[0].name, "first")  == 0);
    assert_true("bounds_second_recorded", strcmp(results[1].name, "second") == 0);
}

static void test_skip_reason_name_mapping(void) {
    assert_true("name_none",      strcmp(bythos_skip_reason_name(SKIP_NONE),                "NONE")                == 0);
    assert_true("name_tool",      strcmp(bythos_skip_reason_name(SKIP_TOOL_ABSENT),         "TOOL_ABSENT")         == 0);
    assert_true("name_feature",   strcmp(bythos_skip_reason_name(SKIP_FEATURE_ABSENT),      "FEATURE_ABSENT")      == 0);
    assert_true("name_exec",      strcmp(bythos_skip_reason_name(SKIP_EXEC_FAILED),         "EXEC_FAILED")         == 0);
    assert_true("name_probe",     strcmp(bythos_skip_reason_name(SKIP_PROBE_INDETERMINATE), "PROBE_INDETERMINATE") == 0);
    assert_true("name_field",     strcmp(bythos_skip_reason_name(SKIP_REPORT_FIELD_ABSENT), "REPORT_FIELD_ABSENT") == 0);
    assert_true("name_parse",     strcmp(bythos_skip_reason_name(SKIP_OUTPUT_UNPARSEABLE),  "OUTPUT_UNPARSEABLE")  == 0);
    assert_true("name_not_conf",  strcmp(bythos_skip_reason_name(SKIP_NOT_CONFIGURED),      "NOT_CONFIGURED")      == 0);
    assert_true("name_subject",   strcmp(bythos_skip_reason_name(SKIP_SUBJECT_ABSENT),      "SUBJECT_ABSENT")      == 0);
    assert_true("name_hw",        strcmp(bythos_skip_reason_name(SKIP_HW_ABSENT),           "HW_ABSENT")           == 0);
    assert_true("name_vendor",    strcmp(bythos_skip_reason_name(SKIP_VENDOR_SCOPE),        "VENDOR_SCOPE")        == 0);
}

int main(void) {
    test_default_initialization();
    test_make_skip_sets_reason();
    test_make_skip_actionable();
    test_make_skip_root();
    test_emit_macros();
    test_emit_macros_respect_bounds();
    test_skip_reason_name_mapping();
    printf("skip reason ok\n");
    return 0;
}
