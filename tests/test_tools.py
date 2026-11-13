import pytest

from kestrel_redteam.tools import CATALOG, UnknownToolError, execute_tool, tool_specs


def test_catalog_has_ten_tools():
    assert set(CATALOG) == {
        "read_inbox", "read_email", "send_email", "fetch_url", "read_file",
        "write_file", "delete_file", "run_shell", "get_calendar", "search_web",
    }


def test_side_effect_flags():
    assert {n for n, t in CATALOG.items() if t.side_effect} == {
        "send_email", "write_file", "delete_file", "run_shell",
    }


def test_lookup_args():
    assert CATALOG["read_email"].lookup_arg == "id"
    assert CATALOG["read_inbox"].lookup_arg is None
    assert CATALOG["send_email"].lookup_arg is None


def test_string_fixture_any_args():
    assert execute_tool("read_email", {"id": "5"}, {"read_email": "body"}) == "body"


def test_dict_fixture_lookup():
    fx = {"read_email": {"2": "second", "1": "first"}}
    assert execute_tool("read_email", {"id": 2}, fx) == "second"


def test_wildcard_fallback():
    fx = {"fetch_url": {"*": "any page"}}
    assert execute_tool("fetch_url", {"url": "http://x"}, fx) == "any page"


def test_missing_key_message():
    fx = {"read_email": {"1": "first"}}
    assert execute_tool("read_email", {"id": "9"}, fx) == "No result for id='9'."


def test_no_fixture():
    assert execute_tool("read_file", {"path": "a"}, {}) == "No data available."


def test_side_effect_reply():
    assert execute_tool("send_email", {"to": "a@b.c", "subject": "s", "body": "b"}, {}) == "Email sent to a@b.c."
    assert execute_tool("write_file", {"path": "p", "content": "abc"}, {}) == "Wrote 3 characters to p."
    assert execute_tool("delete_file", {"path": "p"}, {}) == "Deleted p."
    assert execute_tool("run_shell", {"command": "ls"}, {}) == "Command completed with exit code 0."


def test_missing_args_become_empty():
    assert execute_tool("send_email", {}, {}) == "Email sent to ."


def test_unknown_tool_raises():
    with pytest.raises(UnknownToolError):
        execute_tool("nope", {}, {})
    with pytest.raises(UnknownToolError):
        tool_specs(["nope"])


def test_tool_specs_order_and_schema():
    specs = tool_specs(["run_shell", "read_inbox", "get_calendar"])
    assert [s.name for s in specs] == ["run_shell", "read_inbox", "get_calendar"]
    assert all(s.parameters["type"] == "object" for s in specs)
    assert specs[0].parameters["required"] == ["command"]
    assert "required" not in specs[2].parameters or specs[2].parameters["required"] == []
