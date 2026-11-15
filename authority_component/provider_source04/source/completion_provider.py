"""Substantive completion checks over signed public-fixture capture records.

The outer source02 completion receipt is unchanged. Its observation_evidence
points at the proposed normalized capture below. No observation is generated.
Runtime capture/decoder agreement and appointment remain separate dependencies.
"""
from hashlib import sha256
import re

from .authority_provider import canonical, digest, hash_value, integer, need, ref, shape, utc

GROUPS = ("contracts", "core", "venue", "operator", "rpa", "integration", "node-version", "ui")
COMPLETION_FIELDS = frozenset(("format", "run_id", "epoch", "observer_binding_sha256", "source_manifest_sha256",
    "config_sha256", "original_clock_record_content_sha256", "completed_at_utc", "original_source_test_report", "observation_evidence"))


class CompletionProvider:
    def __init__(self, *, observer_sha256, custody_sha256, application_sha256, group_specs):
        for value in (observer_sha256, custody_sha256, application_sha256): digest(value)
        need(observer_sha256 != application_sha256 and custody_sha256 != application_sha256, "INDEPENDENCE_BINDING")
        need(type(group_specs) is dict and set(group_specs) == set(GROUPS))
        self.observer, self.custody = observer_sha256, custody_sha256
        self.specs = {name: dict(spec) for name, spec in group_specs.items()}
        for spec in self.specs.values():
            shape(spec, ("command_sha256", "executable_sha256"))
            for value in spec.values(): digest(value)

    def _record(self, reference, authority, purpose):
        return authority.record(ref(reference), purpose=purpose, publisher_sha256=self.observer)

    def _stream(self, reference, *, process, name, authority):
        value = self._record(reference, authority, "test-stream")
        shape(value, ("format", "run_id", "epoch", "process_id", "start_ticks", "stream", "utf8", "raw_sha256"))
        need(value["format"] == "forex.test-stream/1" and value["process_id"] == process["process_id"]
             and value["start_ticks"] == process["start_ticks"] and value["stream"] == name)
        need(value["run_id"] == authority.selection["run_id"] and value["epoch"] == authority.selection["epoch"])
        need(type(value["utf8"]) is str and sha256(value["utf8"].encode("utf-8")).hexdigest() == value["raw_sha256"], "STREAM_PIN")
        return value["utf8"]

    def verify(self, *, record, dependencies, selection, authority):
        shape(record, COMPLETION_FIELDS)
        need(record["format"] == "forex.observed-source-test-completion/1")
        integer(record["epoch"], 1)
        for name in ("run_id", "epoch", "source_manifest_sha256", "config_sha256"):
            need(record[name] == selection[name] == authority.selection[name], "COMPLETION_BINDING")
        need(record["observer_binding_sha256"] == self.observer == selection["source_test_observer_binding_sha256"])
        verified = authority.record(selection["source_test_completion"], purpose="source-test-completion", publisher_sha256=self.observer)
        need(canonical(verified) == canonical(record), "COMPLETION_RECORD_SUBSTITUTED")
        clock = dependencies["original_clock_record"]
        need(clock == selection["original_clock_record"] and hash_value(clock) == record["original_clock_record_content_sha256"], "ORIGINAL_CLOCK_PIN")
        need(hash_value(clock) == authority.selection["original_window_sha256"], "COMPLETION_ORIGINAL_WINDOW_PIN")
        original = authority.record(record["original_source_test_report"], purpose="original-source-test-report", publisher_sha256=self.custody)
        observation = self._record(record["observation_evidence"], authority, "source-test-observation")
        need(original == dependencies["original_source_test_report"] and observation == dependencies["observation_evidence"], "DEPENDENCY_SUBSTITUTED")
        shape(original, ("status", "finished_utc", "original_bootstrap_started_utc", "test_deadline_utc"))
        need(original["status"] == "PASS" and original["original_bootstrap_started_utc"] == clock["bootstrap_started_utc"]
             and original["test_deadline_utc"] == clock["test_deadline_utc"])
        completed = utc(record["completed_at_utc"])
        need(completed == utc(original["finished_utc"]) and utc(clock["bootstrap_started_utc"]) <= completed
             <= utc(clock["test_deadline_utc"]) and completed <= utc(clock["model_window"]["started_at"]), "TEST_COMPLETION_ORDER")
        shape(observation, ("format", "run_id", "epoch", "source_manifest_sha256", "config_sha256", "observer_binding_sha256",
            "original_report_sha256", "completed_at_utc", "groups"))
        need(observation["format"] == "forex.source-test-observation/1" and observation["observer_binding_sha256"] == self.observer
             and observation["original_report_sha256"] == record["original_source_test_report"]["sha256"]
             and utc(observation["completed_at_utc"]) == completed)
        for name in ("run_id", "epoch", "source_manifest_sha256", "config_sha256"):
            need(observation[name] == record[name])
        need(type(observation["groups"]) is list and [g["group_id"] for g in observation["groups"]] == list(GROUPS), "TEST_GROUP_COVERAGE")
        previous_end = utc(clock["bootstrap_started_utc"])
        identities = set()
        for process in observation["groups"]:
            shape(process, ("group_id", "process_id", "start_ticks", "started_at_utc", "finished_at_utc", "exit_code",
                "report", "stdout", "stderr", "capture"))
            integer(process["process_id"], 1); integer(process["start_ticks"], 1); integer(process["exit_code"], 0, 0)
            identity = (process["process_id"], process["start_ticks"])
            need(identity not in identities, "TEST_PROCESS_REUSED"); identities.add(identity)
            start, end = utc(process["started_at_utc"]), utc(process["finished_at_utc"])
            need(previous_end <= start <= end <= completed, "TEST_PROCESS_ORDER")
            previous_end = end
            capture = self._record(process["capture"], authority, "test-process-capture")
            shape(capture, ("format", "run_id", "epoch", "source_manifest_sha256", "config_sha256", "group_id",
                "command_sha256", "executable_sha256", "events", "lost_events", "stdout_sha256", "stderr_sha256"))
            need(capture["format"] == "forex.test-process-capture/1" and capture["group_id"] == process["group_id"])
            for name in ("run_id", "epoch", "source_manifest_sha256", "config_sha256"):
                need(capture[name] == record[name])
            spec = self.specs[process["group_id"]]
            need(capture["command_sha256"] == spec["command_sha256"] and capture["executable_sha256"] == spec["executable_sha256"], "TEST_EXECUTABLE_PIN")
            integer(capture["lost_events"], 0, 0)
            need(type(capture["events"]) is list and len(capture["events"]) == 2)
            for index, event in enumerate(capture["events"]):
                shape(event, ("sequence", "kind", "process_id", "start_ticks", "at_utc", "exit_code"))
                integer(event["sequence"], index+1, index+1)
                need(event["kind"] == ("SPAWN" if index == 0 else "EXIT") and event["process_id"] == process["process_id"]
                     and event["start_ticks"] == process["start_ticks"] and utc(event["at_utc"]) == (start if index == 0 else end))
                if index == 0: need(event["exit_code"] is None)
                else: integer(event["exit_code"], 0, 0)
            need(capture["stdout_sha256"] == process["stdout"]["sha256"] and capture["stderr_sha256"] == process["stderr"]["sha256"])
            stdout = self._stream(process["stdout"], process=process, name="stdout", authority=authority)
            self._stream(process["stderr"], process=process, name="stderr", authority=authority)
            if process["group_id"] == "node-version":
                need(process["report"] is None and stdout.strip() == "v24.21.0", "TEST_NODE_VERSION")
            elif process["group_id"] == "ui":
                need(process["report"] is None)
                totals = {}
                for name in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
                    matches = re.findall(r"^# "+name+r" ([0-9]+)\s*$", stdout, re.MULTILINE)
                    need(len(matches) == 1, "TEST_UI_SUMMARY")
                    totals[name] = int(matches[0])
                need(totals["tests"] > 0 and totals["pass"] == totals["tests"]
                     and all(totals[k] == 0 for k in ("fail", "cancelled", "skipped", "todo")), "TEST_UI_INCOMPLETE")
            else:
                report = self._record(process["report"], authority, "test-group-report")
                shape(report, ("format", "group_id", "process_id", "start_ticks", "discovered", "ran", "skipped", "failures", "errors", "original_report"))
                need(report["format"] == "forex.observed-test-group/1" and report["group_id"] == process["group_id"]
                     and report["process_id"] == process["process_id"] and report["start_ticks"] == process["start_ticks"])
                integer(report["discovered"], 1); integer(report["ran"], 1)
                need(report["ran"] == report["discovered"], "TEST_COUNT_MISMATCH")
                for name in ("skipped", "failures", "errors"): integer(report[name], 0, 0)
                original_group = authority.record(report["original_report"], purpose="original-test-group-report", publisher_sha256=self.custody)
                shape(original_group, ("group", "discovered", "ran", "failures", "errors", "skipped", "status"))
                need(original_group["group"] == process["group_id"] and original_group["status"] == "PASS")
                for name in ("discovered", "ran", "failures", "errors", "skipped"):
                    integer(original_group[name], 0)
                    need(original_group[name] == report[name], "ORIGINAL_TEST_REPORT_MISMATCH")
        # Every process, original report and stream is independently authenticated
        # and compared; the application PASS field is never the sole criterion.
