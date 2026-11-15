"""Sole thirteen-group completion verifier; never observes or runs a test."""
import re
from cas_forex_operational_contracts import common, method, protected, completion
from .selection_provider import same, require, fresh
from .gate_adapters import original_clock_bytes, clock_utc
from .source_test_clock import completion_clock_bytes, SOURCE_CLOCK_FORMAT

RECORD_ROUTES = {
    "CompletionSelection2": ("COMPLETION_SELECTION", "completion-selection"),
    "SourceTestReport2": ("SOURCE_TEST_REPORT", "original-source-test-report"),
    "CompletionObservation2": ("SOURCE_TEST_OBSERVATION", "source-test-observation"),
    "SourceInventory": ("SOURCE_INVENTORY", "completion-source-inventory"),
    "CommandPin": ("COMMAND_PIN", "test-command-pin"), "ParserPin": ("PARSER_PIN", "test-parser-pin"),
    "CollectionInventory": ("COLLECTION_INVENTORY", "test-collection-inventory"),
    "GroupReport2": ("TEST_GROUP_REPORT", "test-group-report"),
    "ProcessCapture2": ("TEST_PROCESS_CAPTURE", "test-process-capture"),
    "TestStream2": ("TEST_STREAM", "test-stream"), "TestDiscoveryReport": ("TEST_DISCOVERY_REPORT", "test-discovery-report")}


class FrameworkParser:
    """Pure selected parser. Flat TAP only; ambiguous/nested results reject.

    The integration freeze must pin this component/entrypoint and output dialect.
    A Python framework report is re-parsed from its complete retained JSON file.
    UI discovery is independent of TAP and supplied as its authenticated record.
    """
    def __init__(self, *, component_sha256, entrypoint="custody-strict-framework-v1"):
        self.component_sha256, self.entrypoint = component_sha256, entrypoint

    def parse(self, parser, *, stdout, stderr, framework_raw, group_id):
        require(parser["component_manifest_sha256"] == self.component_sha256 and parser["entrypoint"] == self.entrypoint, "PARSER_IMPLEMENTATION_PIN")
        require(len(framework_raw) <= parser["maximum_report_bytes"], "FRAMEWORK_REPORT_BOUND")
        for data in (stdout, stderr): require(len(data.encode("utf-8")) <= parser["maximum_stream_bytes"], "STREAM_BOUND")
        for key,actual in (("expected_stdout_utf8",stdout),("expected_stderr_utf8",stderr)):
            if parser[key] is not None: require(parser[key]==actual,"EXPECTED_STREAM_BYTES")
        if parser["mode"] == "PYTHON_METHODS":
            return completion.decode("PythonFrameworkReport2", framework_raw).payload()
        if parser["mode"] == "NODE_VERSION":
            expected = {"format": "forex.node-version-report/1", "group_id": "node-version", "stdout_utf8": stdout, "stderr_utf8": stderr}
            require(same(completion.decode("NodeVersionReport1", framework_raw).payload(), expected), "NODE_VERSION_REPORT")
            return expected
        require(parser["mode"] == "NODE_TAP", "PARSER_MODE")
        results, totals, plans = [], {}, []
        for line in stdout.splitlines():
            require(not re.match(r"^\s+(?:not )?ok\s+\d+", line), "NESTED_TAP_UNSUPPORTED")
            require(not line.startswith("Bail out!"), "TAP_BAIL_OUT")
            result = re.fullmatch(r"(ok|not ok) ([0-9]+) - (.+)", line)
            if re.match(r"^(?:not )?ok\b",line): require(result is not None,"MALFORMED_TAP_RESULT")
            if result:
                require(int(result[2]) == len(results)+1 and " # " not in result[3], "AMBIGUOUS_TAP_RESULT")
                results.append({"test_id": result[3], "result": "PASS" if result[1] == "ok" else "FAIL"})
            total = re.fullmatch(r"# (tests|pass|fail|cancelled|skipped|todo) ([0-9]+)", line)
            if total:
                require(total[1] not in totals, "DUPLICATE_TAP_TOTAL"); totals[total[1]] = int(total[2])
            plan = re.fullmatch(r"1\.\.([0-9]+)", line)
            if plan: plans.append(int(plan[1]))
        require(len({row["test_id"] for row in results}) == len(results) and len(plans) == 1
                and plans[0] == len(results) and set(totals) == {"tests", "pass", "fail", "cancelled", "skipped", "todo"}, "TAP_COMPLETENESS")
        require(totals["tests"] == len(results) and totals["pass"] == sum(r["result"] == "PASS" for r in results)
                and totals["fail"] == sum(r["result"] == "FAIL" for r in results), "TAP_RESULT_COUNTS")
        reported = completion.decode("NodeTapReport1", framework_raw).payload()
        require(same(reported["test_results"], results), "TAP_REPORT_SUBSTITUTED")
        counts = reported["counts"]
        require(counts["ran"] == totals["tests"] and counts["passed"] == totals["pass"] and counts["failures"] == totals["fail"]
                and counts["cancelled"] == totals["cancelled"] and counts["skipped"] == totals["skipped"]
                and counts["todo"] == totals["todo"] and counts["errors"] == 0 and reported["complete"] is True, "TAP_REPORT_COUNTS")
        return reported


class CompletionVerifier:
    def __init__(self, *, selection_use, report_use, observation_use, verifier_id,
                 verifier_component_sha256, source_manifest_raw, parser_implementations,
                 registry, clock, current_authority_guard, original_deadline):
        self.selection_use, self.report_use, self.observation_use = [common.decode_canonical(common.canonical_bytes(v)) for v in (selection_use, report_use, observation_use)]
        self.verifier_id, self.component = verifier_id, verifier_component_sha256
        self.source_manifest_raw = bytes(source_manifest_raw)
        self.parsers = dict(parser_implementations)
        self.registry = registry
        self.clock, self.guard = clock, current_authority_guard
        self.deadline = common.decode_canonical(common.canonical_bytes(original_deadline))

    def _now(self, now): return fresh(self.clock, self.guard, now, self.deadline)

    def _resolve(self, use, type_name, *, resolver, publishers, now, binding, limits=None):
        now = self._now(now)
        require(use["required_use"] == "SOURCE_COMPLETION", "COMPLETION_USE")
        require((use["reference"]["record_kind"], use["reference"]["purpose"]) == RECORD_ROUTES[type_name], "COMPLETION_RECORD_ROUTE")
        raw = resolver.resolve(use, selection=publishers, now=now)
        result = completion.decode(type_name, raw, limits=limits).payload()
        if "binding" in result: require(same(result["binding"], binding), "COMPLETION_BINDING")
        self._now(now)
        return result, raw

    @staticmethod
    def _ids(values):
        require(type(values) is list and all(type(v) is str for v in values) and len(set(values)) == len(values), "TEST_ID_UNIQUENESS")
        return sorted(values)

    def _discovery_registration(self, use, *, publishers, now):
        if self.registry is None: raise common.DependencyUnavailable("discovery-registration-reader")
        use=protected.validate("ProtectedReferenceUse",use).payload()
        require(use["required_use"]=="SOURCE_COMPLETION" and use["reference"]["record_kind"]=="TEST_DISCOVERY_REPORT"
                and use["reference"]["purpose"]=="test-discovery-report","DISCOVERY_REGISTRATION_ROUTE")
        current=self._now(now)
        row=self.registry.read_registration(use["registration_sha256"],selection=publishers,now=current)
        row=protected.validate("ProtectedRegistration",row).payload()
        require(common.digest(protected.validate("ProtectedRegistration",row).raw)==use["registration_sha256"]
                and same(row["record_ref"],use["reference"]) and same(row["binding"],publishers["binding"])
                and row["publisher_selection_sha256"]==common.digest(protected.validate("PublisherRootSelection",publishers).raw)
                and row["registry_authority_id"]==publishers["registry_authority_id"],"DISCOVERY_ORIGINAL_REGISTRATION")
        self._now(current)
        return row["registered_at_utc"]

    @staticmethod
    def _discovery_order(*, spawn, discovery, registered, released, exited):
        # released is the observer's execution-release boundary, not process
        # SPAWN and not a child-supplied timestamp or child acknowledgement.
        stamps=[common.utc(value) for value in (spawn,discovery,registered,released,exited)]
        require(all(a<=b for a,b in zip(stamps,stamps[1:])),"DISCOVERY_PUBLICATION_BEFORE_EXECUTION")

    def verify(self, selection, report, observation, *, resolver, publishers, now):
        now = self._now(now)
        selection = completion.validate("CompletionSelection2", selection).payload()
        binding = selection["binding"]
        require(same(binding, publishers["binding"]) and selection["publisher_selection_sha256"] == common.digest(protected.validate("PublisherRootSelection", publishers).raw), "COMPLETION_SELECTION_BINDING")
        for use, name, value in ((self.selection_use, "CompletionSelection2", selection), (self.report_use, "SourceTestReport2", report),
                                 (self.observation_use, "CompletionObservation2", observation)):
            resolved, _ = self._resolve(use, name, resolver=resolver, publishers=publishers, now=now, binding=binding)
            require(same(resolved, value), "COMPLETION_ARGUMENT_SUBSTITUTION")
        require(selection["verifier_id"] == self.verifier_id and selection["verifier_component_sha256"] == self.component, "COMPLETION_VERIFIER_PIN")
        require(common.utc(selection["not_before_utc"]) <= common.utc(now["utc"]) < common.utc(selection["expires_at_utc"]), "COMPLETION_SELECTION_EXPIRED")
        selected_hash = common.digest(completion.validate("CompletionSelection2", selection).raw)
        require(report["selection_sha256"] == observation["selection_sha256"] == selected_hash and report["status"] == "PASS"
                and observation["observer_id"] == selection["observer_id"] and same(report["group_reports"], observation["groups"]), "COMPLETION_REPORT_BINDING")
        clock_record_raw = resolver.resolve(selection["original_clock_ref"], selection=publishers, now=now)
        clock_raw = completion_clock_bytes(clock_record_raw)
        clock = common.decode_canonical(clock_raw)
        require(common.digest(clock_raw) == binding["original_window_sha256"], "ORIGINAL_CLOCK_PIN")
        source_only=clock.get("format")==SOURCE_CLOCK_FORMAT
        if not source_only:
            require(set(clock) == {"model_window", "model_calls", "retry_calls", "bootstrap_started_utc", "test_deadline_utc"},"ORIGINAL_CLOCK_SHAPE")
            require(clock["model_calls"] == 32 and clock["retry_calls"] == 0, "ORIGINAL_CALL_BUDGET")
            window=clock["model_window"]
            require(set(window)=={"started_at","deadline","total_generation_limit","probe_limit","acceptance_limit","includes"}
                    and window["total_generation_limit"]==32 and window["probe_limit"]==2 and window["acceptance_limit"]==30
                    and window["includes"]==["startup","render","tokenize","probes","acceptance","export","shutdown"],"ORIGINAL_WINDOW_DENOMINATOR")
            require(0 < (clock_utc(window["deadline"],window=True)-clock_utc(window["started_at"],window=True)).total_seconds() <= 5400
                    and 0 < (clock_utc(clock["test_deadline_utc"])-clock_utc(clock["bootstrap_started_utc"])).total_seconds() <= 7200
                    and clock_utc(clock["bootstrap_started_utc"]) <= clock_utc(window["started_at"],window=True),"ORIGINAL_WINDOW_LIMITS")
        require(report["original_bootstrap_started_utc"] == clock["bootstrap_started_utc"]
                and report["test_deadline_utc"] == clock["test_deadline_utc"], "TEST_WINDOW_BINDING")
        source_inventory, _ = self._resolve(selection["source_inventory_ref"], "SourceInventory", resolver=resolver, publishers=publishers, now=now, binding=binding)
        require(common.digest(self.source_manifest_raw) == binding["source_manifest_sha256"] == source_inventory["source_manifest_sha256"], "COMPLETE_SOURCE_PIN")
        source_manifest = common.decode_json(self.source_manifest_raw, limit=common.MAX_GRAPH)
        all_files = source_manifest["files"]
        require(len({f["path"] for f in all_files}) == len(all_files), "SOURCE_FILE_DUPLICATE")
        expected_files = {}
        for item in all_files:
            matches = [r for r in source_inventory["test_roots"] if item["path"].startswith(r["source_relative_directory"]+"/")
                       and any(item["path"].endswith(suffix) for suffix in r["suffixes"])]
            require(len(matches) <= 1, "SOURCE_TEST_ROOT_OVERLAP")
            if matches: expected_files[item["path"]] = (item["sha256"], matches[0]["group_id"])
        inventory_files = {f["source_relative_path"]: (f["source_file_sha256"], f["group_id"]) for f in source_inventory["test_files"]}
        require(len(inventory_files) == len(source_inventory["test_files"]) and inventory_files == expected_files, "COMPLETE_TEST_SOURCE_INVENTORY")
        previous_end = clock_utc(clock["bootstrap_started_utc"])
        process_ids, all_test_ids = set(), set()
        for group, group_use in zip(selection["groups"], report["group_reports"], strict=True):
            group_id = group["group_id"]
            command, _ = self._resolve(group["command"], "CommandPin", resolver=resolver, publishers=publishers, now=now, binding=binding)
            parser, _ = self._resolve(group["parser"], "ParserPin", resolver=resolver, publishers=publishers, now=now, binding=binding)
            inventory, _ = self._resolve(group["expected_inventory"], "CollectionInventory", resolver=resolver, publishers=publishers, now=now, binding=binding)
            observed, _ = self._resolve(group_use, "GroupReport2", resolver=resolver, publishers=publishers, now=now, binding=binding)
            observer_uses=[group_use,observed["capture_ref"],observed["stdout_ref"],observed["stderr_ref"],
                           observed["original_framework_report_ref"],observed["discovery_report_ref"],self.observation_use]
            require(all(u["reference"]["publisher_id"]==selection["observer_id"] for u in observer_uses),"SELECTED_COMPLETION_OBSERVER")
            require(command["group_id"] == inventory["group_id"] == observed["group_id"] == group_id and observed["selection_sha256"] == selected_hash, "GROUP_BINDING")
            require(same(observed["command_ref"], group["command"]) and same(observed["parser_ref"], group["parser"])
                    and same(observed["expected_inventory_ref"], group["expected_inventory"]), "GROUP_PIN_SUBSTITUTION")
            require(command["source_manifest_sha256"] == inventory["source_manifest_sha256"] == binding["source_manifest_sha256"]
                    and parser["mode"] == group["mode"], "GROUP_SOURCE_OR_PARSER")
            expected_ids = self._ids([entry["test_id"] for entry in inventory["entries"]])
            require(len(expected_ids) == inventory["expected_count"] == group["expected_test_count"]
                    and inventory["test_ids_sha256"] == common.digest(common.canonical_bytes(expected_ids)), "FROZEN_TEST_DENOMINATOR")
            require(not all_test_ids.intersection(expected_ids), "CROSS_GROUP_TEST_ID"); all_test_ids.update(expected_ids)
            for entry in inventory["entries"]:
                require(inventory_files.get(entry["source_relative_path"]) == (entry["source_file_sha256"], group_id), "TEST_SOURCE_ASSIGNMENT")
            capture, _ = self._resolve(observed["capture_ref"], "ProcessCapture2", resolver=resolver, publishers=publishers, now=now, binding=binding)
            require(capture["group_id"] == group_id and capture["selection_sha256"] == selected_hash
                    and capture["command_sha256"] == command["command_sha256"] and capture["executable_sha256"] == command["executable"]["sha256"], "ACTUAL_COMMAND_PIN")
            start, end = capture["events"]
            require(same(start["process"], end["process"]) and same(start["process"], observed["process"])
                    and common.utc(start["at_utc"]) <= common.utc(observed["started_at_utc"]) and end["at_utc"] == observed["finished_at_utc"]
                    and end["exit_code"] == observed["exit_code"] == 0, "PROCESS_COMPLETION")
            process_key = common.canonical_bytes(observed["process"])
            require(process_key not in process_ids, "REUSED_TEST_PROCESS"); process_ids.add(process_key)
            started, finished = common.utc(observed["started_at_utc"]), common.utc(observed["finished_at_utc"])
            require(previous_end <= common.utc(start["at_utc"]) <= started <= finished <= clock_utc(clock["test_deadline_utc"])
                    and common.utc(selection["not_before_utc"]) <= started <= finished < common.utc(selection["expires_at_utc"]), "TEST_GROUP_TIME")
            previous_end = finished
            streams = {}
            for stream_name, field in (("STDOUT", "stdout_ref"), ("STDERR", "stderr_ref")):
                require(same(capture[field], observed[field]), "STREAM_REFERENCE")
                stream, _ = self._resolve(observed[field], "TestStream2", resolver=resolver, publishers=publishers, now=now,
                    binding=binding, limits=common.ValidationLimits(stream_bytes=parser["maximum_stream_bytes"]))
                require(stream["group_id"] == group_id and same(stream["process"], observed["process"])
                        and stream["stream"] == stream_name and stream["complete"] is True, "STREAM_PROCESS")
                actual = stream["utf8"].encode("utf-8")
                require(stream["bytes"] == len(actual) and common.digest(actual) == stream["raw_sha256"], "RAW_STREAM_PIN")
                streams[stream_name] = stream["utf8"]
            discovery, _ = self._resolve(observed["discovery_report_ref"], "TestDiscoveryReport", resolver=resolver, publishers=publishers, now=now, binding=binding)
            require(discovery["selection_sha256"] == selected_hash and discovery["group_id"] == group_id
                    and discovery["source_inventory_sha256"] == selection["source_inventory_ref"]["reference"]["sha256"]
                    and same(discovery["process"], observed["process"])
                    and common.utc(start["at_utc"]) <= common.utc(discovery["collected_at_utc"]) <= started
                    and self._ids(discovery["collected_test_ids"]) == expected_ids, "INDEPENDENT_DISCOVERY")
            registered=self._discovery_registration(observed["discovery_report_ref"],publishers=publishers,now=now)
            self._discovery_order(spawn=start["at_utc"],discovery=discovery["collected_at_utc"],registered=registered,
                                  released=observed["started_at_utc"],exited=end["at_utc"])
            raw_framework = resolver.resolve(observed["original_framework_report_ref"], selection=publishers, now=now)
            framework_ref = observed["original_framework_report_ref"]
            require(framework_ref["required_use"] == "SOURCE_COMPLETION" and framework_ref["reference"]["record_kind"] == "TEST_FRAMEWORK_REPORT"
                    and framework_ref["reference"]["purpose"] == "test-framework-report", "FRAMEWORK_REPORT_ROUTE")
            fr=framework_ref["reference"]
            grants=[g for p in publishers["publishers"] if p["publisher_id"]==fr["publisher_id"] for g in p["grants"]
                    if g["root_id"]==fr["root_id"] and g["record_kind"]==fr["record_kind"] and g["purpose"]==fr["purpose"]
                    and g["permitted_use"]=="SOURCE_COMPLETION"]
            require(len(grants)==1 and grants[0]["payload_schema_sha256"]==parser["report_schema_sha256"],"FRAMEWORK_SCHEMA_PIN")
            implementation = self.parsers.get((parser["component_manifest_sha256"], parser["entrypoint"]))
            if implementation is None: raise common.DependencyUnavailable("selected-framework-parser")
            framework = implementation.parse(parser, stdout=streams["STDOUT"], stderr=streams["STDERR"], framework_raw=raw_framework, group_id=group_id)
            require(framework["group_id"]==group_id and framework["format"]==parser["accepted_report_format"],"FRAMEWORK_FORMAT_AND_GROUP")
            require(self._ids(observed["collected_test_ids"]) == expected_ids and self._ids(observed["executed_test_ids"]) == expected_ids, "OBSERVED_TEST_MEMBERSHIP")
            counts = observed["counts"]
            require(all(counts[k] == 0 for k in ("skipped", "failures", "errors", "cancelled", "todo")), "TEST_FAILURE_OR_SKIP")
            if group["mode"] == "NODE_VERSION":
                require(not expected_ids and all(v == 0 for v in counts.values()) and observed["node_version_utf8"] == streams["STDOUT"]
                        and streams["STDOUT"] == parser["expected_stdout_utf8"] and streams["STDERR"] == parser["expected_stderr_utf8"], "NODE_VERSION_EXACT")
            else:
                require(expected_ids and observed["node_version_utf8"] is None and counts["discovered"] == counts["ran"] == counts["passed"] == len(expected_ids), "TEST_COUNTERS")
                require(same(framework["counts"], counts) and self._ids(framework["collected_test_ids"]) == expected_ids, "FRAMEWORK_MEMBERSHIP")
                executed = framework["executed_test_ids"] if group["mode"] == "PYTHON_METHODS" else [r["test_id"] for r in framework["test_results"]]
                require(self._ids(executed) == expected_ids, "FRAMEWORK_EXECUTED_IDS")
                if group["mode"] == "PYTHON_METHODS": require(framework["status"] == "PASS", "FRAMEWORK_FAILURE")
                else: require(all(row["result"] == "PASS" for row in framework["test_results"]), "TAP_FAILURE")
            self._now(now)
        completed = report["finished_utc"]
        cutoff=clock_utc(clock["test_deadline_utc"]) if source_only else clock_utc(clock["model_window"]["started_at"],window=True)
        require(common.utc(completed) == previous_end and observation["completed_at_utc"] == completed
                and previous_end <= cutoff, "COMPLETION_BEFORE_ORIGINAL_CUTOFF")
        result = {"format": "forex.observed-source-test-completion/2", "binding": binding, "selection_ref": self.selection_use,
            "observer_id": selection["observer_id"], "verifier_id": self.verifier_id, "verifier_component_sha256": self.component,
            "original_clock_record_content_sha256": common.digest(clock_raw), "completed_at_utc": completed,
            "original_source_test_report": self.report_use, "observation_evidence": self.observation_use,
            "group_reports_sha256": common.digest(common.canonical_bytes(report["group_reports"]))}
        now = self._now(now)
        require(common.utc(now["utc"]) < common.utc(selection["expires_at_utc"]), "COMPLETION_EXPIRED_AT_RETURN")
        return completion.validate("CompletionReceipt2", result).payload()
