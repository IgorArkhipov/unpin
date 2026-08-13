import CryptoKit
import Foundation
import XCTest
@testable import UnpinDesktop

final class BridgeClientTests: XCTestCase {
    func testBundledBridgeCompletesHandshake() async throws {
        let executable = Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("unpin")
        let manifestURL = try XCTUnwrap(Bundle.main.url(
            forResource: "unpin-bridge-manifest",
            withExtension: "json"
        ))
        let manifest = try JSONDecoder().decode(
            BundledBridgeManifest.self,
            from: Data(contentsOf: manifestURL)
        )
        let projectRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-desktop-handshake-\(UUID().uuidString)", isDirectory: true)
        let fixtureRoot = projectRoot.appendingPathComponent("fixtures", isDirectory: true)
        let appStateRoot = projectRoot.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(at: projectRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: appStateRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: projectRoot) }

        let bridge = BridgeClient(
            executableURL: executable,
            projectRoot: projectRoot,
            manifest: manifest,
            roots: BridgeLaunchRoots(
                fixtureRoot: fixtureRoot,
                homeRoot: fixtureRoot,
                appStateRoot: appStateRoot
            )
        )

        do {
            try await bridge.start()
            let handshake = try await bridge.handshake()
            XCTAssertEqual(handshake.protocolVersion, BridgeClient.protocolVersion)
            XCTAssertEqual(handshake.binaryVersion, manifest.unpinVersion)
            let stopped = await bridge.stop()
            XCTAssertTrue(stopped)
        } catch {
            _ = await bridge.stop()
            throw error
        }
    }

    func testStartRejectsManifestDigestMismatch() async throws {
        let temporary = try temporaryExecutable(script: "#!/bin/sh\nexit 0\n")
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: String(repeating: "0", count: 64)
            )
        )

        do {
            try await bridge.start()
            XCTFail("digest mismatch should fail before launch")
        } catch BridgeClientError.bundleIntegrityMismatch {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testHandshakeRejectsBinaryVersionMismatch() async throws {
        let script = """
        #!/bin/sh
        IFS= read -r request
        printf '%s\\n' '{"version":2,"id":"desktop-1","result":{"protocolVersion":2,"binaryVersion":"0.6.2","capabilities":[]}}'
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            )
        )

        do {
            try await bridge.start()
            _ = try await bridge.handshake()
            XCTFail("binary version mismatch should fail the handshake")
        } catch BridgeClientError.incompatibleBinary {
            // Expected.
        } catch {
            _ = await bridge.stop()
            XCTFail("unexpected error: \(error)")
        }
    }

    func testHandshakeRejectsPartialAgentPluginCapabilities() async throws {
        let script = """
        #!/bin/sh
        IFS= read -r request
        printf '%s\\n' '{"version":2,"id":"desktop-1","result":{"protocolVersion":2,"binaryVersion":"1.0.0","capabilities":["agentPlugins.plan","agentPlugins.approve","agentPlugins.apply","agentPlugins.discard"]}}'
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            )
        )

        do {
            try await bridge.start()
            _ = try await bridge.handshake()
            XCTFail("partial Agent Plugin capabilities should fail handshake")
        } catch BridgeClientError.incompatibleCapabilities {
            // Expected.
        } catch {
            _ = await bridge.stop()
            XCTFail("unexpected error: \(error)")
        }
    }

    func testSnapshotRequiresAgentPluginInventoryFields() {
        let snapshot = """
        {"capturedAtUnix":0,"inventory":[],"warnings":[],"groups":[],"groupWarnings":[]}
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(BridgeSnapshot.self, from: Data(snapshot.utf8))
        )
    }

    func testAgentPluginInstanceUsesOpaqueBridgeIdentity() throws {
        let instance = """
        {"instanceId":"agent-plugin-instance:claude:global:abc123","provider":"claude","layer":"global","state":"on","access":"actionable","version":"1.0.0","components":[],"activations":[],"blockers":[],"diagnostics":[]}
        """

        let decoded = try JSONDecoder().decode(AgentPluginInstance.self, from: Data(instance.utf8))
        XCTAssertEqual(decoded.id, "agent-plugin-instance:claude:global:abc123")
    }

    func testStalledControlTimeoutStopsChildAndAllowsRestart() async throws {
        let script = """
        #!/bin/sh
        while IFS= read -r request; do
            case "$request" in
                *group.approve*)
                        case "$request" in
                            *'"auth"'*) ;;
                            *) exit 42 ;;
                        esac
                        case "$request" in
                            *'"parentPid"'*) ;;
                            *) exit 42 ;;
                        esac
                        case "$request" in
                            *'"authTag"'*) ;;
                            *) exit 42 ;;
                        esac
                    while :; do sleep 1; done
                    ;;
                *handshake*)
                    id=$(printf '%s' "$request" | sed -n 's/.*"id":"\\([^"]*\\)".*/\\1/p')
                    parent_pid=$(printf '%s' "$request" | sed -n 's/.*"parentPid":\\([0-9]*\\).*/\\1/p')
                    parent_marker=$(printf '%s' "$request" | sed -n 's/.*"parentStartMarker":"\\([^"]*\\)".*/\\1/p')
                    child_pid=$(printf '%s' "$request" | sed -n 's/.*"childPid":\\([0-9]*\\).*/\\1/p')
                    generation=$(printf '%s' "$request" | sed -n 's/.*"processGeneration":"\\([^"]*\\)".*/\\1/p')
                    project_root=$(printf '%s' "$request" | sed -n 's/.*"projectRoot":"\\([^"]*\\)".*/\\1/p')
                    app_state_root=$(printf '%s' "$request" | sed -n 's/.*"appStateRoot":"\\([^"]*\\)".*/\\1/p')
                    printf '%s\\n' '{"version":2,"id":"'"$id"'","result":{"protocolVersion":2,"binaryVersion":"1.0.0","capabilities":["agentPlugins.inspect","agentPlugins.plan","agentPlugins.approve","agentPlugins.apply","agentPlugins.discard","workflow.compose","workflow.validate","workflow.propose","workflow.launch","workflow.transition","workflow.observe","workflow.cancel-transition","workflow.status","workflow.recovery"],"binding":{"parentPid":'"$parent_pid"',"parentStartMarker":"'"$parent_marker"'","childPid":'"$child_pid"',"childStartMarker":"fake-child-start","projectRoot":"'"$project_root"'","appStateRoot":"'"$app_state_root"'","processGeneration":"'"$generation"'"}}}'
                    ;;
            esac
        done
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            ),
            controlRequestTimeoutMilliseconds: 50
        )

        try await bridge.start()
        _ = try await bridge.handshake()
        do {
            _ = try await bridge.approveGroup(operationID: "operation", fingerprint: "fingerprint")
            XCTFail("a stalled control request must not complete")
        } catch BridgeClientError.controlRequestUncertain {
            // The child was stopped because the mutation outcome is uncertain.
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        try await bridge.start()
        let handshake = try await bridge.handshake()
        XCTAssertEqual(handshake.binaryVersion, "1.0.0")
        let stopped = await bridge.stop()
        XCTAssertTrue(stopped)
    }

    func testStalledControlTimeoutKillsChildIgnoringSigterm() async throws {
        let script = """
        #!/bin/sh
        trap '' TERM
        while IFS= read -r request; do
            case "$request" in
                *group.approve*)
                        case "$request" in
                            *'"auth"'*) ;;
                            *) exit 42 ;;
                        esac
                        case "$request" in
                            *'"parentPid"'*) ;;
                            *) exit 42 ;;
                        esac
                        case "$request" in
                            *'"authTag"'*) ;;
                            *) exit 42 ;;
                        esac
                    while :; do :; done
                    ;;
                *handshake*)
                    id=$(printf '%s' "$request" | sed -n 's/.*"id":"\\([^"]*\\)".*/\\1/p')
                    parent_pid=$(printf '%s' "$request" | sed -n 's/.*"parentPid":\\([0-9]*\\).*/\\1/p')
                    parent_marker=$(printf '%s' "$request" | sed -n 's/.*"parentStartMarker":"\\([^"]*\\)".*/\\1/p')
                    child_pid=$(printf '%s' "$request" | sed -n 's/.*"childPid":\\([0-9]*\\).*/\\1/p')
                    generation=$(printf '%s' "$request" | sed -n 's/.*"processGeneration":"\\([^"]*\\)".*/\\1/p')
                    project_root=$(printf '%s' "$request" | sed -n 's/.*"projectRoot":"\\([^"]*\\)".*/\\1/p')
                    app_state_root=$(printf '%s' "$request" | sed -n 's/.*"appStateRoot":"\\([^"]*\\)".*/\\1/p')
                    printf '%s\\n' '{"version":2,"id":"'"$id"'","result":{"protocolVersion":2,"binaryVersion":"1.0.0","capabilities":["agentPlugins.inspect","agentPlugins.plan","agentPlugins.approve","agentPlugins.apply","agentPlugins.discard","workflow.compose","workflow.validate","workflow.propose","workflow.launch","workflow.transition","workflow.observe","workflow.cancel-transition","workflow.status","workflow.recovery"],"binding":{"parentPid":'"$parent_pid"',"parentStartMarker":"'"$parent_marker"'","childPid":'"$child_pid"',"childStartMarker":"fake-child-start","projectRoot":"'"$project_root"'","appStateRoot":"'"$app_state_root"'","processGeneration":"'"$generation"'"}}}'
                    ;;
            esac
        done
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            ),
            controlRequestTimeoutMilliseconds: 50,
            terminationPolicy: BridgeTerminationPolicy(
                gracePeriodNanoseconds: 10_000_000,
                settlePeriodNanoseconds: 10_000_000
            )
        )

        try await bridge.start()
        _ = try await bridge.handshake()
        do {
            _ = try await bridge.approveGroup(operationID: "operation", fingerprint: "fingerprint")
            XCTFail("a stalled control request must not complete")
        } catch BridgeClientError.controlRequestUncertain {
            // SIGTERM is ignored; forceStop must escalate to SIGKILL and return.
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        try await bridge.start()
        let handshake = try await bridge.handshake()
        XCTAssertEqual(handshake.binaryVersion, "1.0.0")
        let stopped = await bridge.stop()
        XCTAssertTrue(stopped)
    }

    func testIncompatibleGroupDefaultsMissingMembersToEmpty() throws {
        let data = Data(#"""
        {
          "qualifiedName": "personal:incompatible",
          "scope": "personal",
          "revision": "revision-1",
          "contextCompatible": false,
          "state": null,
          "fresh": true
        }
        """#.utf8)

        let group = try JSONDecoder().decode(GroupSummary.self, from: data)

        XCTAssertFalse(group.contextCompatible)
        XCTAssertTrue(group.members.isEmpty)
    }

    func testProviderReachDecodesAllAndSelected() throws {
        let all = try JSONDecoder().decode(
            ProviderReachValue.self,
            from: Data("\"all\"".utf8)
        )
        XCTAssertEqual(all, .all)

        let selected = try JSONDecoder().decode(
            ProviderReachValue.self,
            from: Data(#"""
            {"selected":{"provider":"codex","provenance":"explicit-input"}}
            """#.utf8)
        )
        XCTAssertEqual(selected, .selected(provider: "codex", provenance: "explicit-input"))

        let plan = try JSONDecoder().decode(
            GroupPlan.self,
            from: Data(#"""
            {
              "operationId": null,
              "disposition": "actionable",
              "mode": "native",
              "qualifiedName": "personal:example",
              "scope": "personal",
              "groupRevision": "revision-1",
              "target": "enable",
              "totalMembers": 0,
              "providerReach": {"selected":{"provider":"codex","provenance":"explicit-input"}},
              "providerCoverage": {"entries":[]},
              "lifecycle": "planned",
              "members": [],
              "resources": [],
              "cohorts": [],
              "planFingerprint": "fingerprint"
            }
            """#.utf8)
        )
        XCTAssertEqual(plan.providerReach, "selected · codex · explicit-input")
        XCTAssertEqual(plan.$providerReach, selected)
    }

    func testRecoveryOperationAllowsMissingProviderReach() throws {
        let operation = try JSONDecoder().decode(
            RecoveryOperation.self,
            from: Data(#"""
            {
              "operationId": "operation-1",
              "operationKind": "group-toggle",
              "lifecycle": "planned",
              "recoveryRequired": false,
              "resourceCount": 0
            }
            """#.utf8)
        )

        XCTAssertNil(operation.providerReach)
    }

    func testAgentPluginSnapshotAndPlanDTOsDecodeRedactedContract() throws {
        let snapshot = try JSONDecoder().decode(
            BridgeSnapshot.self,
            from: Data(#"""
            {
              "capturedAtUnix": 1,
              "inventory": [],
              "warnings": [],
              "groups": [],
              "groupWarnings": [],
              "agentPluginInventoryComplete": true,
              "agentPlugins": [{
                "logicalId": "agent-plugin:connector-kit:abc",
                "name": "connector-kit",
                "componentSignature": "mcp+skill",
                "projectionFingerprint": "sha256:projection",
                "state": "mixed",
                "access": "actionable",
                "providers": ["claude", "codex"],
                "componentKinds": ["mcp", "skill"],
                "instanceCount": 1,
                "instances": [{
                  "instanceId": "instance-connector-kit-codex-global",
                  "provider": "codex",
                  "layer": "global",
                  "state": "on",
                  "access": "actionable",
                  "version": "1.0.0",
                  "description": "Portable connector tools",
                  "components": [{"kind":"skill","name":"review","disposition":"available","reason":null}],
                  "activations": [{"enabled":true,"mutability":"read-write"}],
                  "blockers": [],
                  "diagnostics": []
                }]
              }]
            }
            """#.utf8)
        )
        let package = try XCTUnwrap(snapshot.agentPlugins.first)
        XCTAssertEqual(package.providerDisplay, "claude, codex")
        XCTAssertEqual(package.typeDisplay, "mcp + skill")
        XCTAssertEqual(package.instances.first?.activations.first?.mutability, "read-write")

        let envelope = try JSONDecoder().decode(
            AgentPluginPlanEnvelope.self,
            from: Data(#"""
            {"plan":{
              "logicalId":"agent-plugin:connector-kit:abc",
              "name":"connector-kit",
              "componentSignature":"mcp+skill",
              "projectionFingerprint":"sha256:projection",
              "state":"mixed",
              "access":"actionable",
              "providers":["claude","codex"],
              "componentKinds":["mcp","skill"],
              "instanceCount":0,
              "instances":[],
              "operationId":"bulk-toggle-abc",
              "planFingerprint":"sha256:plan",
              "target":"off",
              "providerReach":{"selected":{"provider":"codex","provenance":"explicit-input"}},
              "coverage":[{"provider":"codex","included":1,"excluded":0,"reasonCodes":[]}],
              "lifecycle":"applied",
              "counts":{"instances":2,"activations":2,"components":4,"diagnostics":0,"included":1,"writes":1,"noOp":0,"blocked":0,"reachExcluded":1},
              "review":{"included":[{"provider":"codex","layer":"global","outcome":"applied"}],"noOp":[],"blocked":[],"reachExcluded":[{"provider":"claude","layer":"global","activationCount":1,"reasonCode":"outside-selected-provider-reach"}],"componentDiagnostics":[]}
            }}
            """#.utf8)
        )
        XCTAssertEqual(envelope.plan.target, "off")
        XCTAssertEqual(envelope.plan.providerReach, "selected · codex · explicit-input")
        XCTAssertEqual(envelope.plan.counts.reachExcluded, 1)
        XCTAssertEqual(envelope.plan.review.included.first?.outcome, "applied")
    }

    func testWorkflowProposalDecodesCoreContract() throws {
        let proposal = try JSONDecoder().decode(
            WorkflowProposalEnvelope.self,
            from: Data(#"""
            {
              "status": "proposed",
              "proposal": {
                "schemaVersion": 1,
                "proposalId": "workflow-proposal-abc123",
                "proposalFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "workflowId": "delivery",
                "entryMode": "implementation",
                "provider": "codex",
                "repositoryKey": "repository-key",
                "workspaceKey": "workspace-key",
                "catalogRevision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "workflowRevision": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "promptDigest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "capabilityCount": 3,
                "gatewayRequired": true,
                "reloadLimitation": "live-refresh-expected",
                "approvalExpectation": "explicit-confirmation-required",
                "nextAction": "confirm-workflow-session"
              },
              "candidates": [{
                "workflowId": "delivery",
                "displayName": "Delivery",
                "scope": "workspace",
                "score": 4,
                "entryMode": "implementation"
              }],
              "confirmationRequired": true
            }
            """#.utf8)
        )

        XCTAssertEqual(proposal.status, "proposed")
        XCTAssertEqual(proposal.proposal?.workflowId, "delivery")
        XCTAssertEqual(proposal.proposal?.reloadLimitation, "live-refresh-expected")
        XCTAssertEqual(proposal.candidates.first?.entryMode, "implementation")
        XCTAssertEqual(proposal.confirmationRequired, true)
    }

    func testWorkflowSessionAndTransitionDecodeRouterState() throws {
        let envelope = try JSONDecoder().decode(
            WorkflowTransitionEnvelope.self,
            from: Data(#"""
            {
              "result": {
                "transition": {
                  "operationId": "workflow-transition-1",
                  "lifecycle": "staged",
                  "reasonCode": "workflow-transition-staged",
                  "previousMode": "planning",
                  "desiredMode": "implementation",
                  "previousExposureRevision": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                  "desiredExposureRevision": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                  "leaseStateSequence": 8,
                  "nextAction": "observe-or-cancel-transition"
                },
                "refreshOutcome": "notification-sent"
              },
              "session": {
                "sessionId": "session-1",
                "workflowId": "delivery",
                "proposalId": "workflow-proposal-abc123",
                "activeMode": "implementation",
                "observedMode": "planning",
                "desiredExposureRevision": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "observedExposureRevision": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "stateSequence": 8,
                "liveStatus": "reload-required",
                "admissionOpen": false,
                "operationHistory": []
              },
              "status": {
                "sessionId": "session-1",
                "workflowId": "delivery",
                "activeMode": "implementation",
                "desiredMode": "implementation",
                "observedMode": "planning",
                "stateSequence": 8,
                "liveStatus": "notification-sent",
                "admissionOpen": false,
                "recoveryRequired": false
              }
            }
            """#.utf8)
        )

        XCTAssertEqual(envelope.result?.lifecycle, "staged")
        XCTAssertEqual(envelope.refreshOutcome, "notification-sent")
        XCTAssertEqual(envelope.result?.desiredMode, "implementation")
        XCTAssertEqual(envelope.result?.leaseStateSequence, 8)
        XCTAssertEqual(envelope.session?.id, "session-1")
        XCTAssertEqual(envelope.session?.liveStatus, "reload-required")
        XCTAssertEqual(envelope.status?.liveStatus, "notification-sent")
    }

    func testWorkflowStatusDecodesHydratedDefinitionsAndDurableOperations() throws {
        let envelope = try JSONDecoder().decode(
            WorkflowStatusEnvelope.self,
            from: Data(#"""
            {
              "status": {
                "sessionId": "session-1",
                "workflowId": "delivery",
                "activeMode": "planning",
                "desiredMode": "implementation",
                "observedMode": "planning",
                "stateSequence": 8,
                "liveStatus": "notification-sent",
                "admissionOpen": false,
                "recoveryRequired": false
              },
              "session": {
                "sessionId": "session-1",
                "workflowId": "delivery",
                "proposalId": "proposal-1",
                "activeMode": "planning",
                "observedMode": "planning",
                "desiredExposureRevision": "revision-2",
                "observedExposureRevision": "revision-1",
                "stateSequence": 8,
                "liveStatus": "notification-sent",
                "admissionOpen": false,
                "operationHistory": [{
                  "operationId": "transition-1",
                  "lifecycle": "staged",
                  "reasonCode": "workflow-transition-staged",
                  "sourceMode": "planning",
                  "targetMode": "implementation",
                  "sourceStateSequence": 7,
                  "targetStateSequence": 8,
                  "operationFingerprint": "fingerprint-1"
                }]
              },
              "workflows": [{
                "workflowId": "delivery",
                "displayName": "Delivery",
                "description": "Plan and implement",
                "provider": "codex",
                "baselineProfileId": "baseline",
                "entryMode": "planning",
                "modes": [{"name": "planning", "profileId": "planning"}, {"name": "implementation", "profileId": "implementation"}],
                "workflowRevision": "revision-workflow"
              }],
              "selectedWorkflowId": "delivery",
              "operations": [{
                "operationId": "transition-1",
                "lifecycle": "staged",
                "reasonCode": "workflow-transition-staged",
                "sourceMode": "planning",
                "targetMode": "implementation",
                "sourceStateSequence": 7,
                "targetStateSequence": 8,
                "operationFingerprint": "fingerprint-1"
              }],
              "liveStatus": "notification-sent",
              "recoveryRequired": false
            }
            """#.utf8)
        )

        XCTAssertEqual(envelope.workflows.map(\.workflowId), ["delivery"])
        XCTAssertEqual(envelope.workflow?.workflowId, nil)
        XCTAssertEqual(envelope.selectedWorkflowId, "delivery")
        XCTAssertEqual(envelope.status?.liveStatus, "notification-sent")
        XCTAssertEqual(envelope.session?.operationHistory.first?.operationId, "transition-1")
        XCTAssertEqual(envelope.operations.first?.lifecycle, "staged")
    }

    func testWorkflowHandshakeBindingDecodesProcessBinding() throws {
        let handshake = try JSONDecoder().decode(
            BridgeHandshake.self,
            from: Data(#"""
            {
              "protocolVersion": 2,
              "binaryVersion": "1.0.0",
              "capabilities": ["workflow.status"],
              "binding": {
                "parentPid": 12,
                "parentStartMarker": "parent-start",
                "childPid": 34,
                "childStartMarker": "child-start",
                "projectRoot": "/tmp/workspace",
                "appStateRoot": "/tmp/state",
                "processGeneration": "generation"
              }
            }
            """#.utf8)
        )

        XCTAssertEqual(handshake.binding?.childPid, 34)
        XCTAssertEqual(handshake.binding?.childStartMarker, "child-start")
        XCTAssertEqual(handshake.binding?.processGeneration, "generation")
    }

    func testWorkflowLaunchParametersEncodeHostCommandAsArgv() throws {
        let encoded = try JSONEncoder().encode(WorkflowLaunchParameters(
            proposalId: "workflow-proposal-abc123",
            proposalFingerprint: String(repeating: "a", count: 64),
            hostCommand: ["codex", "--profile", "delivery"]
        ))
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        XCTAssertEqual(
            object["hostCommand"] as? [String],
            ["codex", "--profile", "delivery"]
        )
    }

    func testWorkflowLaunchAndStatusUseAuthenticatedChildHostCommand() async throws {
        let script = """
        #!/bin/sh
        while IFS= read -r request; do
            printf '%s\\n' "$request" >> /tmp/unpin-workflow-request.log
            case "$request" in
                *workflow.launch*)
                    case "$request" in
                        *'"auth"'*) ;;
                        *) exit 42 ;;
                    esac
                    case "$request" in
                        *'"parentPid"'*) ;;
                        *) exit 45 ;;
                    esac
                    case "$request" in
                        *'"authTag"'*) ;;
                        *) exit 46 ;;
                    esac
                    case "$request" in
                        *'"hostCommand":["codex","--profile","delivery"]'*) ;;
                        *) exit 44 ;;
                    esac
                    id=$(printf '%s' "$request" | sed -n 's/.*"id":"\\([^"\\]*\\)".*/\\1/p')
                    printf '%s\\n' '{"version":2,"id":"'"$id"'","result":{"status":"launched","session":{"sessionId":"session-1","workflowId":"delivery","proposalId":"workflow-proposal-abc123","activeMode":"implementation","observedMode":"implementation","desiredExposureRevision":"revision-1","observedExposureRevision":"revision-1","stateSequence":1,"liveStatus":"running","admissionOpen":true,"operationHistory":[]}}}'
                    ;;
                *workflow.status*)
                    case "$request" in
                        *'"auth"'*) ;;
                        *) exit 43 ;;
                    esac
                    case "$request" in
                        *'"parentPid"'*) ;;
                        *) exit 47 ;;
                    esac
                    case "$request" in
                        *'"authTag"'*) ;;
                        *) exit 48 ;;
                    esac
                    id=$(printf '%s' "$request" | sed -n 's/.*"id":"\\([^"\\]*\\)".*/\\1/p')
                    printf '%s\\n' '{"version":2,"id":"'"$id"'","result":{"session":{"sessionId":"session-1","workflowId":"delivery","proposalId":"workflow-proposal-abc123","activeMode":"implementation","observedMode":"implementation","desiredExposureRevision":"revision-1","observedExposureRevision":"revision-1","stateSequence":1,"liveStatus":"running","admissionOpen":true,"operationHistory":[]},"status":{"sessionId":"session-1","workflowId":"delivery","activeMode":"implementation","desiredMode":null,"observedMode":"implementation","stateSequence":1,"liveStatus":"running","admissionOpen":true,"recoveryRequired":false},"operations":[],"liveStatus":"running","recoveryRequired":false}}'
                    ;;
                *handshake*)
                    id=$(printf '%s' "$request" | sed -n 's/.*"id":"\\([^"\\]*\\)".*/\\1/p')
                    parent_pid=$(printf '%s' "$request" | sed -n 's/.*"parentPid":\\([0-9]*\\).*/\\1/p')
                    parent_marker=$(printf '%s' "$request" | sed -n 's/.*"parentStartMarker":"\\([^"]*\\)".*/\\1/p')
                    child_pid=$(printf '%s' "$request" | sed -n 's/.*"childPid":\\([0-9]*\\).*/\\1/p')
                    generation=$(printf '%s' "$request" | sed -n 's/.*"processGeneration":"\\([^"]*\\)".*/\\1/p')
                    project_root=$(printf '%s' "$request" | sed -n 's/.*"projectRoot":"\\([^"]*\\)".*/\\1/p')
                    app_state_root=$(printf '%s' "$request" | sed -n 's/.*"appStateRoot":"\\([^"]*\\)".*/\\1/p')
                    printf '%s\\n' '{"version":2,"id":"'"$id"'","result":{"protocolVersion":2,"binaryVersion":"1.0.0","capabilities":["agentPlugins.inspect","agentPlugins.plan","agentPlugins.approve","agentPlugins.apply","agentPlugins.discard","workflow.compose","workflow.validate","workflow.propose","workflow.launch","workflow.transition","workflow.observe","workflow.cancel-transition","workflow.status","workflow.recovery"],"binding":{"parentPid":'"$parent_pid"',"parentStartMarker":"'"$parent_marker"'","childPid":'"$child_pid"',"childStartMarker":"fake-child-start","projectRoot":"'"$project_root"'","appStateRoot":"'"$app_state_root"'","processGeneration":"'"$generation"'"}}}'
                    ;;
            esac
        done
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            )
        )

        try await bridge.start()
        _ = try await bridge.handshake()
        let launch = try await bridge.launchWorkflow(WorkflowLaunchParameters(
            proposalId: "workflow-proposal-abc123",
            proposalFingerprint: String(repeating: "a", count: 64),
            hostCommand: ["codex", "--profile", "delivery"]
        ))
        XCTAssertEqual(launch.status, "launched")
        XCTAssertEqual(launch.session?.id, "session-1")

        let status = try await bridge.workflowStatus()
        XCTAssertEqual(status.session?.id, "session-1")
        XCTAssertEqual(status.status?.liveStatus, "running")
        XCTAssertEqual(status.liveStatus, "running")
        _ = await bridge.stop()
    }

    private func temporaryExecutable(script: String) throws -> (root: URL, executable: URL) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-bridge-client-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let executable = root.appendingPathComponent("unpin-test-bridge")
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: executable.path
        )
        return (root, executable)
    }
}
