import XCTest
import NIO
import NIOSSH
@testable import Citadel

final class KeyboardInteractiveTests: XCTestCase {
    /// Verifies that `combine` sequences methods in order and that the second
    /// offer is keyboard-interactive when the server advertises both methods.
    func testCombineOffersPasswordThenKeyboardInteractive() throws {
        let eventLoop = EmbeddedEventLoop()
        defer { try? eventLoop.syncShutdownGracefully() }

        let combined = SSHAuthenticationMethod.combine([
            .passwordBased(username: "u", password: "p"),
            .keyboardInteractive(username: "u") { _ in
                eventLoop.makeSucceededFuture(["123456"])
            },
        ])

        let availableMethods: NIOSSHAvailableUserAuthenticationMethods = [.password, .keyboardInteractive]

        // --- First offer: expect password ---
        let promise1 = eventLoop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        combined.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: promise1)
        eventLoop.run()

        var capturedOffer1: NIOSSHUserAuthenticationOffer?
        var capturedError1: Error?
        promise1.futureResult.whenSuccess { capturedOffer1 = $0 }
        promise1.futureResult.whenFailure { capturedError1 = $0 }
        eventLoop.run()

        XCTAssertNil(capturedError1, "First offer should not fail; got: \(String(describing: capturedError1))")
        XCTAssertNotNil(capturedOffer1, "First offer should be non-nil")
        if case .password = capturedOffer1?.offer {
            // expected
        } else {
            XCTFail("Expected first offer to be .password, got \(String(describing: capturedOffer1?.offer))")
        }

        // --- Second offer: expect keyboardInteractive ---
        let promise2 = eventLoop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        combined.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: promise2)
        eventLoop.run()

        var capturedOffer2: NIOSSHUserAuthenticationOffer?
        var capturedError2: Error?
        promise2.futureResult.whenSuccess { capturedOffer2 = $0 }
        promise2.futureResult.whenFailure { capturedError2 = $0 }
        eventLoop.run()

        XCTAssertNil(capturedError2, "Second offer should not fail; got: \(String(describing: capturedError2))")
        XCTAssertNotNil(capturedOffer2, "Second offer should be non-nil")
        if case .keyboardInteractive = capturedOffer2?.offer {
            // expected
        } else {
            XCTFail("Expected second offer to be .keyboardInteractive, got \(String(describing: capturedOffer2?.offer))")
        }
    }

    /// Verifies that `nextKeyboardInteractiveResponse` routes the challenge to the
    /// `onChallenge` closure and that the response is cascaded to the promise.
    /// Dispatches through `any NIOSSHClientUserAuthenticationDelegate` (the existential)
    /// to prove witness-table dispatch reaches the override — not just concrete-type dispatch.
    func testChallengeResponseRouting() throws {
        let eventLoop = EmbeddedEventLoop()
        defer { try? eventLoop.syncShutdownGracefully() }

        let expectedResponse = ["654321"]
        let method = SSHAuthenticationMethod.keyboardInteractive(username: "u") { challenge in
            XCTAssertEqual(challenge.name, "OTP")
            XCTAssertEqual(challenge.instruction, "Enter your code")
            XCTAssertEqual(challenge.prompts.count, 1)
            XCTAssertEqual(challenge.prompts[0].prompt, "Code: ")
            XCTAssertFalse(challenge.prompts[0].echo)
            return eventLoop.makeSucceededFuture(expectedResponse)
        }

        // Call through the existential to prove witness-table dispatch reaches the override.
        let delegate: any NIOSSHClientUserAuthenticationDelegate = method
        let responsePromise = eventLoop.makePromise(of: [String]?.self)
        delegate.nextKeyboardInteractiveResponse(
            name: "OTP",
            instruction: "Enter your code",
            prompts: [NIOSSHKeyboardInteractivePromptField(prompt: "Code: ", echo: false)],
            responsePromise: responsePromise
        )
        eventLoop.run()

        var result: [String]??
        responsePromise.futureResult.whenSuccess { result = $0 }
        eventLoop.run()

        XCTAssertEqual(result, .some(expectedResponse))
    }

    /// Verifies that a method with no KI implementation returns nil (abort) when
    /// `nextKeyboardInteractiveResponse` is called on it.
    /// Dispatches through `any NIOSSHClientUserAuthenticationDelegate` (the existential)
    /// to prove witness-table dispatch reaches the override for the non-KI case too.
    func testNonKIMethodReturnsNilForChallenge() throws {
        let eventLoop = EmbeddedEventLoop()
        defer { try? eventLoop.syncShutdownGracefully() }

        let method = SSHAuthenticationMethod.passwordBased(username: "u", password: "p")

        // Call through the existential to prove witness-table dispatch reaches the override.
        let delegate: any NIOSSHClientUserAuthenticationDelegate = method
        let responsePromise = eventLoop.makePromise(of: [String]?.self)
        delegate.nextKeyboardInteractiveResponse(
            name: "OTP",
            instruction: "Enter your code",
            prompts: [NIOSSHKeyboardInteractivePromptField(prompt: "Code: ", echo: false)],
            responsePromise: responsePromise
        )
        eventLoop.run()

        var result: [String]??
        responsePromise.futureResult.whenSuccess { result = $0 }
        eventLoop.run()

        // .some(nil) means the future succeeded with nil (abort signal)
        XCTAssertEqual(result, .some(nil))
    }

    /// Verifies that a combined object routes KI challenges to the correct implementation
    /// when called through the `any NIOSSHClientUserAuthenticationDelegate` existential.
    /// This proves the combined object's witness-table dispatch is correct, not just
    /// the sequencing of auth offers.
    func testCombinedExistentialKIRouting() throws {
        let eventLoop = EmbeddedEventLoop()
        defer { try? eventLoop.syncShutdownGracefully() }

        // Use a reference type so the @Sendable closure can mutate it without
        // triggering a Swift 6 SendableClosureCaptures warning on a captured var.
        final class Box<T>: @unchecked Sendable { var value: T; init(_ v: T) { value = v } }
        let closureReached = Box(false)
        let combined = SSHAuthenticationMethod.combine([
            .passwordBased(username: "u", password: "p"),
            .keyboardInteractive(username: "u") { _ in
                closureReached.value = true
                return eventLoop.makeSucceededFuture(["123456"])
            },
        ])

        // Call through the existential — proves witness-table dispatch routes the
        // challenge to the KI closure inside the combined object, not a no-op default.
        let delegate: any NIOSSHClientUserAuthenticationDelegate = combined
        let responsePromise = eventLoop.makePromise(of: [String]?.self)
        delegate.nextKeyboardInteractiveResponse(
            name: "OTP",
            instruction: "Enter your code",
            prompts: [NIOSSHKeyboardInteractivePromptField(prompt: "Code: ", echo: false)],
            responsePromise: responsePromise
        )
        eventLoop.run()

        var result: [String]??
        responsePromise.futureResult.whenSuccess { result = $0 }
        eventLoop.run()

        XCTAssertTrue(closureReached.value, "KI closure must be reached via existential dispatch on combined object")
        XCTAssertEqual(result, .some(["123456"]))
    }
}
