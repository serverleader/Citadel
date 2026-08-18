import NIOCore
import NIOEmbedded
import NIOSSH
@testable import Citadel
import XCTest

final class ForwardingTests: XCTestCase {
    func testForwardedAgentDispatchesRegisteredHandler() throws {
        let inbound = SSHClientInboundChannelHandler()
        let channel = EmbeddedChannel()
        var handled = false

        XCTAssertRegistrationSucceeded(inbound.registerForwardedAgent { received in
            XCTAssertTrue(received === channel)
            handled = true
            return received.eventLoop.makeSucceededVoidFuture()
        })

        try inbound.handleChannel(channel: channel, channelType: .forwardedAgent).wait()
        XCTAssertTrue(handled)
        XCTAssertNoThrow(try channel.finish())
    }

    func testX11DispatchesRegisteredHandlerWithOriginator() throws {
        let inbound = SSHClientInboundChannelHandler()
        let channel = EmbeddedChannel()
        let originator = try SocketAddress(ipAddress: "127.0.0.1", port: 6010)
        var received: SSHChannelType.X11?

        XCTAssertRegistrationSucceeded(inbound.registerX11 { _, request in
            received = request
            return channel.eventLoop.makeSucceededVoidFuture()
        })

        try inbound.handleChannel(channel: channel, channelType: .x11(.init(originatorAddress: originator))).wait()
        XCTAssertEqual(received?.originatorAddress, originator)
        XCTAssertNoThrow(try channel.finish())
    }

    func testUnregisteredForwardingChannelsFailClosed() throws {
        let inbound = SSHClientInboundChannelHandler()
        let agent = EmbeddedChannel()
        let x11 = EmbeddedChannel()
        let originator = try SocketAddress(ipAddress: "127.0.0.1", port: 6010)

        XCTAssertThrowsError(try inbound.handleChannel(channel: agent, channelType: .forwardedAgent).wait())
        XCTAssertThrowsError(try inbound.handleChannel(channel: x11, channelType: .x11(.init(originatorAddress: originator))).wait())
        XCTAssertNoThrow(try agent.finish())
        XCTAssertNoThrow(try x11.finish())
    }

    private func XCTAssertRegistrationSucceeded(
        _ result: SSHClientInboundChannelHandler.HandleRegistrationResult,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .success = result else {
            return XCTFail("registration failed", file: file, line: line)
        }
    }
}
