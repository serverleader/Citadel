import NIO
@preconcurrency import NIOSSH

public struct SSHSessionForwarding: Sendable {
    public var agent: Bool
    public var x11: SSHChannelRequestEvent.X11ForwardingRequest?

    public init(
        agent: Bool = false,
        x11: SSHChannelRequestEvent.X11ForwardingRequest? = nil
    ) {
        self.agent = agent
        self.x11 = x11
    }
}

public extension SSHClient {
    enum ForwardingRegistrationError: Error {
        case alreadyRegistered
    }

    /// Bridges server-opened `auth-agent@openssh.com` channels to a local
    /// SSH agent UNIX socket. Call before opening a session with agent forwarding.
    func registerAgentForwarding(socketPath: String) throws {
        let result = session.inboundChannelHandler.registerForwardedAgent { sshChannel in
            let (sshGlue, agentGlue) = GlueHandler.matchedPair()
            return sshChannel.pipeline.addHandlers(
                SSHChannelDataUnwrapper(),
                SSHOutboundChannelDataWrapper(),
                sshGlue
            ).flatMap {
                ClientBootstrap(group: sshChannel.eventLoop)
                    .channelInitializer { agentChannel in
                        agentChannel.pipeline.addHandler(agentGlue)
                    }
                    .connect(unixDomainSocketPath: socketPath)
            }.map { _ in () }
        }
        guard case .success = result else {
            throw ForwardingRegistrationError.alreadyRegistered
        }
    }

    func unregisterAgentForwarding() {
        session.inboundChannelHandler.unregisterForwardedAgent()
    }

    /// Registers consumer for server-opened X11 channels. Consumer must perform
    /// X11 cookie substitution before connecting to local display.
    func registerX11Forwarding(
        handler: @escaping @Sendable (Channel, SSHChannelType.X11) -> EventLoopFuture<Void>
    ) throws {
        let result = session.inboundChannelHandler.registerX11(handler: handler)
        guard case .success = result else {
            throw ForwardingRegistrationError.alreadyRegistered
        }
    }

    func unregisterX11Forwarding() {
        session.inboundChannelHandler.unregisterX11()
    }
}
