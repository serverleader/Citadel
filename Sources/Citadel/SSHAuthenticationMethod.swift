import NIO
import NIOSSH
import Crypto

/// A keyboard-interactive request surfaced by Citadel (mirrors RFC 4256 INFO_REQUEST).
public struct NIOSSHKeyboardInteractivePrompt: Sendable {
    public struct Field: Sendable {
        public let prompt: String
        public let echo: Bool
    }

    public let name: String
    public let instruction: String
    public let prompts: [Field]
}

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
        case keyboardInteractive(String, onChallenge: @Sendable (NIOSSHKeyboardInteractivePrompt) -> EventLoopFuture<[String]?>)
    }

    private let allImplementations: [Implementation]
    private var implementations: [Implementation]

    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
    }

    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }

    internal init(
        keyboardInteractive username: String,
        onChallenge: @escaping @Sendable (NIOSSHKeyboardInteractivePrompt) -> EventLoopFuture<[String]?>
    ) {
        self.allImplementations = [.keyboardInteractive(username, onChallenge: onChallenge)]
        self.implementations = allImplementations
    }

    internal init(combining methods: [SSHAuthenticationMethod]) {
        self.allImplementations = methods.flatMap { $0.allImplementations }
        self.implementations = allImplementations
    }

    /// Creates a password based authentication method.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }

    /// Creates a public key based authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
    }

    /// Creates a public key based authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }

    /// Creates a public key based authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }

    /// Creates a public key based authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }

    /// Creates a public key based authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }

    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }

    /// Creates a keyboard-interactive (RFC 4256) authentication method.
    /// `onChallenge` is invoked for each server INFO_REQUEST with the prompts to answer.
    /// Return `nil` from the closure to abort this authentication method.
    public static func keyboardInteractive(
        username: String,
        onChallenge: @escaping @Sendable (NIOSSHKeyboardInteractivePrompt) -> EventLoopFuture<[String]?>
    ) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(keyboardInteractive: username, onChallenge: onChallenge)
    }

    /// Combines several methods so they are offered in sequence (e.g. key/password then OTP).
    public static func combine(_ methods: [SSHAuthenticationMethod]) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(combining: methods)
    }

    /// True when the server advertises the method this implementation would use.
    private func isAvailable(_ implementation: Implementation, _ availableMethods: NIOSSHAvailableUserAuthenticationMethods) -> Bool {
        switch implementation {
        case .user(_, offer: let offer):
            switch offer {
            case .password: return availableMethods.contains(.password)
            case .hostBased: return availableMethods.contains(.hostBased)
            case .privateKey: return availableMethods.contains(.publicKey)
            case .none: return true
            case .keyboardInteractive: return availableMethods.contains(.keyboardInteractive)
            }
        case .keyboardInteractive: return availableMethods.contains(.keyboardInteractive)
        case .custom: return true // a custom delegate decides for itself
        }
    }

    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // Skip any methods the server does NOT advertise rather than failing the whole
        // attempt. Important for 2FA servers: it lets us prefer keyboard-interactive and
        // not burn a Google-Authenticator attempt by offering the bare `password` method
        // (which a PAM/OTP stack rejects as an "invalid verification code").
        while !implementations.isEmpty {
            let implementation = implementations.removeFirst()
            guard isAvailable(implementation, availableMethods) else {
                continue // not offered by the server — try the next configured method
            }
            switch implementation {
            case .user(let username, offer: let offer):
                nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
            case .keyboardInteractive(let username, _):
                nextChallengePromise.succeed(
                    NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: .keyboardInteractive(.init()))
                )
            case .custom(let implementation):
                implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
            }
            return
        }
        nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
    }

    public func nextKeyboardInteractiveResponse(
        name: String,
        instruction: String,
        prompts: [NIOSSHKeyboardInteractivePromptField],
        responsePromise: EventLoopPromise<[String]?>
    ) {
        for implementation in allImplementations {
            if case .keyboardInteractive(_, let onChallenge) = implementation {
                let challenge = NIOSSHKeyboardInteractivePrompt(
                    name: name,
                    instruction: instruction,
                    prompts: prompts.map { NIOSSHKeyboardInteractivePrompt.Field(prompt: $0.prompt, echo: $0.echo) }
                )
                onChallenge(challenge).cascade(to: responsePromise)
                return
            }
        }
        responsePromise.succeed(nil) // no KI responder configured → abort this method
    }
}
