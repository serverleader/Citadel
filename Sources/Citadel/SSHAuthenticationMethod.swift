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

    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }

        let implementation = implementations.removeFirst()

        switch implementation {
        case .user(let username, offer: let offer):
            switch offer {
            case .password:
                guard availableMethods.contains(.password) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPasswordAuthentication)
                    return
                }
            case .hostBased:
                guard availableMethods.contains(.hostBased) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedHostBasedAuthentication)
                    return
                }
            case .privateKey:
                guard availableMethods.contains(.publicKey) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
                    return
                }
            case .none:
                ()
            case .keyboardInteractive:
                guard availableMethods.contains(.keyboardInteractive) else {
                    nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
                    return
                }
            }

            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
        case .custom(let implementation):
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
        case .keyboardInteractive(let username, _):
            guard availableMethods.contains(.keyboardInteractive) else {
                nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
                return
            }
            nextChallengePromise.succeed(
                NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: .keyboardInteractive(.init()))
            )
        }
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
