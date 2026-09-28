# AegisKit: PwnBot for iOS

PwnBot counts a free tier, a sign-up or a reward against the phone, so
deleting the app and installing it again, or making a second account,
doesn't bring it back. This is its Swift package. Made by Checkmate Labs.

- What PwnBot is: https://pwnbot.checkmatelabs.app
- Start a hosted site (free while it only counts): https://pwnbot.checkmatelabs.app/start
- Guides: https://pwnbot.checkmatelabs.app/guides

## Install

Swift Package Manager, iOS 15+ / macOS 12+. In Xcode: File, Add Package
Dependencies, and paste `https://github.com/checkmatelabsapps/aegiskit-swift.git`,
or in `Package.swift`:

```swift
.package(url: "https://github.com/checkmatelabsapps/aegiskit-swift.git", from: "0.2.0")
```

Add the **App Attest** capability to your target (Signing & Capabilities),
and set `com.apple.developer.devicecheck.appattest-environment` to
`production` for release builds. Enter your app id (`TEAMID.your.bundle.id`)
in your PwnBot console.

## Send the request that costs you money with a pass

```swift
import AegisKit

let pwnbot = try AegisClient(baseURL: URL(string: "https://your-app.sites.checkmatelabs.app")!)

var request = URLRequest(url: URL(string: "https://api.example.com/api/scan")!)
request.httpMethod = "POST"

do {
    let (data, response) = try await pwnbot.send(request, route: "POST /api/scan", ifNoPass: .send)
} catch let error as AegisError where error.isCapExhausted {
    // This phone has used its free tier: show your paywall.
} catch let error as AegisError {
    // error.explanation.message is a sentence you can show.
}
```

`send` gets a single-use pass for the route and sends it with your request.
With `ifNoPass: .send`, where no pass can be had (the Simulator, PwnBot
unreachable, the limit reached, a phone that can't attest) the request goes
without one and says why in the header `x-pwnbot-no-pass`; your server
decides. With the default, `.fail`, `send` throws instead and sends nothing.

Your server checks the pass: `npm install pwnbotdetect` for Node, or two
HTTPS calls from any language (see the guides).

## What one call does

| Step | What happens | What leaves the device |
|---|---|---|
| Identity | First run: App Attest makes a Secure Enclave key and Apple attests it. Later: the key signs a fresh challenge. | Apple's attestation, or an assertion. Never the private key. |
| Ticket | A random value is blinded on the device and the server signs it blind (RFC 9497 VOPRF, ristretto255). | Only the blinded value. |
| Spend | The ticket buys a single-use pass, good for about 30 seconds, counted against the phone's limit for that route. | The ticket and the identity credential. |

A reinstall keeps the phone's identity: a key in the Keychain, which
survives deleting the app, ties the new install to the old one. Erasing the
phone doesn't keep it, unless Apple's per-phone key count is on for your
site.

## What has been shown, and what hasn't

- **The crypto:** byte-for-byte against vectors from the server's own
  library, plus an RFC 9380 vector. Tampered proofs and proofs from another
  key are refused.
- **On a real iPhone:** one iPhone 17 Pro, two recorded tests (25 and 27
  September 2026): a pass, the limit, the same identity after a reinstall,
  and a refusal once the route was enforced. Both ran through the React
  Native bridge over this package.
- **`send(ifNoPass: .send)` called from Swift directly** is covered by the
  tests and has not run on a phone.
- **Tests:** `swift test` runs the crypto vectors, the refusal texts and
  sending without a pass. The live tests (`LiveServerTests.swift`) need a
  PwnBot server and a synthetic App Attest device, and are skipped
  otherwise.

## Privacy

The package ships Apple's privacy manifest (`PrivacyInfo.xcprivacy`): it
collects a device-bound pseudonym for your app and nothing else, and does
no tracking. The default `URLSession` is ephemeral: no cookies, no cache.
What PwnBot keeps, and for how long:
https://pwnbot.checkmatelabs.app/guides/what-we-store

## Licence

Functional Source License 1.1, converting to Apache 2.0 after two years.
See LICENSE.
