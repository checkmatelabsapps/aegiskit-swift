import XCTest
@testable import AegisKit
#if canImport(DeviceCheck)
import DeviceCheck

/// How DeviceCheck's errors reach AegisClient. A key that's gone must come
/// out as AppAttestKeyInvalid, so the client enrolls a new one instead of
/// failing forever.
@available(iOS 14.0, macOS 11.0, *)
final class AppAttestErrorTests: XCTestCase {
    func testAMissingKeyOnAssertionIsAKeyToReplaceWhicheverCodeAppleUses() {
        XCTAssertTrue(DCAppAttestProvider.mapError(DCError(.invalidKey), assertion: true) is AppAttestKeyInvalid)
        // What a real iPhone returned after a reinstall (2026-09-25).
        XCTAssertTrue(DCAppAttestProvider.mapError(DCError(.invalidInput), assertion: true) is AppAttestKeyInvalid)
    }

    func testInvalidInputOutsideAnAssertionIsLeftAlone() {
        let mapped = DCAppAttestProvider.mapError(DCError(.invalidInput), assertion: false)
        XCTAssertEqual((mapped as? DCError)?.code, .invalidInput)
    }

    func testServerUnavailableIsBusyAndOtherErrorsPassThrough() {
        guard case AegisError.busy = DCAppAttestProvider.mapError(DCError(.serverUnavailable), assertion: true) else {
            return XCTFail("serverUnavailable should be busy")
        }
        XCTAssertEqual((DCAppAttestProvider.mapError(DCError(.featureUnsupported), assertion: true) as? DCError)?.code, .featureUnsupported)
        XCTAssertTrue(DCAppAttestProvider.mapError(URLError(.timedOut), assertion: true) is URLError)
    }
}
#endif
