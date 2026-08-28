import UIKit
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?

  var reactNativeDelegate: ReactNativeDelegate?
  var reactNativeFactory: RCTReactNativeFactory?

  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let delegate = ReactNativeDelegate()
    let factory = RCTReactNativeFactory(delegate: delegate)
    delegate.dependencyProvider = RCTAppDependencyProvider()

    reactNativeDelegate = delegate
    reactNativeFactory = factory

    window = UIWindow(frame: UIScreen.main.bounds)

    // The one thing JavaScript cannot work out for itself: a directory this
    // process may write to. `createCryptoMachine` needs one, the library
    // deliberately chooses none (a crypto library that picks its own on-disk
    // location writes somewhere the product did not agree to), and React
    // Native exposes no path API. So the platform's own answer travels to
    // the root component as an initial property -- see App.tsx. This is the
    // example app's own native code doing it: no dependency was added, and
    // nothing was added to the library.
    //
    // Empty rather than a fallback path if the search somehow returns
    // nothing: App.tsx turns that into a failing probe step, which is the
    // honest outcome. Inventing a path here would move the failure to
    // somewhere nobody agreed to write.
    let storeDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
      .first ?? ""

    // RULE FOR ANYONE ADDING A PROP BELOW: initial properties are printed
    // verbatim to the system log. React Native's own AppRegistry logs the
    // whole dictionary on startup in a debug build -- observed here as
    // `Running "ExampleApp" with {"rootTag":11,"initialProps":
    // {"storeDir":"...Documents"},"fabric":true}` at info level, subsystem
    // com.facebook.react.log, category javascript -- and they are ordinary
    // JavaScript props afterwards, which any code may print. So NO
    // PASSPHRASE, NO KEY MATERIAL AND NO USER OR DEVICE IDENTIFIER may
    // travel this way. `storeDir` is here
    // because it is the app's own sandbox directory, derivable from the
    // bundle id and secret from nobody; the passphrase deliberately is not,
    // and lives in src/cryptoConfig.ts instead. No gate in this repository
    // enforces that -- this comment is the enforcement.

    factory.startReactNative(
      withModuleName: "ExampleApp",
      in: window,
      initialProperties: ["storeDir": storeDir],
      launchOptions: launchOptions
    )

    return true
  }
}

class ReactNativeDelegate: RCTDefaultReactNativeFactoryDelegate {
  override func sourceURL(for bridge: RCTBridge) -> URL? {
    self.bundleURL()
  }

  override func bundleURL() -> URL? {
#if DEBUG
    RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: "index")
#else
    Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
  }
}
