package com.exampleapp

import android.os.Bundle
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

class MainActivity : ReactActivity() {

  /**
   * Returns the name of the main component registered from JavaScript. This is used to schedule
   * rendering of the component.
   */
  override fun getMainComponentName(): String = "ExampleApp"

  /**
   * Returns the instance of the [ReactActivityDelegate]. We use [DefaultReactActivityDelegate]
   * which allows you to enable New Architecture with a single boolean flags [fabricEnabled]
   *
   * The delegate is subclassed here for exactly one reason: to hand JavaScript a directory this
   * process may write to. `createCryptoMachine` needs one, the library deliberately chooses none
   * (a crypto library that picks its own on-disk location writes somewhere the product did not
   * agree to), and React Native exposes no path API. So the platform's own answer, `filesDir`,
   * travels to the root component as an initial property -- see App.tsx. This is the example
   * app's own native code doing it: no dependency was added, and nothing was added to the
   * library.
   */
  override fun createReactActivityDelegate(): ReactActivityDelegate =
      object : DefaultReactActivityDelegate(this, mainComponentName, fabricEnabled) {
        override fun getLaunchOptions(): Bundle =
            Bundle().apply {
              putString("storeDir", this@MainActivity.applicationContext.filesDir.absolutePath)
            }
      }
}
