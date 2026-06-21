// Entry point for the NetworkExtension system extension.
//
// A .systemextension is an executable bundle. `NEProvider.startSystemExtensionMode()`
// hands control to NetworkExtension so nesessionmanager can instantiate the
// provider class declared in Info.plist's NetworkExtension/NEProviderClasses map.

import Dispatch
import NetworkExtension

NEProvider.startSystemExtensionMode()
dispatchMain()
