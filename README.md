# go-appattest

Server-side verification of Apple
[App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
for Go: checks that a request comes from a genuine copy of your iOS app on a
real device.

It follows Apple's
[Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
step by step, using Go's standard crypto. No network calls, no storage, no
global state.

Not affiliated with Apple. App Attest and DeviceCheck are Apple's.

## Status

Under construction. Nothing is released yet.

## License

[MIT](LICENSE)
