# watcher

A simple implementation of Apple's [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity) to monitor a single process and its child process.

## For Developer
You need the Apple's Endpoint Security Entitlement from apple, you can make the request [here](https://developer.apple.com/contact/request/system-extension/).
Alternatively, you can disable SIP temporarily.

## Release notes
### v1.0
Support for `EXEC`, `FORK`, and `EXIT` events.
