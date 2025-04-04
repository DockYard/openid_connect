# CHANGELOG

## v1.0.0

Complete rewrite of the library by @AndrewDryga

### Added
* Add `end_session_uri/2` and `fetch_userinfo/2`
* Adds OpenID claim validation

### Removed
* GenServer bottleneck
* Atom requirement for provider name
* Application config from the library

### Changed
* Rewrote tests to better cover production code
* Use Finch/Mint as the HTTP client instead of HTTPoison

Please see the documentation for migrating from prior versions.

## v0.2.2
* Allow missing `claims_supported` in discovery document
* Allow overriding document params

## v0.2.1
* Relaxed jason version requirement

## v0.2.0
* BREAKING CHANGE - Multiple response types supported. See: PR #17 for details

## v0.1.2
* Optional params for `authorization_uri`

## v0.1.1

* Remove Poison (legacy dep)
* Force JOSE to use Jason in test suite

## v0.1.0

* Initial public release
