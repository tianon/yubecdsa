module github.com/tianon/yubecdsa

go 1.24

require (
	github.com/alexflint/go-arg v1.6.0
	github.com/go-piv/piv-go/v2 v2.3.0
)

require github.com/alexflint/go-scalar v1.2.0 // indirect

// https://github.com/go-piv/piv-go/pull/108#issuecomment-3105074356
replace github.com/go-piv/piv-go/v2 v2.3.0 => github.com/tianon/piv-go/v2 v2.0.0-20250722230016-aee16e401953
