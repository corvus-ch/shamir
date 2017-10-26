# Shamir's Secret Sharing

[![Build Status](https://img.shields.io/travis/corvus-ch/shamir.svg)](https://travis-ci.org/corvus-ch/shamir)
[![Test Coverage](https://img.shields.io/codecov/c/github/corvus-ch/shamir.svg)](https://codecov.io/gh/corvus-ch/shamir)
[![Documentation](https://godoc.org/gopgk.in/corvus-ch/shamir.v1?status.svg)](https://godoc.org/gopkg.in/corvus-ch/shamir.v1)

Implementation of the [Shamir's Secret Sharing][sss] in golang.

This package:

* supports splitting and recombining of byte arrays;
* supports splitting and recombining using `io.Writer` and `io.Reader`
  interfaces;
* is compatible with `gfsplit` and `gfcombine` from [libgfshare].

Based on `github.com/hashicorp/vault` from [HashiCorp].

## Contributing and license

This library is licences under [Mozilla Public License, version 2.0](LICENSE).
For information about how to contribute to this project, see
[CONTRIBUTING](CONTRIBUTING.md)

[sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
[libgfshare]: https://www.digital-scurf.org/software/libgfshare
[HashiCorp]: https://www.hashicorp.com
