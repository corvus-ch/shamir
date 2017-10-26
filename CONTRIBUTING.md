# How to contribute

I take that you have ended up here, because you have found an issue or have a
question. If this is the case, please file an issue with this project on its
[issue tracker over at github](https://github.com/corvus-ch/shamir/issues).

Before doing so, please keep the following in mind:

* The maintainer of this library is most certainly busy with a lot of other
  stuff. So if you struggling with using this library, please try one of the
  many friendly places in the internet first. You most probably will not get
  any support here.

If you have found a bug and are willing to fix it yourself, great thanks a lot.
I will happily accept your pull request given the following rules are obliged:

* The bug must be reproduced by adding a test for it.
* All tests must pass
* Formatting rules are followed. That is, `gofmt -w .` does not result in any
  changes.

Notes for running the tests:

This library contains test to check compatibility with the binaries provided by
libgfshare. Those tests are skipped if the those binaries are not present.  In
order to run those tests, please ensure you have [libgfshare] installed and the
commands `gfsplitt` and `gfcombine` are available in your path.

[libgfshare]: https://www.digital-scurf.org/software/libgfshare
