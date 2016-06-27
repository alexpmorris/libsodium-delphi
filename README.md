# libsodium-delphi [![License](http://img.shields.io/badge/license-MIT-green.svg)](https://github.com/alexpmorris/libsodium-delphi/blob/master/license)

libsodium-delphi, or [libsodium](https://github.com/jedisct1/libsodium) for Delphi, is a Delphi/FreePascal wrapper around libsodium.  libsodium is a portable and relatively easy to use implementation of [Daniel Bernstein's](http://cr.yp.to/djb.html) fantastic [NaCl](http://nacl.cr.yp.to/) library.

## Why

NaCl is a great encryption, hashing, and authentication library that is designed to make proper implementation easy and straight-forward.  By using it (or a wrapper), many of the finer details (including speed-optimization) are abstracted away so the programmer doesn't need to worry about them.  NaCl itself is less than portable C, only targeted for *nix systems.  libsodium makes the library portable, and adds additional conveniences to make the library easily standardized across multiple platforms, operating systems, and languages.

Crypto is very tricky to implement correctly.  With this library, you are much more likely to get it correct out of the box, by implementing solid encryption standards and practices without materially effecting performance.

## Installation

**Windows**: For Windows, the `libsodium` library is included in the [release](https://github.com/alexpmorris/libsodium-delphi/releases) packages, along with an executable demo.

## Documentation

Between the Delphi demo application, and the [original libsodium documentation library](http://doc.libsodium.org/) written by Frank Denis ([@jedisct1](https://github.com/jedisct1)), you should have all you need to get going.

## Requirements & Versions

libsodium-delphi works with either the 32-bit or 64-bit libsodium.dll library version 1.0.10.  [Click here for precompiled libsodium DLLs.](https://download.libsodium.org/libsodium/releases/)

## License

NaCl has been released to the public domain to avoid copyright issues. libsodium is subject to the [ISC license](https://en.wikipedia.org/wiki/ISC_license), and this software is subject to the MIT license (see [license](https://github.com/alexpmorris/libsodium-delphi/blob/master/license)).
