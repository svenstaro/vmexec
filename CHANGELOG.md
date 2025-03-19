# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [0.1.3] - 2025-03-19
- Add dead run dir reaping
- Add locking when pulling images

## [0.1.2] - 2025-03-18
- Add some flags to `virtiofsd` call to improve performance and decrease guest memory usage
- Fix multiple `-v` options not working due to incorrect fstab getting generated
- Add virtio-pmem device support with `--pmem`

## [0.1.1] - 2025-03-13
- Fix NvVars file getting created in mounted dirs

## [0.1.0] - 2025-03-13
- First somewhat working version

<!-- next-url -->
[Unreleased]: https://github.com/svenstaro/vmexec/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/svenstaro/vmexec/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/svenstaro/vmexec/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/svenstaro/vmexec/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/svenstaro/dummyhttp/compare/v0.1.0...v0.1.0
