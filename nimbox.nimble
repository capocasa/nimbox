# nimble file for nimbox
# Package

version       = "0.1.0"
author        = "Carlo Capocasa"
description   = "A filesystem sandbox backed by Linux Landlock"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]

bin           = @["nimbox"]


# Dependencies

requires "nim >= 2.0.0"

# Tasks / tests

task test, "Run nimbox tests":
  # build the binary first; CLI tests invoke it from the project root
  exec "nim c --path:src -d:release -o:nimbox src/nimbox.nim"
  withDir "tests":
    exec "nim c --path:../src -r test_sandbox.nim"
