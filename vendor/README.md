# vendor/

Third-party binaries are **not redistributed** in this repository. Download them
yourself and drop them here.

## FakeNet-NG

Required only for `--mode full` (the fake-internet stage). Without it, a sample that
downloads or beacons will appear to "try and fail", which hides the second half of its
behaviour.

1. Download the Windows release zip from the Mandiant FakeNet-NG releases page.
2. Put it in this directory.
3. Either name it `fakenet3.5.zip`, or set `fakenet_zip` in `host/config.json` to its
   path.

`mal.py setup-guest` pushes the zip into the guest and runs `vm/install_fakenet.ps1`,
which unpacks it to `<guest_root>\tools` and writes a marker file that `detonate.ps1`
reads. The install happens **after** the pre-run revert, so it survives the revert and
your clean snapshot never has to be retaken to add it.

If the install fails, `detonate` records `fakenet=False` rather than pretending a fake
internet was up. Check `detonate.log` for `FakeNet-NG up (pid ...)` and `summary.json`'s
`fakenet` flag before citing any DNS or TCP artifact.

Set `install_fakenet: false` in `host/config.json` to skip it entirely.
