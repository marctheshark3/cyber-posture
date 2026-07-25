# Licensing

## cyber-posture (this repository)

**MIT** — see [`LICENSE`](../LICENSE).

You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, with copyright notice retained.

## Container image (aggregate)

The GHCR image installs Ubuntu packages that are **not** re-licensed as MIT.
See [`NOTICE.md`](../NOTICE.md) for the third-party table.

If you redistribute the image, keep:

1. `LICENSE` (MIT for our code)
2. `NOTICE.md` (third-party attribution)
3. Upstream copyright files from the base image where required by those licenses (GPL obligations for corresponding source on request / via Ubuntu archives)

## CI / Actions

GitHub Actions and third-party actions (docker/*, softprops/action-gh-release, etc.) are used under their respective licenses; they are not shipped inside the runtime image.

## Contributor note

By contributing, you agree your patches are MIT-licensed unless stated otherwise in the PR.
