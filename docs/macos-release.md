# macOS release boundary

> Historical hardware-release planning reference; the requirements below are not a software-beta installation guide or a claim of completed controls. For the published `0.2.0-beta.2` software beta, use [getting started](getting-started.md) and the [support matrix](software-beta-support.md).

The provisional beta channel is a direct archive. It preserves the reviewed native binary and makes the one-time Gatekeeper approval explicit. Clean-Mac packaging evidence must confirm this choice. The current status-only qualification archive is not a beta release and cannot access a vault or launch a child.

Beta and GA automation fail closed in three layers: checked-in evidence gates, an exact tagged clean source checkout, and a native status report that declares the reviewed protocol and enables lifecycle operations. All three must pass before packaging. The current evidence record keeps the release jobs blocked.

GA uses a Developer ID Application identity outside the Mac App Store. CI imports signing material into an ephemeral keychain, signs the native executable with hardened runtime and a secure timestamp, creates and signs a DMG, requires an accepted `notarytool` result, staples and validates the ticket, and assesses the DMG with Gatekeeper. A failure stops before publication.

The release set consists of the tag, source commit, DMG or beta archive, SHA-256 checksum, SPDX SBOM, and GitHub provenance attestation. The clean-Mac acceptance result remains external evidence; CI output alone does not satisfy it.
