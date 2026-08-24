# macOS release boundary

The provisional beta channel is a direct archive. It preserves the reviewed native binary and makes the one-time Gatekeeper approval explicit. Clean-Mac packaging evidence must confirm this choice. The current status-only qualification archive is not a beta release and cannot access a vault or launch a child.

Beta and GA automation fail closed in three layers: checked-in evidence gates, an exact tagged clean source checkout, and a native status report that declares the reviewed protocol and enables lifecycle operations. All three must pass before packaging. The current evidence record keeps the release jobs blocked.

GA uses a Developer ID Application identity outside the Mac App Store. CI imports signing material into an ephemeral keychain, signs the native executable with hardened runtime and a secure timestamp, creates and signs a DMG, requires an accepted `notarytool` result, staples and validates the ticket, and assesses the DMG with Gatekeeper. A failure stops before publication.

The release set consists of the tag, source commit, DMG or beta archive, SHA-256 checksum, SPDX SBOM, and GitHub provenance attestation. The clean-Mac acceptance result remains external evidence; CI output alone does not satisfy it.
