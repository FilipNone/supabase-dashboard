# supabase-dashboard

A self-hosted web dashboard, written in Rust, for managing several self-hosted Supabase deployments from one place. The goal is a UI that feels familiar to users of the hosted Supabase dashboard, plus server and deployment management that self-hosted installs lack.

This is an independent project. It is not made, endorsed, or supported by Supabase.

## Status

Early development (milestones M0 and M1, M2 started). Operators can sign in, manage organizations, members, and invitations, register existing self-hosted stacks by API URL, store each stack's API keys encrypted on the server, and check whether its Auth and REST services answer. `ROADMAP.md` has the plan and current status.

## Install

Development releases ship a prebuilt container image for linux/amd64 and linux/arm64, `ghcr.io/filipnone/supabase-dashboard`, and a Docker Compose bundle on the [releases page](https://github.com/FilipNone/supabase-dashboard/releases). Nothing is compiled on the server. See [docs/deployment.md](docs/deployment.md).

## Development

See [docs/development.md](docs/development.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Files adapted from other projects keep their original license; each one says so in its header. The Supabase name and logos are trademarks of Supabase, Inc. and are not covered by either license.
