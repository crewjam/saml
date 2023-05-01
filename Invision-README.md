
# Overview
We're maintaining a fork of this repo in order to support certain
deviations from the saml spec that are not of general use. The goal
is to support our requirements with a minimum of maintenance and stay
as close to upstream as possible.


## Branches
- `main` - This matches upstream's main exactly
- `invision-main` - This branch includes upstream's main as well as
    InVision-specific changes rebased on top of upstream.
- `releases/<date>` -


### How to make a change to this saml library
1. Is it a bug in upstream? Submit there and update this fork when it is released.
2. If it's InVision specific, branch from and open a PR against `invision-main`.
    **Be careful opening the PR. Github defaults to the base fork and will open it on upstream unless you specify.**
3. Once the PR is approved and merged, follow the process below to release.

### How to update from upstream
0. Ensure that a dated release branch exists with the release that is currently used in other services.
1. Pull `main` branch from upstream. This should be a fast forward.
2. **Rebase** `invision-main` on top of `main`, re-applying our changes as necesary.
3. Force push the rebased version of `invision-main`.

### Creating a new Release
1. Create a new release branch from `main` which includes the desired version of upstream named `release/<date>`
2. Create a PR from `invision-main` onto the release branch to apply invision's changes. This should be a fast forward
as invision-main should be rebased on top of upstream.
3. Once the release branch is correct, create a tagged github release from the release branch.
4. Note that release branches should live forever since we need to rebase `invision-main`
