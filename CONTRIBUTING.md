# Contributing to Cloudera Labs projects

Welcome to Cloudera Labs! We welcome contributions to our projects. Below is the ground rules for engaging with a Cloudera Labs project and its development community.

## Submitting Issues

Cloudera Labs projects use GitHub to track project issues.

## Contribution Process

We have a 3-step process for contributions:

1. Commit changes to a git branch in your forked repository, making sure to sign-off those changes for the [Developer Certificate of Origin](#developer-certification-of-origin-dco) (DCO).
2. Create a GitHub Pull Request (PR) for your change.
3. Perform a [Code Review](#code-review-process) with the project maintainers on the pull request.

### Pull Request Requirements

tktk

### Code Review Process

We perform code reviews in the GitHub pull requests. Once you open a pull request, project maintainers will review your code and respond to your pull request with any feedback they might have. The process at this point is as follows:

1. Two or more members of the project maintainers must approve your PR.
2. Your change will be merged into the project's `devel` branch.
3. The project maintainers will then merge the `devel` branch in to the `primary` branch according to the project's release cycle.

### Developer Certification of Origin (DCO)

This project uses [the Apache 2.0 license](LICENSE). The license tells you what rights you have that are provided by the copyright holder. It is important that the contributor fully understands what rights they are licensing and agrees to them. Sometimes the copyright holder isn't the contributor, such as when the contributor is doing work on behalf of a company.

To make a good faith effort to ensure these criteria are met, Cloudera Lab projects require the Developer Certificate of Origin (DCO) process to be followed.

The DCO is an attestation attached to every contribution made by every developer. In the commit message of the contribution, the developer simply adds a `Signed-off-by` statement and thereby agrees to the DCO, which you can find below or at <http://developercertificate.org/>.

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the
    best of my knowledge, is covered under an appropriate open
    source license and I have the right under that license to
    submit that work with modifications, whether created in whole
    or in part by me, under the same open source license (unless
    I am permitted to submit under a different license), as
    Indicated in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including
    all personal information I submit with it, including my
    sign-off) is maintained indefinitely and may be redistributed
    consistent with this project or the open source license(s)
    involved.
```

#### DCO Sign-Off Methods

The DCO requires a sign-off message in the following format appear on each commit in the pull request:

```
Signed-off-by: Example Developer <example@cloudera.com>
```

The DCO text can either be manually added to your commit body, or you can add either `-s` or `--signoff` to your usual `git` commit commands. If you are using the GitHub UI to make a change, you can add the sign-off message directly to the commit message when creating the pull request. If you forget to add the sign-off, you can also amend a previous commit with the sign-off by running `git commit --amend -s`. If you've pushed your changes to GitHub already, you'll need to force push your branch after this with `git push -f`.

### Obvious Fix Policy

Small contributions, such as fixing spelling errors, where the content is small enough to not be considered intellectual property, can be submitted without signing the contribution for the DCO.

As a rule of thumb, changes are obvious fixes if they do not introduce any new functionality or creative thinking. Assuming the change does not affect functionality, some common obvious fix examples include the following:

- Spelling / grammar fixes
- Typo correction, white space and formatting changes
- Comment clean up
- Bug fixes that change default return values or error codes stored in constants
- Adding logging messages or debugging output
- Changes to 'metadata' files like .gitignore, build scripts, etc.
- Moving source files from one directory or package to another

**Whenever you invoke the "obvious fix" rule, please say so in your commit message:**

```
------------------------------------------------------------------------
commit 983e9618f9ac03292cd4be1cb1fb940e67686f19
Author: Example Developer <example@cloudera.com>
Date:   Wed Jan 20 12:00:01 2021 -0500

  Fix typo in the README.

  Obvious fix.

------------------------------------------------------------------------
```

## Release Cycles

Cloudera Labs projects adhere to the [Semantic Versioning](http://semver.org/) standard. Our standard version numbers look like X.Y.Z which mean:

- X is a major release, which may not be fully compatible with prior major releases
- Y is a minor release, which adds both new features and bug fixes
- Z is a patch release, which adds just bug fixes

## The Cloudera Community

Cloudera Labs is made possible by a strong community of developers, administrators, partners, and users. If you have any questions or if you would like to get involved in the Cloudera and Cloudera Labs communities, you can check out:

- [Cloudera Labs Community](https://community.cloudera.com/t5/Cloudera-Labs/bd-p/ClouderaLabs)

Also here are some additional pointers to broader Cloudera content:

- [Cloudera Documentation](https://docs.cloudera.com/)
- [Cloudera Community](https://community.cloudera.com/)
- [Cloudera Inc. Website](https://www.cloudera.com/)