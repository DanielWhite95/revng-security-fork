*******
Purpose
*******

`revng` is a static binary translator. Given a input ELF binary for one of the
supported architectures (currently MIPS, ARM and x86-64) it will analyze it and
emit an equivalent LLVM IR. It can be also used for static binary analysis. This
projects aims at adding vulnerability discovery to revng using such feature.

*******
Build
*******

The suggested method to build this fork is to use `revng` orchestra repo.
Once the repo has been cloned install revng in the suggested way inside the repo README.
After that delete the revng directory inside the orchestra repo and clone this fork to replace it.

```
git clone <revng-security-fork-repo> revng
```

**Be sure to checkout on the master branch!!**
After that re-issue the command `make install-revng` from the orchestra directory and now you should be able
to execute revng security analyses. **Always source the orchestra environment before launching the analyses**
