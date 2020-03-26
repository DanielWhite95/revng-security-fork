*******
Purpose
*******

`revng` is a static binary translator. Given a input ELF binary for one of the
supported architectures (currently MIPS, ARM and x86-64) it will analyze it and
emit an equivalent LLVM IR. It can be also used for static binary analysis. This
projects aims at adding vulnerability discovery to revng using such feature.

*******
Build & Install
*******

The suggested method to build this fork is to use `revng` orchestra repo.
Once the repo has been cloned install revng in the suggested way inside the repo README.
After that delete the revng directory inside the orchestra repo and clone this fork to replace it.

```
git clone <revng-security-fork-repo> revng
```

**Be sure to checkout on the master branch!!**

After that re-issue the command `make install-revng` (or your preferred version of revng) from the orchestra directory and now you should be able
to execute revng security analyses. **Always source the orchestra environment before launching the analyses**

*******
Usage
*******
First of all source the environment file in the main directory of the orchestra repo, otherwise required binaries will not be in your PATH.
If you have trouble, remove the environment file and re-generate it with the command `make environment` from orchestra repo.

To analyze a simple program you need to lift it first using the helper script `revng-security-lifter`. This revng-lift wrapper lift the binaries and optimize 
the lifted code with some required LLVM passes.

Then the produced lifted IR can be analyzed using the script `revng-security-analyzer` (more info on its usage with `revng-security-analyzer -h`). 

*******
Example
*******
To analyze a binary named `bin-example` under the `bin` directory issue the following command:

1. Lift the binary: 
   ```
        revng-security-lifter bin/bin-example bin-example.ll
   ```
2. Analyze the lifted code, using the input functions listed in the `input-functions.csv` file
   ```
        revng-security-analyzer -r -i input-functions.csv -t bin-example-taint-output.json -j bin-example-output.json bin-example.ll
   ```



