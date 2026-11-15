# SEC-T 2026

You can view the talk [here](https://www.youtube.com/watch?v=s22wW8I_Jxk).

## Description

Modern Linux systems run a long chain of code before the kernel takes over - firmware, bootloaders like GRUB, and early runtime environments. Although each component is well understood, the transitions between them are often treated as simple handoffs, obscuring key assumptions about what state persists, what gets reinitialized, and where execution can truly be intercepted.

This talk offers a practical examination of one of the most important transitions: the GRUB-to-kernel handoff. Through reverse engineering GRUB and analyzing how the kernel image is loaded, decompressed, and executed, it shows how early-boot control flow is assembled - and where it can be influenced reliably.

Instead of staying theoretical, the presentation focuses on real constraints that shape boot-chain abuse. It explores which execution contexts survive across stages, which don’t, and how that affects the feasibility of establishing persistent control before OS security mechanisms activate.

To ground the discussion, a UEFI bootkit is built within the reconstructed execution flow. The implementation demonstrates concrete ways to subvert the Linux boot process, along with limitations and failure modes that appear when early-execution assumptions break.

Overall, the talk clarifies how early boot works in practice: what can be controlled, what cannot, and what that implies for both offensive techniques and defensive visibility during one of the least observed phases of system execution.

## What the repository contains

- Presentation.
