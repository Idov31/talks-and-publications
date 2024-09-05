# X33fCon 2024

You can view the talk [here](https://www.youtube.com/watch?v=edI6tpBO-pY).

## Description

Kernel Games: Ballad Of Offense And Defense is a talk about creating stealthy rootkits to help red teams remain persistent, evade EDRs, and connect them to your existing C2 environment. Additionally, this will help elevate blue teams to detect the complex threat mentioned above.

- Rootkit methodologies: Demonstrate several interesting capabilities of rootkits, such as hiding an injected DLL, dumping credentials from the kernel, and removing kernel callbacks of AVs/EDRs.

- Real-world scenario - Integration with Mythic C2: Showcasing real-world usage with Mythic C2's agent - Athena - as part of a possible red team engagement scenario.

- Detecting rootkits methods: Explaining how to detect some of the methods rootkits are using, for example, removing kernel callbacks, file protecting, and ETWTI tampering.

- Tool demo - Finding IRP hooks: To help defenders have more visibility on loaded kernel drivers, I will also show a tool that lists the loaded drivers and information about them (path, registered callbacks, imports, IRP hooks).

## What the repository contains

- "IrpHookDetector" was used to demonstrate the detection of IRP hooks.
- Presentation.
