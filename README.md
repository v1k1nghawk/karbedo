# karbedo
* _Purpose:_ hash collisions finder.
* _Desription:_ One can use this security research software for pentesting purposes or as a **password recovery tool**.
* _Usage:_
1. Use the "Open File..." button to select a /etc/shadow-type file;
2. From a right drop-down menu select a user;
3a. Wait untill collision(s) are found OR
3b. Interrupt the attack with the "STOP" button OR
3c. Save the attack with the Close button (continue with the "RESUME" button after the next restart of the application).
* _Tested on:_ /etc/shadow files from "FC28", "Kali linux 2020.1", "SANS SIFT Workstation with Ubuntu LTS 16.04 Base".

* Key new features of **karbedo** include:
_v0.2:_
1. Dictionary attack (uses all .txt files inside ~/.local/share/dictionaries/ directory);
2. Current attack saving for later resumption.
_v0.1:_
1. Multithreaded brute-force attack;
2. Username attack;
3. GUI.
