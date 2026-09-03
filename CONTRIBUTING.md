# Contributing

Thanks for considering a contribution!

1. Fork the repo and create a branch: `git checkout -b feature/my-feature`
2. Test your changes on Kali Linux with `sudo python3 packet_sniffer.py ...`
3. Keep functions small and documented; follow existing style (PEP 8).
4. Do not add features intended to intercept, decrypt, or exfiltrate
   traffic without explicit authorization (e.g. no built-in MITM/ARP
   spoofing). Keep this project focused on passive, authorized
   monitoring and analysis.
5. Open a pull request describing what changed and why.

## Reporting issues

Please include your Kali version, Python version (`python3 --version`),
and the exact command you ran.
