Tools for use in the 2026 DOE CyberForce competition.

The ICS folder contains a web GUI for manipulating registers and coils over the modbus protocol without needing to log onto to the PLC or HMI machine(s) directly. You can run it using the command from the base LUC-CyberForce-2026 folder:
```bash
pip3 install -r ICS/requirements.txt
python3 ICS/ICS_gui.py IP_ADDRESS
```
then navigate to localhost:1337.
