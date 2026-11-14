from ICS_operations import ICSO

# [FIRST STEP BEFORE ANYTHING ELSE] Make sure the "Enable Pressure Release Valve" option is not selected.


isco = ICSO("10.0.15.144")
isco.write_to_register(0,0.5) # Drainage valve will increase to 100%, which is okay. 
isco.write_to_coil(4,0) 

# Power generation readout should soon read ~17-18 MW! 