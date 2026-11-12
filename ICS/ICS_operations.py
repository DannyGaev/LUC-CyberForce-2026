from pyModbusTCP.client import ModbusClient
import struct

# Value conversions are based on IEEE-754 Floating Point (https://www.h-schmidt.net/FloatConverter/IEEE754.html)
# Connect to the PLC machine

class ICSO:
    def __init__(self, address):
        self.client = ModbusClient(host=address, auto_open=True, auto_close=True)

    # Reads a coil value
    def read_coil(self,coil_key):
        coil_value = self.client.read_coils(coil_key,1)
        return coil_value

    # Writes a Boolean (True/False) value to the specified coil. Coils store binary values, and
    # so can only hold True/False values.
    def write_to_coil(self,coil_key, value_to_set):
        if value_to_set == "T" or value_to_set == 1:
            value_to_set = "TRUE"
        bit = True if value_to_set=="TRUE" else False
        result = self.client.write_single_coil(coil_key, bit)
        return result

    # Reads the value of a specified register
    def read_register(self,register_key):
    # As per the ICS documentation, register addresses begin at offset 2048.
    # We apply a calculation to the initial offset to reach the address that corresponds
    # to the specified register. We read two registers from the address, as the values are 32 bits and # their representation is divided across two registers.
        result = self.client.read_holding_registers(2048+(register_key*2), 2)
        split_result = result
        combined_hex = "" # Take each returned portion of the value (integer format) and convert it to hex
        for sr in split_result:
            formatted = (str(hex(sr))).replace("0x", "")
            if formatted == "0":
                formatted += "000"
            combined_hex += formatted

        # Add padding where necessary to ensure proper conversion
        while len(combined_hex) != 8:
            combined_hex += "0"

        # Convert the combined hex values back into a decimal value
        register_value = struct.unpack('!f', bytes.fromhex(combined_hex))[0]
        return register_value


    # Writes a number value to the specified register
    def write_to_register(self, register_key, value_to_set):
        try:
            # Converts the passed number value to its hexadecimal representation, taking into account floating point format
            hex_writing = str(hex(struct.unpack('<I', struct.pack('<f', value_to_set))[0])).replace("0x","")
            length_of_hex = len(hex_writing)
            # Split the entire hex value in half, so as to write the different halves to their respective registers
            split_result = [hex_writing[0:int(length_of_hex/2)], hex_writing[int(length_of_hex/2):]]
            integer_results = []
            # Convert each hex half into its integer representation (simply appending 0 when a 0 is passed to be written)
            for sr in split_result:
                if sr != "":
                    integer_results.append(int(sr, 16))
                else: integer_results.append(0)
                # Write the integer values to their respective registers
                self.client.write_single_register(2048+(register_key*2),integer_results[0])
                self.client.write_single_register(2048+(register_key*2)+1, integer_results[1])
                return 1
        except:
            return 0