from nicegui import ui
import asyncio
from ICS_operations import ICSO
import sys
import time

def change_value(key, value_to_set, type, isco):
    if type=="register":
        isco.write_to_register(key, value_to_set)
    elif type=="coil":
        isco.write_to_coil(key, value_to_set)

    ui.navigate.reload()
   


def populate_tables(table,type,isco):
    register_meaning = ["Separator Valve Percent","Separator Pressure","Separator Temp","Flash Factor","Sep Press Optimal","Well Temp Factor","Optimal Valve Opening","Steam Flow","Wellhead Flow","Wellhead Pressure","Wellhead Temp","Max Wellhead Pressure","Max Wellhead Flow","Max Wellhead Temp","Max Separator Pressure","Max Separator Temp","Separator Level","Separator Drain Percent","Separator Drain","Max Separator Level","Turbine Exhaust Temp","Recent Wellhead Flow","Wellhead Override Pressure","MQTT Wellhead Pressure"]
    coil_meaning = ["Manual Override","ESD","Start System","Stop System","Pressure Release"]

    rows = []
    cntr = 0
    if type=="registers":
        for x in range(24):
            value = isco.read_register(x)
            new_row = {'register': str(x), 'value': '%.3f'%(value), 'meaning':register_meaning[cntr]}
            rows.append(new_row)
            table.rows = rows
            table.update()
            cntr+=1
    elif type=="coils":
        for x in range(5):
            value = isco.read_coil(x)[0]
            new_row = {'coil': str(x), 'value': value, 'meaning':coil_meaning[cntr]}
            rows.append(new_row)
            table.rows = rows
            table.update()
            cntr+=1



@ui.page('/')
async def main():
    # Initalize new ISCO object for querying PLC(s)
    isco = ICSO(sys.argv[1])

    ui.query('body').style('background-color: #c1c9d9;')
    with ui.row().classes('w-full items-start justify-between no-wrap gap-30'):
        with ui.column().classes('w-1/2'):
            with ui.expansion('Change Register Value', caption='[⇩] Press to expand menu').classes('w-full border border-gray-300 rounded-lg bg-white dark:bg-slate-900').style('color: #6E93D6; font-size: 200%; font-weight: 300'):
                with ui.row().classes('gap-x-20'):

                    with ui.column().classes('w-1/4'):

                        reg_input1 = ui.number(
                                    'Register',
                                    value=0
                                ).props('dense outlined').classes('w-32')
                        reg_input2 = ui.number(
                                    'Value',
                                    value=0.0,
                                    format='%.2f'
                                ).props('dense outlined').classes('w-32')

                        ui.button(
                                    'Submit',
                                    on_click=lambda: change_value(int(reg_input1.value), reg_input2.value, "register",isco)
                                ).style('color: #6E93D6')

            with ui.expansion('Change Coil Value', caption='[⇩] Press to expand menu').classes('w-full border border-gray-300 rounded-lg bg-white dark:bg-slate-900').style('color: #6E93D6; font-size: 200%; font-weight: 300'):
                with ui.row().classes('gap-x-20'):

                    with ui.column().classes('w-1/4'):

                        coil_input1 = ui.number(
                                    'Coil',
                                    value=0
                                ).props('dense outlined').classes('w-32')

                        coil_input2 = ui.toggle({1: 'TRUE', 2: 'FALSE'}, value=1)

                        ui.button(
                                    'Submit',
                                    on_click=lambda: change_value(int(coil_input1.value), coil_input2.value, "coil",isco)
                                ).style('color: #6E93D6')


        with ui.column().classes('w-1/2'):
            with ui.row().classes('w-full items-start'):
                await ui.context.client.connected()

                with ui.column().classes('flex-1 min-w-0'):
                    ui.label('Registers').classes('text-h6 font-bold mb-2')
                    register_columns = [
                            {'name': 'register', 'label': 'Register', 'field': 'register', 'required': True, 'align': 'left'},
                            {'name': 'value', 'label': 'Value', 'field': 'value', 'required': True, 'align': 'left'},
                            {'name': 'meaning', 'label': 'Meaning', 'field': 'meaning', 'required': True, 'align': 'left'},
                        ]
                    register_init_table = ui.table(columns=register_columns, rows=[], row_key='register').props('no-data-label="Populating register data, please wait..."')
                    
                    print("[!] Now populating initial register table.")
                    loop = asyncio.get_running_loop()
                    while True:
                        try:
                            await loop.run_in_executor(None, lambda: populate_tables(register_init_table,"registers",isco))
                            break
                        except Exception as e:
                            print(f"{e}: Error occured while populating table, trying again...")
                    print("[✔] Populated initial register table.")

                with ui.column().classes('flex-1 min-w-0'):
                    ui.label('Coils').classes('text-h6 font-bold mb-2')
                    coil_columns = [
                            {'name': 'coil', 'label': 'Coil', 'field': 'coil', 'required': True, 'align': 'left'},
                            {'name': 'value', 'label': 'Value', 'field': 'value', 'required': True, 'align': 'left'},
                            {'name': 'meaning', 'label': 'Meaning', 'field': 'meaning', 'required': True, 'align': 'left'},
                        ]
                    coil_init_table = ui.table(columns=coil_columns, rows=[], row_key='coil').props('no-data-label="Populating coil data, please wait..."')

                    print("[!] Now populating initial coil table.")
                    loop2 = asyncio.get_running_loop()
                    while True:
                        try:
                            await loop2.run_in_executor(None, lambda: populate_tables(coil_init_table,"coils",isco))
                            break
                        except Exception as e:
                            print(f"{e}: Error occured while populating table, trying again...")
                    print("[✔] Populated initial coil table.")


ui.run(host="0.0.0.0",port=1337,title='CyberRamblers ICS',show=False,favicon='VDL_Logo.png')