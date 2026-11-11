from nicegui import ui
import asyncio
from ICS_operations import ICSO
import sys


def change_value(key, value_to_set, temp_table, type, init_table, isco):
    if type=="register":
        isco.write_to_register(key, value_to_set)
        double_check = isco.read_register(key)
    elif type=="coil":
        isco.write_to_coil(key, value_to_set)
        double_check = isco.read_coil(key)[0]

    temp_table.rows = []
    temp_table.update()

    new_row = {f'{type}': str(key), 'value': double_check}
    temp_table.rows.append(new_row)
    temp_table.update()

    for row in init_table.rows:
        if row[type] == str(key):
            row['value'] = double_check
   


def populate_tables(table,type,isco):
    register_meaning = ["Separator Valve Percent","Separator Pressure","Separator Temp","Flash Factor","Sep Press Optimal","Well Temp Factor","Optimal Valve Opening","Steam Flow","Wellhead Flow","Wellhead Pressure","Wellhead Temp","Max Wellhead Pressure","Max Wellhead Flow","Max Wellhead Temp","Max Separator Pressure","Max Separator Temp","Separator Level","Separator Drain Percent","Separator Drain","Max Separator Level","Turbine Exhaust Temp","Recent Wellhead Flow","Wellhead Override Pressure","MQTT Wellhead Pressure"]
    coil_meaning = ["Manual Override","ESD","Start System","Stop System","Pressure Release"]

    rows = []
    cntr = 0
    if type=="registers":
        for x in range(24):
            value = isco.read_register(x)
            new_row = {'register': str(x), 'value': value, 'meaning':register_meaning[cntr]}
            rows.append(new_row)
            cntr+=1
    elif type=="coils":
        for x in range(5):
            value = isco.read_coil(x)[0]
            new_row = {'coil': str(x), 'value': value, 'meaning':coil_meaning[cntr]}
            rows.append(new_row)
            cntr+=1
    table.rows = rows
    table.update()


@ui.page('/')
async def main():

    # Initalize new ISCO object for querying PLC(s)
    isco = ICSO(sys.argv[1])

    # Enable dark mode option
    ui.colors(
        primary='#c1c9d9',
        dark='#1e1e2e',
        dark_page='#11111b',
        accent='#cba6f7'
    )
    dark = ui.dark_mode()
    ui.switch('Dark mode').bind_value(dark)

    ui.query('body').style('background-color: #c1c9d9;')
    ui.add_head_html('''
        <style>
        /* Expansion header */
        body.body--dark .q-expansion-item > .q-item {
            background-color: #0f172a !important;
            color: #e2e8f0 !important;
        }

        /* Expansion content */
        body.body--dark .q-expansion-item__content {
            background-color: #0f172a !important;
            color: #e2e8f0 !important;
        }

        /* Nested white backgrounds */
        body.body--dark .q-expansion-item__content .bg-white {
            background-color: #0f172a !important;
        }

        /* Borders */
        body.body--dark .q-expansion-item__content .border-gray-300 {
            border-color: #334155 !important;
        }
        </style>
    ''')
    with ui.row().classes('w-full items-start justify-between no-wrap gap-50'):
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
                                    on_click=lambda: change_value(int(reg_input1.value), reg_input2.value, temp_reg_table, "register",register_init_table,isco)
                                ).style('color: #6E93D6')
                    with ui.column().classes('flex-1'):

                        columns = [
                                {'name': 'register', 'label': 'Register', 'field': 'register', 'required': True, 'align': 'left'},
                                {'name': 'value', 'label': 'Value', 'field': 'value', 'required': True, 'align': 'left'},
                                {'name': 'meaning', 'label': 'Meaning', 'field': 'meaning', 'required': True, 'align': 'left'},
                            ]
                        with ui.column().classes('w-full'):
                            ui.label('Live Feed of Updated Register').classes('text-lg font-bold')
                            temp_reg_table = ui.table(columns=columns, rows=[], row_key='register').props('no-data-label="No registers edited yet."')


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
                                    on_click=lambda: change_value(int(coil_input1.value), coil_input2.value, temp_coil_table, "coil", coil_init_table,isco)
                                ).style('color: #6E93D6')
                    with ui.column().classes('flex-1'):

                        columns = [
                                {'name': 'coil', 'label': 'Coil', 'field': 'coil', 'required': True, 'align': 'left'},
                                {'name': 'value', 'label': 'Value', 'field': 'value', 'required': True, 'align': 'left'},
                                {'name': 'meaning', 'label': 'Meaning', 'field': 'meaning', 'required': True, 'align': 'left'},
                            ]
                        with ui.column().classes('w-full'):
                            ui.label('Live Feed of Updated Coil').classes('text-lg font-bold')
                            temp_coil_table = ui.table(columns=columns, rows=[], row_key='coil')


        with ui.column().classes('w-1/2'):
            with ui.row().classes('w-full items-start gap-4'):
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
                        except:
                            print("Error occured while populating table, trying again...")

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
                        except:
                            print("Error occured while populating table, trying again...")

                    print("[✔] Populated initial coil table.")


ui.run(host="0.0.0.0",port=1337,title='CyberRamblers ICS',show=False,favicon='VDL_Logo.png')