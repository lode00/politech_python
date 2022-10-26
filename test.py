'''
Импортируем основной модуль zachet.py. 
Запускаем функцию fn_ipaddresses и выводим в консоль результат ее выполнения. 
Убеждаемся, что код функции main из модуля zachet.py не выполняется.
'''


import zachet
from zachet import fn_ipaddresses, fn_ipaccess


local_addrs = fn_ipaddresses()
local_ip_address = [addr[0] for addr in (*local_addrs['ipv4'], *local_addrs['ipv6'])]
out = fn_ipaccess(local_ip_address)

print('Результат выполнения функции fn_ipaccess')
print(out)

