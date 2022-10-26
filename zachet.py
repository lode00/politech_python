# Использовал питон 3.10
# netifaces не поддерживается, ищут мэйнтейнера. 
# так написано тут https://pypi.org/project/netifaces/
# поэтому использую psutil
#https://docs.python.org/3/library/email.policy.html
from email.policy import strict
# Библиотека для подключения к портам
import socket
#для получения сведений об аппаратной платформе, операционной системе и интерпретаторе на которой выполняется программа.
import platform
import ipaddress
#позволяет создавать новые процессы
import subprocess

import psutil
# Модуль для оформления вывода в виде таблиц
from tabulate import tabulate


#функция для вывода в "красивой форме"
def update_progress_bar(i, total, prefix='', fill='█', length=48):
    '''
    Функция для печати прогрессбара
    i: int
        текущая итерация
    total: int
        всего итераций
    prefix: str
        печатать до прогрессбара
    fill: str
        заполнитель прогрессбара
    length: int
        длина прогрессбара
    '''
    frac = i / total
    nf = int(frac * length)
    bar = f' {prefix} {fill * nf:░<{length}} {frac * 100:5.1f}%'
    print(bar, end='\r')
    if i == total:
        print()

 
def netmask4_to_cidr(netmask):
    '''
    преобразует ipv4 маску в число cidr
    >>> netmask('255.255.255.0')
    24
    >>> netmask('255.255.255.192')
    26
    '''
    return sum(
        f'{int(x):b}'.count('1') 
        for x in netmask.split('.')
    )


def netmask6_to_cidr(netmask):
    '''
    маску преобразует в число cidr
    >>> netmask('255.255.255.0')
    24
    >>> netmask('255.255.255.192')
    26
    >>> netmask('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    128
    '''
    return sum(
        f'{int(x or "0", 16):b}'.count('1') 
        for x in netmask.split(':')
    )


def check_port(ip, port):
    '''
    Функция возвращает True если порт открыт, иначе False
    SOCK_STREAM  означает что это TCP socket.
    '''
    family, kind, _, _, address = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM)[0]
    sock = socket.socket(family, kind)
    sock.settimeout(0.5)
    result = sock.connect_ex(address)
    return result == 0
    # with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
    #     result = sock.connect_ex((ip, port))
    # return result == 0

def fn_ipaddresses():
    '''
    Функция перечислияющая сетевые интерфейсы
    return: dict
        {
            'ipv4': [(IP-address, Net-prefix), ...],
            'ipv6': [(IP-address, Net-prefix), ...]
        }
    AF_INET для сетевого протокола IPv4
    AF_INET6 для IPv6
    '''
    local_addrs = {'ipv4': [], 'ipv6': []}

    interfaces = psutil.net_if_addrs() #взял отсюда https://stackoverflow.com/questions/3837069/how-to-get-network-interface-card-names-in-python
    for _, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                cidr = netmask4_to_cidr(addr.netmask)
                local_addrs['ipv4'].append((addr.address, cidr))
            if addr.family == socket.AF_INET6:
                cidr = netmask6_to_cidr(addr.netmask)
                local_addrs['ipv6'].append((addr.address, cidr))
    return local_addrs


def port_scan(addrs):
    '''
    Функция, сканирующая порты на доступность

    addrs: dict
        словарь, потученный от функции fn_ipaddresses

    return: 
        кортеж из имен файлов с открытыми и закрытыми портами
    '''
    num_ports = 2**16 # сканируются порты от 1 до num_ports
    op_filename = 'opened_ports.txt' 
    cp_filename = 'closed_ports.txt'
    with open(op_filename, 'w') as op_file, \
         open(cp_filename, 'w') as cl_file:
        for ip_iface, cidr in (*addrs['ipv4'], *addrs['ipv6']):
            ip = ipaddress.ip_interface(f'{ip_iface}/{cidr}').ip.compressed
            print(f'\nСканирование IP-адреса {ip}')
            opened, closed = [], []
            for port in range(1, num_ports):
                store = opened if check_port(ip, port) else closed
                store.append(str(port))      
                update_progress_bar(port, num_ports - 1)
            if opened: op_file.write(f'IP-адрес: {ip}, порты {", ".join(opened)}\n')
            if closed: cl_file.write(f'IP-адрес: {ip}, порты {", ".join(closed)}\n')
    return op_filename, cp_filename


def ping(ip):
    '''
    ip: str
        ip адрес
    return: bool
        доступность ip
    '''
    stop_after = '-n' if platform.system()=='Windows' else '-c'
    command = ['ping', stop_after, '1', ip]
    # возвращает 0, если пингуется DEVNULL подавляет вывод stdout или stderr
    res = subprocess.call(command, stdout=subprocess.DEVNULL)
    return res == 0


def fn_ipaccess(ips):
    '''
    ips: list[str]
        список ip адресов
    return: tuple
        кортеж из списка доступных и недоступных ip адресов
    '''
    available, unavailable = [], [] 
    for ip in ips:
        store = available if ping(ip) else unavailable
        store.append(ip)
    return available, unavailable


def main():
    '''
    Функция main немоходима для вызова остальных ф-ций модуля:
        fn_ipaddresses();
        fn_portscan();
        fn_ipaccess().6
    '''
    rule = '\n\n\n' + '-' * 70


    print('Сканирование интерфейсов')
    local_addrs = fn_ipaddresses()
    print(tabulate(local_addrs, headers='keys', tablefmt='grid'))


    print(rule)
    print('Сканирование портов')
    filenames, ns = [], []
    for filename in port_scan(local_addrs):
        filenames.append(filename)
        with open(filename) as f:
            ns.append(f.read().count('\n'))

    port_stat = {'Имя файла': filenames, 'Колличество строк': ns}
    print(tabulate(port_stat, headers='keys', tablefmt='grid'))


    print(rule)
    print('Сканирование IP адресов на доступность')
    # получение списка ipv4 и ipv6 адресов
    local_ip_address = [addr[0] for addr in (*local_addrs['ipv4'], *local_addrs['ipv6'])]
    available, unavailable = fn_ipaccess(local_ip_address)
    ip_available_stat = {'Доступные': available, 'Недоступные': unavailable}
    print(tabulate(ip_available_stat, headers='keys', tablefmt='grid'))



if __name__ =="__main__": # если скрипт запущен непосредственно, а не импортируется
    main()
