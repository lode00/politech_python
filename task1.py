##Денис Лобач. Python


##Задание:уравнение
##x=5
##y=2.3
##z=2
##f=7.8
##g=(((x*(y-x))/z)+x)
##h=(f+z)
##t=((h/(f**y))-(z-f)/z)
##print ((g+t)/(h/(z**y)-f))

#Задание: перевод  в различные счисления
##с=int(input("из 10 в 2: "))
##print(bin(c))
##b=int(input("из 2 в 10: "),2)
##print(b)
##a=int(input("from 16 to 10: "),16)
##print(a)
##d=int(input("from 10 to 16: "))
##print(hex(d))
##e=hex(input("16 в 2: "))
##print(bin(e))
##с= input("из 2 в 16: ")
##с= int(r,2)
##print(с)

#Практика1

#Вычислим 2^2019
##print(2**2019)
#cколько 7 в 136
##print(round(136/7))
#вывести 121 раз
##print('A'*121)
#cтроки вывести из знаков =
##N=5
##print("="*1)
##print('='*2)
##print('='*3)
##print('='*4)
##print('='*N)

##5) Число 2019 запишите 40 раз подряд. Результат возведите в квадрат. Что получилось?
##2019 40 раз записать и возвести в ^
##print(int('2019'*40)**2)
 
 
#Практика2

##1. Запросите у пользователя два целых числа. Выведите значение наименьшего из них

##x= int(input("Введи число x:"))
##y= int(input("Введи число y:"))
##if x>y:
##print("x больше y, значение x =", x)
##elif x print("y больше x,значение x =", y)
##else:
##print("y=x")

##2. Запросите у пользователя три целых числа. Выведите значение
##наименьшего из них
##x= int(input("Введи число x:"))
##y= int(input("Введи число y:"))
##z= int(input("Введи число z:"))
##if x>y>z:
##print("x самый большой и равен",x)
##elif y>z>x:
##print("y самый большой и равен",y)
##elif z>x>y:
##print("y самый большой и равен",z)
##else:
##print("все 3 числа одинаковые")

##3. Для заданного числа x выведите значение sign(x). Эту задачу
##желательно решить с использованием каскадных инструкций
##if...elif...else…

##x = int (input ('Введите значние Х: '))
##if x > 0:
##   print ('sign(x)=1')
##elif x == 0:
##   print ('sign(x)=0')
##else:
##    print ('sign(x)=-1')

#while practice
#1. Каждый день я пробегаю «следующую степень двойки» км.
#Сколько дней пройдет, пока я в сумме пробегу 1000 км?
#10000 км?

##
##n = 2
##c = 0
##s = 0
##while s < 1000:
##    s = s + n
##    c = c + 1
##    n = n * 2
##print ("За", c, 'дней спортсмен пробежит 1000км')

##2. Начав тренировки, спортсмен в первый день пробежал 10
##км. Для увеличения выносливости ему необходимо
##повышать норму бега через одну тренировку на 15% от
##нормы предыдущей тренировки. Спортсмен тренируется
##каждый день. Какой суммарный путь он пробежит за 30
##дней.
##
##km = 10
##day = 30
##allkm = 0
##while day > 0:
##    if day % 2 == 0:
##        km = km + (km * 0.15)
##    else:
##        allkm = allkm = km
##    day = day - 1
##print ('Спортсмен пробежал', allkm, 'км. за 30 дней')


##t= input ('Введите последний актет: ')
##if t <= '255' and t >= '0':
## print ('Правильно')
##elif t < '0':
## print ('НЕ правильно')
##else:
## print ('НЕ правильно')

## reverse
##num= 12345
##print(str(num)[::-1])

#Задания на For

# Вывести прямоугольную рамочку из звёздочек, шириной А
#звёздочек и высотой В
##a = int (input ('Введите шрину: '))
##v = int (input ('Введите высоту: '))
##print("* " * a)
##for r in range(v):
##    print("* ", "  " * (a - 3), "*")
##print("* " * a)


##Даны натуральные числа А и В. Вывести сначала все чётные
##числа, заключённые между ними, потом все нечётные
##a = int (input ('Введите число А: '))
##b = int (input ('Введите число В: '))
##for i in range (a,b + 1):
##    if i % 2 == 0:
##        print (i)
##    continue
##
##for r in range (a,b + 1):
##    if r % 2 != 0:
##        print (r)


# Исходный список содержит положительные и отрицательные
#числа. Требуется положительные поместить в один список, а
#отрицательные - в другой

##a = [1, 2, 3, 4, 5, -1, -2, -3, -4, -5]
##b = []
##c = []
##for i in a:
##    if i > 0:
##        b.append(i)
##    elif i < 0:
##        c.append(i)
##print (b)
##print (c)

# Вывести квадраты нечетных чисел до N
##a = int (input ('Введи число: '))
##number = 0
##for number in range (a):
##    if number % 2 != 0:
##        print (number ** 2) 


#Задания на if
##Написать программу, которая:
##1. Автор задумывает число (из интервала от 1 до 100).
##2. Пользователь это число отгадывает: вводит свои варианты, получает
##ответы "больше, "меньше" или "да, это оно".
##• Уровень 1: играется всего одна партия
##• Уровень 2: в конце игры у пользователя спрашивают, хочет ли он
##сыграть ещё. Ведётся подсчёт партий.
##• Уровень 3: у пользователя есть лимит в 50 ходов на все партии, пока
##он его не исчерпал - играет. Ведётся подсчёт законченных партий.

##import random
##s = 0
##numbers = random.randint (1,100)
##restart = 'да'
##while restart == 'да':
##    while chpop < 50:
##        s = int (input ('Попробуй угадать число: '))
##        chpop += 1
##        if s < number:
##            print ('Попробуй большее значение')
##        elif s > number:
##            print ('Попробуй меньшее значение')
##        elif s == number:
##            break
##    if s == number:
##        print ('Ты угадал! Моё число - ', number,'.' ' На это тебе понадобилось', chpop, 'попыток!')
##        restart = input ('Хотите еще сыграть? да\нет ')
##        s = 0
##    else:
##        print ('К сожалению ты потратил все попытки и не угадал число ', number)
##        restart = input ('Хотите еще сыграть? да\нет ')
##        s = 0
##        break 
##print ('Спасибо за игру!')


##1. С клавиатуры вводится число n.
##Вычислить сумму S = 1/1 + 1/2 + 1/3 + ...+ 1/n
##n = int (input ('Число: '))
##summa = 0
##for i in range (1, n + 1):
##    summa += (1 / i)
##    print (summa)
##print ('Общая сумма чисел равна:', summa)

##2. Вводится число n.
##Необходимо перевернуть его. Например: 12345 54321
##n = input ('Введи число: ')[::-1]
##print (n)

##3. На вход программе подается последовательность целых чисел,
##заканчивающаяся числом 0.
##Выведите их среднее арифметическое, 0 при этом членом
##последовательности не считается.

 
##Домашнее задание
##1. Для настольной игры используются карточки с номерами от 1
##до N. Одна карточка потерялась. Найдите ее, зная номера
##оставшихся карточек.
##а) Введите число N – количество карточек.
##б) Далее введите N−1 различных чисел в диапазоне от 1 до N - номера
##оставшихся карточек.
##в) Программа должна вывести номер потерянной карточки.
##2. Задача «Удалить каждый третий символ».
##г) Дана строка.
##д) Удалите из нее все символы, чьи индексы делятся на 3.


##n=int(input("Введите количество карточек: "))
##s=0
##for i in range(1,n+1):
##    s+=i
##for i in range(n-1):
##    x=int(input("Введите известные карточки: "))
##    s-=x
##print(s)


##s = input("Введите что-нибудь: ")
##t = ''
##for i in range(len(s)):
## if i % 3 != 0:
## t = t + s[i]
##print(t)