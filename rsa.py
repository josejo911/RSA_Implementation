'''
JOSE JAVIER JO ESCOBAR
14343

Implementacion de algoritmo RSA criptografico
Se seleccionan dos numeros primos aleatorios de un archivo de texto y son usados para la produccion de claves publicas y privadas.
Con las llaves se puede cifrar o decifrar mensajes usando el algoritmo de RSA.

Los archivos de texto de la llaves privadas y publicas leeran la primera linea n y la segunda linea  sea 'e' o 'd'.

'''

import random

def mcd(a, b):
    """
    Algoritmo euclideano que devuelve el maximo comun divisor de a y b
    """
    if (b == 0):
        return a
    else:
        return mcd(b, a % b)

def xmcd(a, b):
    """
    Algoritmo euclideano extendido utilizado para retornar el maximo comun divisor y los coeficientes de a y b
    """
    x, old_x = 0, 1
    y, old_y = 1, 0

    while (b != 0):
        cociente = a // b
        a, b = b, a - cociente * b
        old_x, x = x, old_x - cociente * x
        old_y, y = y, old_y - cociente * y

    return a, old_x, old_y

def selE(toti):
    """
    Seleccionamos un numero random que este entre 1<e<toti y verificamos si es no coprimo
    el mcd  de e y toti debe ser 1
    """
    while (True):
        e = random.randrange(2, toti)

        if (mcd(e, toti) == 1):
            return e

def selKey():
    """
    - Agarramos dos numeros primos aleatorios en la lista de 100k que tenemos
    - Creamos un archivo de texto donde almacenamos dos numeros que se utilizaran despues
    - Con los numeros primos seleccionados almacenamos la llave publica y privada en dos archivos separados
    """
    
    rand1 = random.randint(100, 300)
    rand2 = random.randint(100, 300)

    fo = open('100kprimos.txt', 'r')
    lines = fo.read().splitlines()
    fo.close()

    prime1 = int(lines[rand1])
    prime2 = int(lines[rand2])

    n = prime1 * prime2
    toti = (prime1 - 1) * (prime2 - 1)
    e = selE(toti)
    mcd, x, y = xmcd(e, toti)

    if (x < 0):
        d = x + toti
    else:
        d = x

    f_public = open('public_keys.txt', 'w')
    f_public.write(str(n) + '\n')
    f_public.write(str(e) + '\n')
    f_public.close()

    f_private = open('private_keys.txt', 'w')
    f_private.write(str(n) + '\n')
    f_private.write(str(d) + '\n')
    f_private.close()

def cifrar(msj, file_name = 'public_keys.txt', block_size = 2):
    """
    - Ciframos el mensaje elevando el valor ASCII de cada carácter a
      la e y tomando el módulo de n.
    - Devolvemos la cadena de numeros
    - El File_name es el archivo donde se encuentra la llave publica si no se da un archivo
      vamos a asumir que vamos a cifrar con nuestra propia llave publica
    - Block_size es referido a  cuantos caractecteres formamos en un grupo de numeros en cada indice de los bloques cifrados
    """

    try:
        fo = open(file_name, 'r')

    except FileNotFoundError:
        print('Wee no encontre nada ')
    else:
        n = int(fo.readline())
        e = int(fo.readline())
        fo.close()

        encrypted_blocks = []
        ciphertext = -1

        if (len(msj) > 0):
            # Iniciamos el texto cifrado con el ASCII del primer caracter del mensaje
            ciphertext = ord(msj[0])

        for i in range(1, len(msj)):
            if (i % block_size == 0):
                encrypted_blocks.append(ciphertext)
                ciphertext = 0

            # Multiplicamos por 1000 para cambiar el digito para la izquierda por 3 espacios ya que los codigos ASCII son de un maximo de 3 digitos decimales
            ciphertext = ciphertext * 1000 + ord(msj[i])

        encrypted_blocks.append(ciphertext)

        for i in range(len(encrypted_blocks)):
            encrypted_blocks[i] = str((encrypted_blocks[i]**e) % n)

        encrypted_message = " ".join(encrypted_blocks)

        return encrypted_message

def decifrar(blocks, block_size = 2):
    """
    - Deciframos la cadena de numeros elevando cada numero a la potencia de 'd' y sacamos el modulo de 'n'
    - Retornamos el mensaje como un string
    """

    fo = open('private_keys.txt', 'r')
    n = int(fo.readline())
    d = int(fo.readline())
    fo.close()

    list_blocks = blocks.split(' ')
    int_blocks = []

    for s in list_blocks:
        int_blocks.append(int(s))

    msj = ""

    # Convertimos cada int de la lista a bloques de numeros de caracteres
    for i in range(len(int_blocks)):
        # Deciframos todos los numeros haciendo la potencia 'd' y aplicando modulo 'n'
        int_blocks[i] = (int_blocks[i]**d) % n
        
        tmp = ""
        # Separamos cad bloque en los sus codigos ascii para cada caracter y lo guardamos en el string del mensaje
        for c in range(block_size):
            tmp = chr(int_blocks[i] % 1000) + tmp
            int_blocks[i] //= 1000
        msj += tmp

    return msj

def main():
    # Seleccionamos los primos para generar la llave publica y llave privada,
    choose_again = input('Desea generar una nueva llave publica y privada? (s/n) ')
    if (choose_again == 's'):
        selKey()

    instruction = input('Le gustaria cifrar o decifrar? (Ingrese c ó d): ')
    if (instruction == 'c'):
        msj = input('Que mensaje quiere cifrar?\n')
        option = input('Le gustaria cifrar el mensaje utilizando su propia llave publica? (s/n) ')

        if (option == 's'):
            print('Cifrando...')
            print(cifrar(msj))
        else:
            file_option = input('Ingrese el nombre del archivo que almacena la llave publica: ')
            print('Cifrando...')
            print(cifrar(msj, file_option))

    elif (instruction == 'd'):
        msj = input('Ingrese el mensaje que desea desencriptar\n')
        print('Decifrando...')
        print(decifrar(msj))
    else:
        print('Ke pedo con tu mensaje weeee :S')

main()