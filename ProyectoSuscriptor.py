import paho.mqtt.client as mqtt

# Imprimir texto plano en formato hexadecimal
def _print_hexaformat(plaintext):
    if plaintext is None:
        return '0x0000'
    return '0x{0:02x}'.format(plaintext)


class Simon:
    # Variables iniciales.
    def __init__(self, cypher_key):
        # Llave de cifrado
        self.cypher_key = cypher_key
        # Tamaño del bloque para el algoritmo (16)
        self.BLOCK_SIZE = 16
        # Constantes para generar la siguiente llave
        self.Z_0 = 0x19C3522FB386A45F
        self.CONSTANT = 0xFFFC
        # Constante del numero de rondas
        self.ROUND_NUMBER = 32

    # Funcion para hacer corrimiento a la derecha
    def _shift_right(self, plain_text, digits):
        shift_value = (plain_text >> digits) | (plain_text << (self.BLOCK_SIZE - digits))
        return self._trim_to_16_bits(shift_value)

    # Funcion para hacer corrimiento a la izquierda
    def _shift_left(self, plain_text, digits):
        shift_value = (plain_text << digits) | (plain_text >> (self.BLOCK_SIZE - digits))
        return self._trim_to_16_bits(shift_value)

    # Funcion para hacer xor
    def _xor(self, plain_text_a, plain_text_b):
        return plain_text_a ^ plain_text_b

    # Calcular la constante que se utiliza cuando se genera el siguiente Ki
    def _calculate_constant(self, round_number):
        # Revisar si el i-esimo bit esta encendido o no
        if ((self.Z_0 & (1 << round_number)) > 0):
            return self._xor(self.CONSTANT, 1)
        else:
            return self.CONSTANT

    # Recortar los resultados a 16 bits para ser consistentes con el algoritmo
    def _trim_to_16_bits(self, plain_text):
        return plain_text & 0xFFFF

    # Generacion de la llave de la ronda numero round_number
    def _generate_next_key(self, round_number, key_i, key_i_1, key_i_2, key_i_3):
        step_1 = self._shift_right(key_i_3, 3)
        step_2 = self._xor(step_1, key_i_1)
        step_3 = self._xor(step_2, key_i)
        step_4 = self._shift_right(step_2, 1)
        step_5 = self._xor(step_3, step_4)
        round_constant = self._calculate_constant(round_number)
        step_6 = self._xor(step_5, round_constant)
        return self._trim_to_16_bits(step_6)

    # Funcion para generar todas las 32 llaves
    def _generate_keys(self):
        keys = [0] * self.ROUND_NUMBER
        keys[0] = self._trim_to_16_bits(self.cypher_key)
        keys[1] = self._trim_to_16_bits(self.cypher_key >> 16)
        keys[2] = self._trim_to_16_bits(self.cypher_key >> 32)
        keys[3] = self._trim_to_16_bits(self.cypher_key >> 48)

        for i in range(0, self.ROUND_NUMBER - 4):
            keys[i + 4] = self._generate_next_key(i, keys[i], keys[i + 1], keys[i + 2], keys[i + 3])
        # [print(_print_hexaformat(key)) for key in keys]
        return keys

    # Ejecucion de la ronda de Simon. Recibe las dos entradas, las llaves y el numero de la ronda
    def _simon_encryption_round(self, input_1, input_2, keys, round_number):
        step_1 = self._shift_left(input_1, 1)
        step_2 = self._shift_left(input_1, 8)
        step_3 = step_1 & step_2
        step_4 = self._xor(step_3, input_2)
        step_5 = self._shift_left(input_1, 2)
        step_6 = self._xor(step_5, step_4)
        step_7 = self._xor(step_6, keys[round_number])
        return step_7, input_1

    # Cifrar texto plano utilizando el algoritmo
    def encrypt_text(self, plain_text):
        # Generar las 32 llaves del algoritmo
        keys = self._generate_keys()

        # Separar el texto en 2 bloques de 16 bits
        input_1 = self._trim_to_16_bits(plain_text >> 16)
        input_2 = self._trim_to_16_bits(plain_text)
        output_1 = output_2 = 0

        # Ejecucion de las 32 rondas
        for round in range(0, self.ROUND_NUMBER):
            # Ejecutar la funcion F de cifrado
            output_1, output_2 = self._simon_encryption_round(input_1, input_2, keys, round)
            input_1 = output_1
            input_2 = output_2

        # Concatenar el resultado en una unica cadena
        return (output_1 << 16) | output_2

    # Decifrado de una cadena de texto
    def decrypt_text(self, plain_text):
        # Generar las 32 llaves del algoritmo
        keys = self._generate_keys()

        # Separar el texto en 2 bloques de 16 bits
        input_2 = self._trim_to_16_bits(plain_text >> 16)
        input_1 = self._trim_to_16_bits(plain_text)
        output_1 = output_2 = 0

        # Ejecucion de las 32 rondas
        for round in range(self.ROUND_NUMBER, 0, -1):
            # Ejecutar la funcion F de cifrado con las llaves al revés
            output_1, output_2 = self._simon_encryption_round(input_1, input_2, keys, round - 1)
            input_1 = output_1
            input_2 = output_2

        # Concatenar el resultado en una unica cadena
        return (output_1 << 16) | output_2


# Variables simon
CYPHER_KEY = 0x0123456789ABCDEF
simon = Simon(CYPHER_KEY)


# Funcion que se llama cuando se recibe el ConACK de parte del broker
def on_connect(client, userdata, flags, reason_code, properties):
    # Imprimir el resultado de la conexion
    print(f'flags: {flags} result_code: {reason_code}')


# Funcion que se llama cuando se recibe un mensaje
def on_message(client, userdata, msg):
    # Mensaje
    print(f'Mensaje cifrado: {msg.payload}')
    mensaje_decifrado = simon.decrypt_text(int(msg.payload))
    print(f'Mensaje decifrado hexa: {_print_hexaformat(mensaje_decifrado)}')
    # Convertir a 1 cifra decimal
    print(f'Mensaje decifrado decimal: {mensaje_decifrado * 0.1}')


# Funcion principal
if __name__ == '__main__':
    # Inicializacion del cliente
    mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqtt.on_connect = on_connect
    mqtt.on_message = on_message

    # Usuario y contraseña
    mqtt.username_pw_set(username="oscar", password="oscar")

    # Puerto e IP
    mqtt.connect('192.168.24.93', 1883, 60)

    # Topico al que se suscribe
    topic = '/puj/embebidos'
    mqtt.subscribe(topic)

    # Ciclo infinito para leer de ese topico
    mqtt.loop_forever()
