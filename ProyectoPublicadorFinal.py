import serial
import time
import paho.mqtt.client as mqtt

# Imprimir texto plano en formato hexadecimal
def _print_hexaformat(plaintext):
    if plaintext is None:
        return '0x0000'
    return '0x{0:02x}'.format(plaintext)

class Simon:
    # Variables iniciales.
    def __init__(self, cypher_key):
        self.cypher_key = cypher_key
        self.BLOCK_SIZE = 16
        self.Z_0 = 0x19C3522FB386A45F
        self.CONSTANT = 0xFFFC
        self.ROUND_NUMBER = 32

    def _shift_right(self, plain_text, digits):
        shift_value = (plain_text >> digits) | (plain_text << (self.BLOCK_SIZE - digits))
        return self._trim_to_16_bits(shift_value)

    def _shift_left(self, plain_text, digits):
        shift_value = (plain_text << digits) | (plain_text >> (self.BLOCK_SIZE - digits))
        return self._trim_to_16_bits(shift_value)

    def _xor(self, plain_text_a, plain_text_b):
        return plain_text_a ^ plain_text_b

    def _calculate_constant(self, round_number):
        if ((self.Z_0 & (1 << round_number)) > 0):
            return self._xor(self.CONSTANT, 1)
        else:
            return self.CONSTANT

    def _trim_to_16_bits(self, plain_text):
        return plain_text & 0xFFFF

    def _generate_next_key(self, round_number, key_i, key_i_1, key_i_2, key_i_3):
        step_1 = self._shift_right(key_i_3, 3)
        step_2 = self._xor(step_1, key_i_1)
        step_3 = self._xor(step_2, key_i)
        step_4 = self._shift_right(step_2, 1)
        step_5 = self._xor(step_3, step_4)
        round_constant = self._calculate_constant(round_number)
        step_6 = self._xor(step_5, round_constant)
        return self._trim_to_16_bits(step_6)

    def _generate_keys(self):
        keys = [0] * self.ROUND_NUMBER
        keys[0] = self._trim_to_16_bits(self.cypher_key)
        keys[1] = self._trim_to_16_bits(self.cypher_key >> 16)
        keys[2] = self._trim_to_16_bits(self.cypher_key >> 32)
        keys[3] = self._trim_to_16_bits(self.cypher_key >> 48)

        for i in range(0, self.ROUND_NUMBER - 4):
            keys[i + 4] = self._generate_next_key(i, keys[i], keys[i + 1], keys[i + 2], keys[i + 3])
        return keys

    def _simon_encryption_round(self, input_1, input_2, keys, round_number):
        step_1 = self._shift_left(input_1, 1)
        step_2 = self._shift_left(input_1, 8)
        step_3 = step_1 & step_2
        step_4 = self._xor(step_3, input_2)
        step_5 = self._shift_left(input_1, 2)
        step_6 = self._xor(step_5, step_4)
        step_7 = self._xor(step_6, keys[round_number])
        return step_7, input_1

    def encrypt_text(self, plain_text):
        keys = self._generate_keys()
        input_1 = self._trim_to_16_bits(plain_text >> 16)
        input_2 = self._trim_to_16_bits(plain_text)
        output_1 = output_2 = 0

        for round in range(0, self.ROUND_NUMBER):
            output_1, output_2 = self._simon_encryption_round(input_1, input_2, keys, round)
            input_1 = output_1
            input_2 = output_2

        return (output_1 << 16) | output_2

def on_connect(client, userdata, flags, reason_code, properties):
    print(f'flags: {flags} result_code: {reason_code}')

def on_message(client, userdata, msg):
    print(f'{msg.topic}: {msg.payload}')

if __name__ == '__main__':
    CYPHER_KEY = 0x0123456789ABCDEF
    simon = Simon(CYPHER_KEY)

    mqtt = mqtt.Client()
    mqtt.on_connect = on_connect
    mqtt.on_message = on_message
    mqtt.username_pw_set(username="oscar", password="oscar")
    mqtt.connect('192.168.24.93', 1883, 60)
    mqtt.loop_start()

    topic = '/puj/embebidos'

    # Configura el puerto serial para leer el valor desde Arduino
    ser = serial.Serial('COM7', 9600, timeout=1)
    time.sleep(2)  # Esperar para que se estabilice la conexión serial

    while True:
        if ser.in_waiting > 0:
            # Leer la temperatura desde el puerto serial
            sensor = ser.readline().decode('utf-8').strip()
            if sensor:
                try:
                    sensor_value = int(float(sensor) * 10)
                    print(f'Valor sensor: {sensor_value / 10.0} C')

                    encrypted_sensor = simon.encrypt_text(sensor_value << 16)
                    print(f'Valor sensor cifrado hexa: {_print_hexaformat(sensor_value)}')
                    mqtt.publish(topic, str(encrypted_sensor))
                except ValueError:
                    print("Error al convertir el valor del sensor.")

        time.sleep(1)

    mqtt.loop_stop()
