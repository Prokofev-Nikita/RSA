#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

typedef struct rsa_key_t {
    int n;  // RSA модуль
    int e;  // Публичный экспонент
    int d;  // Приватный экспонент
} Rsa;

int is_prime(int num) {
    if (num <= 1) {
        return 0;  // Возвращает 0, если число меньше или равно 1
    }
    int i;
    for (i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) {
            return 0;  // Возвращает 0, если число делится нацело на любое число от 2 до sqrt(num)
        }
    }
    return 1;  // Возвращает 1, если число простое
}

int gcd(int a, int b) {
    if (b == 0) {
        return a;  // Возвращает a, если b равно 0 (базовый случай алгоритма Евклида)
    }
    return gcd(b, a % b);  // Рекурсивно находит наибольший общий делитель с помощью алгоритма Евклида
}

int mod_pow(int base, int exp, int mod) {
    int result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;  // Вычисляет модулярное возведение в степень
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

Rsa generate_key_pair() {
    struct rsa_key_t key_pair;
    int p, q, phi, e, d;
    srand(time(NULL));  // Инициализирует генератор случайных чисел текущим временем
    do {
        p = rand() % 100 + 2;  // Генерирует случайное простое число p от 2 до 100
    } while (!is_prime(p));
    do {
        q = rand() % 100 + 2;  // Генерирует случайное простое число q от 2 до 100
    } while (!is_prime(q) || q == p);
    key_pair.n = p * q;  // Вычисляет RSA модуль n
    phi = (p - 1) * (q - 1);  // Вычисляет значение функции Эйлера phi
    do {
        e = rand() % phi + 2;  // Генерирует случайное число e от 2 до phi
    } while (gcd(e, phi) != 1);  // Проверяет, являются ли e и phi взаимно простыми
    key_pair.e = e;  // Устанавливает публичный экспонент e
    int k = 1;
    while (1) {
        d = (k * phi + 1) / e;  // Вычисляет приватный экспонент d с помощью модулярного мультипликативного обратного
        if ((d * e) % phi == 1) {
            break;  // Прерывает цикл, когда d найдено
        }
        k++;
    }
    key_pair.d = d;  // Устанавливает приватный экспонент d
    return key_pair;  // Возвращает сгенерированную пару ключей
}

void encrypt(char *message, size_t msg_len, Rsa public_key, int *encrypted_message) {
    size_t i;
    for (i = 0; i < msg_len; i++) {
        encrypted_message[i] = mod_pow(message[i], public_key.e, public_key.n);  // Шифрует каждый символ сообщения с помощью модулярного возведения в степень
    }
}

void decrypt(int *encrypted_message, size_t msg_len, Rsa private_key, char *decrypted_message) {
    size_t i;
    for (i = 0; i < msg_len; i++) {
        decrypted_message[i] = (char)mod_pow(encrypted_message[i], private_key.d, private_key.n);  // Дешифрует каждый символ зашифрованного сообщения с помощью модулярного возведения в степень
    }
}

int main() {
    printf("Input message!\n");
    char message[1024];
    fgets(message, sizeof(message), stdin);
    size_t msg_len = strlen(message);
    int *encrypted_message = malloc(msg_len * sizeof(int));
    char *decrypted_message = malloc(msg_len * sizeof(char));
    Rsa public_key, private_key;
    public_key = generate_key_pair();
    private_key = public_key;
    printf("Public key: n = %d, e = %d\n", public_key.n, public_key.e);
    printf("Private key: n = %d, d = %d\n", private_key.n, private_key.d);
    encrypt(message, msg_len, public_key, encrypted_message);
    decrypt(encrypted_message, msg_len, private_key, decrypted_message);
    printf("Original message: %s", message);
    printf("Encrypted message: ");
    size_t i;
    for (i = 0; i < msg_len; i++) {
        printf("%d ", encrypted_message[i]);
    }
    printf("\n");
    printf("Decrypted message: %s\n", decrypted_message);
    free(encrypted_message);
    free(decrypted_message);
    return 0;
}