import secrets
import sys
from xPlaze import encrypt, decrypt, N, xPlze

#версии 1, 1.5 не безопасны., версии менее 4, не советуются.

if xPlze < 2:
    print("Your version doesn't support")
else:
    print(f"Your version {xPlze}, OK")

def generate_private_key() -> int:
    return secrets.randbelow(N - 1) + 1

def is_valid_private_key(key: int) -> bool:
    return 1 < key < N

def main():
    private_key = None

    while True:
        print("\n=== xPlaze Шифрование/Дешифрование ===")
        print("1. Сгенерировать новый приватный ключ")
        print("2. Установить приватный ключ")
        print("3. Показать текущий приватный ключ")
        print("4. Зашифровать сообщение")
        print("5. Расшифровать blob (hex)")
        print("6. Выход")

        choice = input("Выберите действие: ").strip()

        if choice == '1':
            private_key = generate_private_key()
            print("Новый приватный ключ создан.")

        elif choice == '2':
            raw = input("Введите ключ (число или hex с 0x): ").strip()
            try:
                if raw.startswith(('0x', '0X')):
                    key = int(raw, 16)
                else:
                    key = int(raw, 10)
                if is_valid_private_key(key):
                    private_key = key
                    print("Приватный ключ успешно установлен.")
                else:
                    print("Ошибка: ключ вне допустимого диапазона (1 < key < N).")
            except ValueError:
                print("Ошибка: неверный формат числа.")

        elif choice == '3':
            if private_key is None:
                print("Приватный ключ не задан.")
            else:
                print(f"Приватный ключ (hex): {hex(private_key)}")
                print(f"Приватный ключ (десятичное): {private_key}")

        elif choice == '4':
            if private_key is None:
                print("Приватный ключ не задан.")
                continue
            message = input("Введите сообщение: ").encode('utf-8')
            if not message:
                print("Сообщение не может быть пустым.")
                continue
            try:
                blob = encrypt(message, private_key)
                print("Зашифрованный blob (hex):")
                print(blob.hex())
            except Exception as e:
                print(f"Ошибка шифрования: {e}")

        elif choice == '5':
            if private_key is None:
                print("Приватный ключ не задан.")
                continue
            blob_hex = input("Введите blob (hex): ").strip()
            try:
                blob = bytes.fromhex(blob_hex)
                plaintext = decrypt(blob, private_key)
                print("Расшифрованное сообщение:")
                print(plaintext.decode('utf-8'))
            except Exception as e:
                print(f"Ошибка дешифрования: {e}")

        elif choice == '6':
            print("До свидания!")
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
