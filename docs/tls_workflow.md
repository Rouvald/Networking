## Схема обмена TLS 1.3 (упрощённо, на основе RFC 8446)

```mermaid
sequenceDiagram
    participant C as Клиент
    participant S as Сервер

    Note over C,S: Handshake (ECDHE + AES-256-GCM)

    %% 1. Клиент генерирует ключ ECDHE и отправляет его
    C->>C: crypto = ECDHECrypto()
    C->>C: clientPub = crypto.get_public_key_der()
    C->>S: UtilsNetwork::write_vector(sock, clientPub)

    %% 2. Сервер читает публичный ключ клиента, генерирует свой, отправляет его
    S->>S: clientPub = UtilsNetwork::read_vector(sock)
    S->>S: clientKey = d2i_PUBKEY_from_vector(clientPub)
    S->>S: crypto = ECDHECrypto()
    S->>S: serverPub = crypto.get_public_key_der()
    S->>C: UtilsNetwork::write_vector(sock, serverPub)

    %% 3. Клиент читает публичный ключ сервера
    C->>C: serverPub = UtilsNetwork::read_vector(sock)
    C->>C: serverKey = d2i_PUBKEY_from_vector(serverPub)

    %% 4. Оба вычисляют общий секрет и деривируют AES-ключ
    C->>C: shared = crypto.compute_shared_secret(serverKey)
    S->>S: shared = crypto.compute_shared_secret(clientKey)
    Note over C,S: derive symmetric key из `shared`

    %% 5. Клиент шифрует и отправляет данные
    C->>C: aes = AESCrypto(shared)
    C->>C: cipher, tag = aes.encrypt(plainData, iv, tag)
    C->>S: UtilsNetwork::write_vector(sock, cipher)
    C->>S: UtilsNetwork::write_vector(sock, tag)

    %% 6. Сервер получает и расшифровывает
    S->>S: cipher = UtilsNetwork::read_vector(sock)
    S->>S: tag    = UtilsNetwork::read_vector(sock)
    S->>S: plain  = aes.decrypt(cipher, iv, tag)

    %% 7. Сервер шифрует и отправляет ответ
    S->>S: cipher2, tag2 = aes.encrypt(responseData, iv, tag)
    S->>C: UtilsNetwork::write_vector(sock, cipher2)
    S->>C: UtilsNetwork::write_vector(sock, tag2)

    %% 8. Клиент получает и расшифровывает ответ
    C->>C: cipher2 = UtilsNetwork::read_vector(sock)
    C->>C: tag2    = UtilsNetwork::read_vector(sock)
    C->>C: plain2  = aes.decrypt(cipher2, iv, tag2)

    Note over C,S: Data exchange завершён - канал защищён
```

**Пояснения:**
1. **ECDHECrypto** — обмен ключами: генерация пары (приватный/публичный), сериализация через DER и передача функциями `UtilsNetwork`.
2. **compute_shared_secret** — вычисление общего секрета на основе ключей сторон.
3. **AESCrypto** — инициализация AES-256-GCM, шифрование (`encrypt`) и дешифрование (`decrypt`).
4. **UtilsNetwork** — сетевые утилиты для сериализации/десериализации вектора байт подряд: `write_vector`/`read_vector`.

Эта диаграмма близка к обмену сообщениями TLS 1.3 (RFC 8446), адаптированная к используемым в проекте функциям.
