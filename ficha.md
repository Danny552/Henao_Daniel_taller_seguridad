# Ficha: cifrado extremo a extremo y forward secrecy

## Definición

El **cifrado extremo a extremo (E2EE)** hace que un mensaje se cifre en el dispositivo del emisor y solo pueda descifrarse en el del receptor; el servidor y la red solo transportan texto cifrado. Protege la **confidencialidad y la integridad del contenido** frente a quien está en medio (proveedor, operador de red, atacante en la red).

**No protege:** (a) los metadatos: quién habla con quién, cuándo, tamaño, dirección IP; (b) los extremos comprometidos (malware, dispositivo robado y desbloqueado, capturas de pantalla, copias de seguridad sin cifrar); (c) a un interlocutor que reenvía el contenido; (d) la autenticidad de las claves si los usuarios no las verifican (un servidor malicioso podría sustituir una clave en el primer contacto).

## Amenaza

El **secreto hacia adelante (forward secrecy)** garantiza que, si una clave se compromete en el futuro, los mensajes *pasados* siguen siendo ilegibles. Mitiga el escenario "grabar ahora, descifrar después": un adversario que guarda todo el tráfico cifrado y más tarde roba un dispositivo, un respaldo o una clave de larga duración. Sin esta propiedad, una sola clave robada abriría todo el historial; con ella, solo expone los mensajes cuyas claves aún no se han borrado.

Su complemento es la **seguridad posterior al compromiso (post-compromise security)**: tras un robo de estado, la conversación se "cura" cuando se introduce material secreto nuevo que el atacante no conoce.

## Mecanismo

Signal usa el algoritmo **Double Ratchet** (Perrin y Marlinspike, 2016), con dos trinquetes:

1. **Trinquete simétrico (cadena de claves).** Cada mensaje usa una clave nueva derivada de una clave de cadena con una función de un solo sentido (KDF). Tras usarla, la clave de mensaje se borra y la cadena avanza. Como la KDF no se puede invertir, quien robe la cadena actual no puede recalcular las claves de mensajes anteriores: eso es el secreto hacia adelante.
2. **Trinquete de Diffie-Hellman.** Cada vez que cambia la dirección de la conversación, el emisor genera un nuevo par de claves efímeras (X25519) y mezcla el nuevo secreto DH en la clave raíz. Un atacante que solo conocía el estado anterior no puede calcular la nueva clave raíz: eso aporta la seguridad posterior al compromiso.

Cohn-Gordon et al. (2017) analizaron formalmente el protocolo y mostraron que, bajo supuestos criptográficos estándar, ofrece estas propiedades de seguridad.

## Fuentes

1. Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., Stebila, D. (2017). *A Formal Security Analysis of the Signal Messaging Protocol*. IEEE European Symposium on Security and Privacy (EuroS&P), pp. 451-466. https://eprint.iacr.org/2016/1013
2. Perrin, T., Marlinspike, M. (2016). *The Double Ratchet Algorithm*, revisión 1. Signal. https://signal.org/docs/specifications/doubleratchet/
3. Krawczyk, H., Eronen, P. (2010). *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, RFC 5869. (KDF usada en la práctica)
