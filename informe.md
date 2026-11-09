# Informe: Seguridad en Messenger (A1 y A2)

## Qué se implementó

**A1: cadena de claves simétrica** (`a1_cadena.py`). `derivar_clave(cadena, indice)` aplica HKDF-SHA256 a una clave de cadena de 32 bytes con el índice del mensaje como contexto. `cifrar(clave, texto)` usa ChaCha20-Poly1305 con nonce aleatorio. La clase `CadenaSimetrica` avanza la cadena en cada mensaje con una HKDF de un solo sentido y sobrescribe con ceros la clave de mensaje usada y la clave de cadena anterior.

**A2: Double Ratchet reducido** (`a2_ratchet.py`). Dos participantes (Alice y Bob) en un único proceso, sin red. Alice envía los mensajes 1-3 y Bob responde con los 4-6; ese cambio de dirección obliga a Bob a generar un nuevo par X25519 (`cambiar_direccion`). La clase `Ratchet` expone `enviar`, `recibir` y `cambiar_direccion`. Incluye un trinquete de Diffie-Hellman (HKDF sobre la clave raíz), un trinquete simétrico (HMAC-SHA256), cifrado autenticado con la cabecera como datos asociados y rechazo de mensajes alterados o repetidos sin dañar el estado.

**Pruebas.** 9 pruebas (4 de A1 y 5 de A2) que reproducen la tabla de resultados. Las de forward secrecy y post-compromise simulan un atacante que roba el estado completo de un participante e intenta descifrar de dos formas: comportándose como receptor y recorriendo hacia adelante todas las cadenas derivables de ese estado. Cada una incluye un control positivo (un estado anterior sí descifra), para comprobar que el atacante simulado no es trivialmente inútil.

**Resultados.** 9 de 9 pruebas en OK (100 %, por encima del 90 % de la escala). No hay filas en FALLA, por lo que no hay justificaciones pendientes. Detalle en `resultados.csv` y `log_pruebas.json`.

| Prueba | Esperado | Obtenido | Estado |
|---|---|---|---|
| A1-01 | misma clave | misma clave | OK |
| A1-02 | 10 claves distintas | 10 claves distintas | OK |
| A1-03 | 10/10 correctos | 10/10 correctos | OK |
| A1-04 | no recuperable | no recuperable | OK |
| A2-01 | 6/6 correctos | 6/6 correctos | OK |
| A2-02 | rechazado | rechazado | OK |
| A2-03 | rechazado | rechazado | OK |
| A2-04 | no descifrable | no descifrable | OK |
| A2-05 | no descifrable | no descifrable | OK |

## Diferencias

Frente al protocolo real de Signal, esta versión simplificada:

- **No incluye el acuerdo inicial X3DH.** El secreto compartido inicial y la clave pública de Bob se generan en memoria.
- **No cifra las cabeceras.** La clave pública DH, `pn` y `n` viajan en claro (autenticadas, pero visibles); Signal define una variante con cabeceras cifradas.
- **Tolera pocos mensajes perdidos** (`MAX_SALTO = 10`) y no tiene gestión de grupos, persistencia, múltiples dispositivos ni verificación de identidad.
- **Una prueba verifica el cambio de dirección en un solo sentido** (Alice → Bob y respuesta de Bob); no se ejercitan conversaciones largas con muchos cambios.
- **A1 es una cadena simple**, sin trinquete DH: protege el pasado, pero no se recupera de un robo de estado.

## Limitaciones

- **Borrado de memoria.** En Python no se puede garantizar que una clave desaparezca de la memoria. Los `bytearray` se ponen en ceros, pero las claves en `bytes` (inmutables), las copias intermedias del intérprete y el recolector de basura pueden dejar rastros. La prueba A1-04 demuestra la no recuperabilidad lógica (desde el estado de la cadena), no un borrado físico.
- **Post-compromise es asimétrico.** Si se roba el estado de Alice antes de que Bob responda, ese estado sí descifra la respuesta de Bob (el control de A2-05 lo muestra): la conversación solo se cura cuando el participante comprometido renueva su propio par. La prueba A2-05 roba el estado de quien genera la clave nueva (Bob).
- **Atacante pasivo.** Las pruebas modelan un atacante que roba el estado una vez y observa el tráfico; no modelan un atacante activo que siga controlando el dispositivo.
- **Pruebas locales.** Todo se ejecutó en un entorno local, con datos de ejemplo y sin credenciales ni datos reales (Ley 1581 de 2012).
- **A1 no tolera mensajes fuera de orden**: el receptor debe procesar los mensajes en el orden de envío, y un mensaje que falla igualmente avanza la cadena.
