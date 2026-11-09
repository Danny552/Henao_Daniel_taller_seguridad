"""A1. Cadena de claves simétrica con HKDF.

Cada mensaje se cifra con una clave nueva derivada de una clave de cadena.
Después de usarla, la clave de mensaje se borra y la cadena avanza con una
función de un solo sentido, de modo que el estado actual no permite
reconstruir claves anteriores (secreto hacia adelante).

Solo se usan primitivas estándar de la biblioteca `cryptography`
(HKDF-SHA256 y ChaCha20-Poly1305). No se implementa criptografía propia.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LONGITUD_CLAVE = 32
LONGITUD_NONCE = 12
_INFO_MENSAJE = b"taller-seguridad/a1/mensaje/"
_INFO_CADENA = b"taller-seguridad/a1/siguiente-cadena"


def _hkdf(material: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=None,
        info=info,
    ).derive(bytes(material))


def derivar_clave(cadena: bytes, indice: int) -> bytes:
    """Deriva la clave de mensaje número `indice` a partir de `cadena`.

    Usa HKDF-SHA256 con la clave de cadena como material y el índice dentro
    de `info`. Es determinista: misma cadena e índice dan la misma clave;
    índices distintos dan claves distintas.

    Args:
        cadena: clave de cadena de 32 bytes.
        indice: número de mensaje (entero >= 0).
    Returns:
        Clave de mensaje de 32 bytes.
    """
    if len(cadena) != LONGITUD_CLAVE:
        raise ValueError("la clave de cadena debe tener 32 bytes")
    if not isinstance(indice, int) or indice < 0:
        raise ValueError("el índice debe ser un entero >= 0")
    return _hkdf(cadena, _INFO_MENSAJE + indice.to_bytes(4, "big"))


def cifrar(clave: bytes, texto: str | bytes) -> bytes:
    """Cifra `texto` con ChaCha20-Poly1305 usando una clave de mensaje.

    Devuelve nonce (12 bytes) || texto cifrado con etiqueta de autenticación.
    Cada clave de mensaje se usa una sola vez, por eso el nonce aleatorio
    no se repite con la misma clave.
    """
    datos = texto.encode("utf-8") if isinstance(texto, str) else texto
    nonce = os.urandom(LONGITUD_NONCE)
    return nonce + ChaCha20Poly1305(bytes(clave)).encrypt(nonce, datos, None)


def descifrar(clave: bytes, cifrado: bytes) -> bytes:
    """Descifra lo producido por `cifrar`. Lanza InvalidTag si no es válido."""
    nonce, cuerpo = cifrado[:LONGITUD_NONCE], cifrado[LONGITUD_NONCE:]
    return ChaCha20Poly1305(bytes(clave)).decrypt(nonce, cuerpo, None)


class CadenaSimetrica:
    """Cadena de claves que avanza y borra lo ya usado.

    En cada paso: clave_mensaje = derivar_clave(cadena_i, i) y
    cadena_{i+1} = HKDF(cadena_i). La cadena anterior se sobrescribe con ceros.
    """

    def __init__(self, cadena_inicial: bytes):
        if len(cadena_inicial) != LONGITUD_CLAVE:
            raise ValueError("la clave de cadena debe tener 32 bytes")
        self._cadena = bytearray(cadena_inicial)
        self.indice = 0

    def siguiente(self) -> tuple[int, bytearray]:
        """Devuelve (indice, clave_de_mensaje) y avanza la cadena.

        La clave se devuelve como bytearray para poder borrarla con
        `descartar`. La cadena anterior queda sobrescrita con ceros.
        """
        i = self.indice
        clave = bytearray(derivar_clave(bytes(self._cadena), i))
        nueva = bytearray(_hkdf(bytes(self._cadena), _INFO_CADENA))
        self._borrar(self._cadena)
        self._cadena = nueva
        self.indice += 1
        return i, clave

    @staticmethod
    def _borrar(buffer: bytearray) -> None:
        for k in range(len(buffer)):
            buffer[k] = 0

    def descartar(self, clave: bytearray) -> None:
        """Sobrescribe con ceros una clave de mensaje ya usada."""
        self._borrar(clave)

    def estado_actual(self) -> bytes:
        """Copia de la clave de cadena vigente (lo que vería un atacante
        que robe el estado ahora). Se usa solo en las pruebas."""
        return bytes(self._cadena)

    def cifrar_siguiente(self, texto: str | bytes) -> tuple[int, bytes]:
        """Cifra un mensaje con la siguiente clave y la borra de inmediato."""
        i, clave = self.siguiente()
        try:
            return i, cifrar(clave, texto)
        finally:
            self.descartar(clave)

    def descifrar_siguiente(self, cifrado: bytes) -> bytes:
        """Descifra (en orden) con la siguiente clave y la borra."""
        _, clave = self.siguiente()
        try:
            return descifrar(clave, cifrado)
        finally:
            self.descartar(clave)
