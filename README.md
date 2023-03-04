# Interconexiones seguras con Gawk mediante TLS

## ¿Qué es `gawk-tls`?

`gawk-tls` es una extensión de [Gawk](https://www.gnu.org/software/gawk/manual/gawk.html) que permite establecer conexiones TCP/IP entre procesos de diferentes sistemas, sobre la capa de seguridad [TLS](https://es.wikipedia.org/wiki/Seguridad_de_la_capa_de_transporte)

## Requisitos

* Sistema operativo GNU/Linux
* Implementación GNU del lenguaje de programción AWK - gawk (>= 5.1.0)
* Biblioteca GNU TLS. Ficheros de desarrollo - libgnutls28-dev (>= 3.7.1-5)
* Biblioteca GNU TLS. Utilidades en línea de comandos - gnutls-bin (>= 3.7.1-5)
* Gestor de compilación y enlazado - pkg-config (>= 0.29.2-1)

## Instalación

1. Descargar el proyecto completo:

```bash
$ git clone https://github.com/Qaracas/gawk-tls.git
```
2. Entrar en el proyecto:

```bash
$ cd gawk-tls
```

3. Compilar el código fuente:

```bash
$ cd fnt/;make;cd ..
```

4. Fijar la variable de entorno [AWKPATH](https://www.gnu.org/software/gawk/manual/gawk.html#AWKPATH-Variable):

```bash
$ export AWKPATH=${AWKPATH}:"$(pwd)/ejemplos"
```

5. Fijar la variable de entorno [AWKLIBPATH](https://www.gnu.org/software/gawk/manual/html_node/AWKLIBPATH-Variable.html)

```bash
$ export AWKLIBPATH=${AWKLIBPATH}:"$(pwd)/lib"
```

## Referencias

* [Documentación biblioteca GnuTLS](https://www.gnutls.org/manual/html_node/index.html)

## Autores

* [Ulpiano Tur de Vargas](https://github.com/Qaracas)
* [Y Cía](https://github.com/Qaracas/gawk-tls/contributors)

## Licencia

Este proyecto se distribuye bajo los términos de la Licencia Pública General de GNU (GNU GPL v3.0). Mira el archivo [LICENSE](LICENSE) para más detalle.
