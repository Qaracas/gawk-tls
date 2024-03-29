/*
 * Autor: Ulpiano Tur de Vargas <ulpiano.tur.devargas@gmail.com>
 *
 * Este programa es software libre; puedes distribuirlo y/o
 * modificarlo bajo los términos de la Licencia Pública General de GNU
 * según la publicó la Fundación del Software Libre; ya sea la versión 3, o
 * (a su elección) una versión superior.
 *
 * Este programa se distribuye con la esperanza de que sea útil,
 * pero SIN NINGUNA GARANTIA; ni siquiera la garantía implícita de
 * COMERCIABILIDAD o APTITUD PARA UN PROPÓSITO DETERMINADO. Vea la
 * Licencia Pública General de GNU para más detalles.
 *
 * Deberás haber recibido una copia de la Licencia Pública General
 * de GNU junto con este software; mira el fichero LICENSE. Si
 * no, mira <https://www.gnu.org/licenses/>.
 *
 * Author: Ulpiano Tur de Vargas <ulpiano.tur.devargas@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this software; see the file LICENSE. If
 * not, see <https://www.gnu.org/licenses/>.
 */

#ifndef TOMA_H
#define TOMA_H

/* Tome máximo para cola de conexiones pendientes */
#define CNTR_MAX_PENDIENTES 100

typedef enum gtls_verdad t_gtls_verdad;

struct sockaddr;

struct addrinfo;

struct gtls_ruta;
typedef struct gtls_ruta t_gtls_ruta;

struct gtls_tope;
typedef struct gtls_tope t_gtls_tope;

#if GNU_LINUX
/* Número máximo de descriptores de fichero listos para la operación de E/S
   solicitada, que devuelve epoll_wait */
#define CNTR_MAX_EVENTOS 10

struct epoll_event;
typedef struct epoll_event t_gtls_evt;

typedef struct gtls_sonda {
    t_gtls_evt *evt; /* Lista de dsfs. de interés de la sonda 'epoll'        */
    t_gtls_evt *eva; /* Dsfs. en la lista de interés con eventos de E/S      */
    int        ndsf; /* Nº dscs. de fichero con eventeos de E/S (epoll_wait) */
    int        dfsd; /* Df. de la sonda de eventos (instancia 'epoll')       */
} t_gtls_sonda;
#endif

struct capa_gnutls;
typedef struct capa_gnutls t_capa_gnutls;

typedef ssize_t (*func_recibe)(t_capa_gnutls *capatls, int df_cliente,
                             void *tope, size_t bulto);

typedef ssize_t (*func_envía)(t_capa_gnutls *capatls, int df_cliente,
                             const void *tope, size_t bulto);

typedef void (*func_para)(t_capa_gnutls *capatls);

typedef int (*func_inicia)(t_capa_gnutls *capatls);

typedef int (*func_sesión)(t_capa_gnutls *capatls, char *nodo);

typedef int (*func_cierra)(t_capa_gnutls *capatls, int df_toma);

typedef int (*func_diálogo)(t_capa_gnutls *capatls, int df_cliente);

/* Para cargar los datos que se envían o reciben de la toma */

typedef struct datos_toma {
    t_gtls_tope *tope;        /* Tope de datos entre la E/S                */
    char        *sdrt;        /* Separador de registro. Variable RS gawk   */
    size_t      tsr;          /* Tamaño cadena separador de registro       */
    size_t      lgtreg;       /* Tamaño actual del registro                */
} t_gtls_dts_toma;

typedef struct gtls_toma_es {
    t_capa_gnutls   *gtls;
#if GNU_LINUX
    t_gtls_sonda    *sonda;   /* Sonda de eventos E/S (epoll API)          */
#endif
    int             servidor; /* Descriptor servidor en modo escucha       */
    int             cliente;  /* Descriptor cliente (lectura/escritura)    */
    t_gtls_dts_toma *pila;    /* Pila de datos entre el programa y la toma */
    struct addrinfo *infred;  /* Información de red TCP/IP (API Linux)     */
    t_gtls_verdad   local;    /* ¿Toma local?                              */
    func_inicia     inicia_tls;        /* Iniciar globalmente TLS          */
    func_sesión     ini_sesión_tls;    /* Iniciar sesión TLS               */
    func_diálogo    ini_diálogo_tls;   /* Iniciar diálogo TLS              */
    func_envía      envia;             /* Enviar datos                     */
    func_recibe     recibe;            /* Recibir datos                    */
    func_para       para_tls;          /* Parar globalmente TLS            */
    func_cierra     cierra_tm_cli_tls; /* Cerrar toma TLS cliente          */
    func_cierra     cierra_tm_srv_tls; /* Cerrar toma TLS servidor         */
} t_gtls_toma_es;

/* gtls_nueva_toma --
 *
 * Crea nueva toma 'nula' de E/S para una ruta
 */

t_gtls_toma_es *
gtls_nueva_toma(t_gtls_ruta *ruta);

/* gtls_borra_toma --
 *
 * Borra toma de la memoria
 */

void
gtls_borra_toma(t_gtls_toma_es **toma);

/* gtls_nueva_pila_toma --
 *
 * Crea estructura de la pila de datos en la toma
 */

t_gtls_dts_toma *
gtls_nueva_pila_toma(t_gtls_toma_es **toma, char *sr, size_t tpm);

/* gtls_borra_pila_toma --
 *
 * Libera memoria de la pila asociada a la toma
 */

void
gtls_borra_pila_toma(t_gtls_toma_es **toma);

/* gtls_envia_toma --
 *
 * Envía datos por la toma de conexión
 */

int
gtls_envia_toma(t_gtls_toma_es *toma, const void *datos, size_t bulto);

/* gtls_recibe_linea_toma --
 *
 * Recibe línea terminada en RS por la toma de conexión
 */

char *
gtls_recibe_linea_toma(t_gtls_toma_es *toma, char **sdrt, size_t *tsr);

/* gtls_recibe_flujo_toma --
 *
 * Recibe un flujo contínuo de datos por la toma de conexión
 */

char *
gtls_recibe_flujo_toma(t_gtls_toma_es *toma, char **sdrt, size_t *tsr);

/* gtls_conecta_toma --
 *
 * Conecta la toma asociada a una ruta de tipo cliente
 */
int
gtls_conecta_toma(t_gtls_toma_es *toma, char *nodo);

/* gtls_pon_a_escuchar_toma --
 *
 * Pone a escuchar la toma asociada a una ruta local (servidor)
 */

int
gtls_pon_a_escuchar_toma(t_gtls_toma_es *toma);

/* gtls_trae_primer_cliente_toma --
 *
 * Extrae la primera conexión de una toma en modo de escucha
 */

int
gtls_trae_primer_cliente_toma(t_gtls_toma_es *toma,
                              struct sockaddr *cliente);

/* gtls_cierra_toma_cliente --
 *
 * Cierra toma de datos del cliente (punto de conexión al cliente)
 */

int
gtls_cierra_toma_cliente(t_gtls_toma_es *toma, int forzar);

/* gtls_cierra_toma_servidor --
 *
 * Cierra toma de datos del servidor (punto de conexión al servidor)
 */

int
gtls_cierra_toma_servidor(t_gtls_toma_es *toma, int forzar);

#endif /* TOMA_H */