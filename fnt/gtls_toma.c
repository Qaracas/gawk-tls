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

#define _GNU_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>

#include "gtls_defcom.h"
#include "gtls_ruta.h"
#include "gtls_toma.h"
#include "gtls_stoma.h"
#include "gtls_tope.h"
#include "gtls_capa_tls.h"

#if GNU_LINUX
#include <sys/epoll.h>
#else
#include <sys/select.h>
#endif

/* privada - __cambia_no_bloqueante --
 *
 * Poner toma en estado no bloqueante. Véase:
 * http://dwise1.net/pgm/sockets/blocking.html
 */

static
int __cambia_no_bloqueante(int df)
{
    int indicadores;
    /* Si existe O_NONBLOCK se hace a la manera Posix */
#ifdef O_NONBLOCK
    /* Arréglame: O_NONBLOCK está definido pero roto en
       SunOS 4.1.x y AIX 3.2.5. */
    if (-1 == (indicadores = fcntl(df, F_GETFL, 0)))
        indicadores = 0;
    return fcntl(df, F_SETFL, indicadores | O_NONBLOCK);
#else
    /* Si no, se hace a la manera tradicional */
    indicadores = 1;
    return ioctl(df, FIOBIO, &indicadores);
#endif
}

/* privada - __ini_cliente_tls*/

static
void __ini_cliente_tls(t_gtls_toma_es *toma) {
    toma->inicia_tls = &gtls_arranque_global_capa_tls_cliente;
    toma->ini_sesión_tls = &gtls_inicia_sesion_capa_tls_cliente;
    toma->ini_diálogo_tls = &gtls_inicia_diálogo_tls_cliente;
    toma->envia = &gtls_envia_datos_capa_tls;
    toma->recibe = &gtls_recibe_datos_capa_tls;
    toma->para_tls = &gtls_parada_global_capa_tls_noprds;
    toma->cierra_tm_cli_tls = &gtls_cierra_toma_tls_cliente;
    toma->cierra_tm_srv_tls = &gtls_cierra_toma_tls_servidor;
}

/* privada - __ini_servidor_tls */

static
void __ini_servidor_tls(t_gtls_toma_es *toma) {
    toma->inicia_tls = &gtls_arranque_global_capa_tls_servidor;
    toma->ini_sesión_tls = &gtls_inicia_sesion_capa_tls_servidor;
    toma->ini_diálogo_tls = &gtls_inicia_diálogo_tls_servidor;
    toma->envia = &gtls_envia_datos_capa_tls;
    toma->recibe = &gtls_recibe_datos_capa_tls;
    toma->para_tls = &gtls_parada_global_capa_tls;
    toma->cierra_tm_cli_tls = &gtls_cierra_toma_tls_cliente;
    toma->cierra_tm_srv_tls = &gtls_cierra_toma_tls_servidor;
}

/* privada - __ini_cliente_servidor_no_cifrado */

static
void __ini_cliente_servidor_no_cifrado(t_gtls_toma_es *toma){
    toma->gtls = NULL;
    toma->inicia_tls = &gtls_falso_arranque_global_capa_tls;
    toma->ini_sesión_tls = &gtls_falso_inicio_sesion_capa_tls;
    toma->ini_diálogo_tls = &gtls_falso_inicio_diálogo_tls;
    toma->envia = &gtls_envia_datos;
    toma->recibe = &gtls_recibe_datos;
    toma->para_tls = &gtls_falsa_parada_global_capa_tls;
    toma->cierra_tm_cli_tls = &gtls_falso_cierre_toma_tls;
    toma->cierra_tm_srv_tls = &gtls_falso_cierre_toma_tls;
}

/* gtls_nueva_toma */

t_gtls_toma_es *
gtls_nueva_toma(t_gtls_ruta *ruta)
{
    gtls_limpia_error_simple();

    if (ruta == NULL) {
        gtls_error(CNTR_ERROR, gtls_msj_error("%s %s",
                             "gtls_nueva_toma()",
                             "ruta nula"));
        return NULL;
    }

    gtls_asigmem(ruta->toma, t_gtls_toma_es *,
                 sizeof(t_gtls_toma_es), "gtls_nueva_toma");
#if GNU_LINUX
    gtls_asigmem(ruta->toma->sonda, t_gtls_sonda *,
                 sizeof(t_gtls_sonda), "gtls_nueva_toma");
#endif
    ruta->toma->servidor = CNTR_DF_NULO;
    ruta->toma->cliente = CNTR_DF_NULO;

    if (ruta->segura) {
        gtls_asigmem(ruta->toma->gtls, t_capa_gnutls *,
                     sizeof(t_capa_gnutls), "gtls_nueva_toma");
        if (ruta->cliente) {
            __ini_cliente_tls(ruta->toma);
        } else {
            __ini_servidor_tls(ruta->toma);
        }
    } else {
        __ini_cliente_servidor_no_cifrado(ruta->toma);
    }

    return ruta->toma;
}

#define __ini_cliente_tls call function
#define __ini_servidor_tls call function
#define __ini_cliente_servidor_no_cifrado call function

/* gtls_borra_toma */

void
gtls_borra_toma(t_gtls_toma_es **toma)
{
    if (*toma != NULL) {
        /* Se detiene globalmente capa TLS si aplica */
        (*(*toma)->para_tls)((*toma)->gtls);
        if ((*toma)->gtls != NULL) {
            free((*toma)->gtls);
            (*toma)->gtls = NULL;
        }
        gtls_borra_pila_toma(toma);
#if GNU_LINUX
        if ((*toma)->sonda != NULL) {
            free((*toma)->sonda);
            (*toma)->sonda = NULL;
        }
#endif
        free(*toma);
        *toma = NULL;
    }
}

/* gtls_nueva_pila_toma */

t_gtls_dts_toma *
gtls_nueva_pila_toma(t_gtls_toma_es **toma, char *sr, size_t tpm)
{
    gtls_asigmem((*toma)->pila, t_gtls_dts_toma *,
                 sizeof(t_gtls_dts_toma), "gtls_nueva_pila_toma");
    gtls_asigmem((*toma)->pila->sdrt, char *,
                 (*toma)->pila->tsr + 1, "gtls_nueva_pila_toma");

    strcpy((*toma)->pila->sdrt, (const char *) sr);
    gtls_nuevo_tope(&(*toma)->pila->tope, tpm);

    (*toma)->pila->lgtreg = 0;
    (*toma)->pila->tsr = strlen((const char *) sr);

    return (*toma)->pila;
}

/* gtls_borra_pila_toma */

void
gtls_borra_pila_toma(t_gtls_toma_es **toma)
{
    if ((*toma)->pila != NULL) {
        gtls_borra_tope(&(*toma)->pila->tope);
        free((*toma)->pila->sdrt);
        free((*toma)->pila);
        (*toma)->pila->sdrt = NULL;
        (*toma)->pila = NULL;
    }
}

/* gtls_envia_a_toma */

int
gtls_envia_toma(t_gtls_toma_es *toma, const void *datos, size_t bulto)
{
    if ((*toma->envia)(toma->gtls, toma->cliente, datos, bulto) < 0) {
        return CNTR_ERROR;
    }
    return CNTR_HECHO;
}

/* gtls_recibe_toma */

char *
gtls_recibe_linea_toma(t_gtls_toma_es *toma, char **sdrt, size_t *tsr)
{
    extern int errno;
    int recbt;
    t_gtls_tope *tope = toma->pila->tope;

    if (tope->ldatos == 0) {
        gtls_limpia_error(errno);
        recbt = gtls_rcbl_llena_tope(toma);

        switch (recbt) {
            case CNTR_TOPE_RESTO:
                /* Tamaño del registro */
                toma->pila->lgtreg = tope->ldatos;

                /* Variable RT: El final del registro es el final de flujo */
                *sdrt = NULL;
                *tsr = 0;

                return tope->datos;
            case CNTR_TOPE_VACIO:
                toma->pila->lgtreg = EOF;
                return NULL;
            case CNTR_ERROR:
                return NULL;
        }

    } else {
        /* Apunta al siguiente registro del tope */
        tope->ptrreg += toma->pila->lgtreg + toma->pila->tsr;
    }

    /* Apuntar al siguiente separador de registro */
    *sdrt = strstr((const char*) tope->datos + tope->ptrreg,
                       (const char*) toma->pila->sdrt);
    *tsr = toma->pila->tsr;

    if (*sdrt == NULL) {
        if (tope->ptrreg == 0) {
            gtls_error(CNTR_ERROR, gtls_msj_error("%s %s",
                                 "gtls_recibe_linea_toma()",
                                 "desbordamiento de pila"));
            return NULL;
        }
        /* Copia lo que nos queda por leer al inicio del tope */
        memcpy(tope->datos,
               (const void *) (tope->datos + tope->ptrreg),
               tope->ldatos - tope->ptrreg);
        tope->ptrreg = tope->ldatos - tope->ptrreg;
        tope->ldatos = 0;
        return gtls_recibe_linea_toma(toma, sdrt, tsr);
    }

    /* Tamaño del registro */
    toma->pila->lgtreg = *sdrt - (tope->datos + tope->ptrreg);

    return tope->datos + tope->ptrreg;
}

/* gtls_recibe_flujo_toma */

char *
gtls_recibe_flujo_toma(t_gtls_toma_es *toma, char **sdrt, size_t *tsr)
{
    extern int errno;
    int recbt;

    t_gtls_tope *tope = toma->pila->tope;

    gtls_limpia_error(errno);
    recbt = gtls_rcbf_llena_tope(toma);

    switch (recbt) {
        case CNTR_TOPE_VACIO:
           toma->pila->lgtreg = EOF;
           return NULL;
        case CNTR_ERROR:
            return NULL;
    }

    /* Tamaño del registro */
    toma->pila->lgtreg = tope->ldatos;

    /* Variable RT no tiene sentido leyendo flujos */
    *sdrt = NULL;
    *tsr = 0;

    return tope->datos;
}

/* gtls_conecta_toma*/

int
gtls_conecta_toma(t_gtls_toma_es *toma, char *nodo)
{
    extern int errno;
    gtls_limpia_error(errno);

    struct addrinfo *rp;

    /* Se inicia globalmente capa TLS si aplica */
    if ((*toma->inicia_tls)(toma->gtls) != CNTR_HECHO)
        return CNTR_ERROR;

    /* Inicia sesión TLS si aplica */
    if ((*toma->ini_sesión_tls)(toma->gtls, nodo) != CNTR_HECHO) {
        return CNTR_ERROR;
    }

    for (rp = toma->infred; rp != NULL; rp = rp->ai_next) {
        /* Crear toma de entrada y guardar df asociado a ella */
        toma->cliente = socket(rp->ai_family, rp->ai_socktype,
                     rp->ai_protocol);
        if (toma->cliente == CNTR_DF_NULO)
            continue;

        if (connect(toma->cliente, rp->ai_addr, rp->ai_addrlen) != -1)
            break;

        close(toma->cliente);
    }

    gtls_borra_infred(toma); /* Ya no se necesita */

    if (rp == NULL) {
        gtls_error(CNTR_ERROR, gtls_msj_error("%s %s",
                             "gtls_conecta_toma()",
                             "fallo conectando con servidor"));
        return CNTR_ERROR;
    }

    /* Inicia diálogo TLS si procede */
    if ((*toma->ini_diálogo_tls)(toma->gtls, toma->cliente) < 0)
        return CNTR_ERROR;

    return CNTR_HECHO;
}

/* gtls_pon_a_escuchar_toma */

int
gtls_pon_a_escuchar_toma(t_gtls_toma_es *toma)
{
    extern int errno;
    gtls_limpia_error(errno);

    if (   toma == NULL || toma->infred == NULL
        || toma->servidor != CNTR_DF_NULO
        || toma->local == gtls_falso) {
        gtls_error(CNTR_ERROR, gtls_msj_error("%s %s",
                             "gtls_pon_a_escuchar_toma()",
                             "toma nula o no local"));
        return CNTR_ERROR;
    }

    /* Se inicia globalmente capa TLS si aplica */
    if ((*toma->inicia_tls)(toma->gtls) != CNTR_HECHO)
        return CNTR_ERROR;

    struct addrinfo *rp;

    for (rp = toma->infred; rp != NULL; rp = rp->ai_next) {
        /* Crear toma de entrada y guardar df asociado a ella */
        toma->servidor = socket(rp->ai_family, rp->ai_socktype,
                     rp->ai_protocol);
        if (toma->servidor == CNTR_DF_NULO)
            continue;
        /* Asociar toma de entrada a una dirección IP y un puerto */
        int activo = 1;
        setsockopt(toma->servidor, SOL_SOCKET, SO_REUSEADDR,
                   &activo, sizeof(activo));
        if (bind(toma->servidor, rp->ai_addr, rp->ai_addrlen) == 0)
            break; /* Hecho */
        close(toma->servidor);
    }

    if (rp == NULL) {
        gtls_error(errno, gtls_msj_error("%s %s",
                             "gtls_pon_a_escuchar_toma()",
                             strerror(errno)));
        return CNTR_ERROR;
    }

    /* Poner toma en modo escucha */
    if (listen(toma->servidor, CNTR_MAX_PENDIENTES) < 0) {
        gtls_error(errno, gtls_msj_error("%s %s",
                             "gtls_pon_a_escuchar_toma()",
                             strerror(errno)));
        return CNTR_ERROR;
    }

#if GNU_LINUX
    /* Sonda: df que hace referencia a la nueva instancia de epoll */
    toma->sonda->dfsd = epoll_create1(0);
    if (toma->sonda->dfsd == -1) {
        gtls_error(errno, gtls_msj_error("%s %s",
                             "gtls_pon_a_escuchar_toma()",
                             strerror(errno)));
        return CNTR_ERROR;
    }

    /* Incluir toma de escucha en la lista de interés */
    toma->sonda->evt->events = EPOLLIN;
    toma->sonda->evt->data.fd = toma->servidor;
    if (epoll_ctl(toma->sonda->dfsd, EPOLL_CTL_ADD, toma->servidor,
        toma->sonda->evt) == -1) {
        gtls_error(errno, gtls_msj_error("%s %s",
                             "gtls_pon_a_escuchar_toma()",
                             strerror(errno)));
        return CNTR_ERROR;
    }
#endif

    gtls_borra_infred(toma); /* Ya no se necesita */
    return CNTR_HECHO;
}

#if GNU_LINUX
/* gtls_trae_primer_cliente_toma */

int
gtls_trae_primer_cliente_toma(t_gtls_toma_es *toma, struct sockaddr *cliente)
{
    extern int errno;
    gtls_limpia_error(errno);

    if (   toma == NULL
        || toma->servidor == CNTR_DF_NULO )
        return CNTR_ERROR;

    socklen_t lnt = (socklen_t) sizeof(*cliente);

    if (toma->sonda->ctdr < toma->sonda->ndsf) {
        toma->sonda->ctdr++;
        goto atiende_resto_eventos;
    }
    while(1) {
        /* Espera eventos en la instancia epoll refenciada en la sonda */
        toma->sonda->ndsf = epoll_wait(toma->sonda->dfsd, *toma->sonda->eva,
                                       CNTR_MAX_EVENTOS, -1);
        if (toma->sonda->ndsf == -1) {
            gtls_error(errno, gtls_msj_error("%s %s",
                                 "gtls_trae_primer_cliente_toma()",
                                 strerror(errno)));
            return CNTR_ERROR;
        }
        for (toma->sonda->ctdr = 0; toma->sonda->ctdr < toma->sonda->ndsf;
             ++(toma->sonda->ctdr)) {
atiende_resto_eventos:
            if (   toma->sonda->eva[toma->sonda->ctdr]->data.fd
                == toma->servidor) {
                /* Extraer primera conexión de la cola de conexiones */
                toma->cliente = accept(toma->servidor, cliente, &lnt);
                /* ¿Es cliente? */
                if (toma->cliente < 0) {
                    gtls_error(errno, gtls_msj_error("%s %s",
                                         "gtls_trae_primer_cliente_toma()",
                                         strerror(errno)));
                    return CNTR_ERROR;
                }
                /* Sí, es cliente */
                /* Pon la toma en estado no bloqueante */
                __cambia_no_bloqueante(toma->cliente);
                toma->sonda->evt->events = EPOLLIN | EPOLLOUT | EPOLLET;
                toma->sonda->evt->data.fd = toma->cliente;
                if (epoll_ctl(toma->sonda->dfsd, EPOLL_CTL_ADD, toma->cliente,
                              toma->sonda->evt) == -1) {
                    gtls_error(errno, gtls_msj_error("%s %s",
                                         "gtls_trae_primer_cliente_toma()",
                                         strerror(errno)));
                    return CNTR_ERROR;
                }
            } else {
                toma->cliente = toma->sonda->eva[toma->sonda->ctdr]->data.fd;
                goto sal_y_usa_el_df;
            }
        }
    }
sal_y_usa_el_df:

    /* Pon la toma en estado no bloqueante */
    __cambia_no_bloqueante(toma->cliente);

    /* Inicia diálogo TLS si procede */
    if ((*toma->ini_diálogo_tls)(toma->gtls, toma->cliente) < 0)
        return CNTR_ERROR;

    return CNTR_HECHO;
}
#else
/* gtls_trae_primer_cliente_toma */

int
gtls_trae_primer_cliente_toma(t_gtls_toma_es *toma, struct sockaddr *cliente)
{
    extern int errno;
    gtls_limpia_error(errno);

    if (   toma == NULL
        || toma->servidor == CNTR_DF_NULO ) {
        gtls_error(CNTR_ERROR, gtls_msj_error("%s %s",
                                 "gtls_trae_primer_cliente_toma()",
                                 "toma o descriptor de servidor nulo"));
        return CNTR_ERROR;
    }

    socklen_t lnt = (socklen_t) sizeof(*cliente);
    fd_set lst_df_sondear_lect, lst_df_sondear_escr;

    /* Borrar colección de tomas E/S a sondear */
    FD_ZERO(&lst_df_sondear_lect);
    FD_ZERO(&lst_df_sondear_escr);
    /* Sondear toma de escucha */
    FD_SET(toma->servidor, &lst_df_sondear_lect);

    while (1) {
        /* Esperar a que los df estén listos para hacer operaciones de E/S */
        if (select(FD_SETSIZE, &lst_df_sondear_lect, &lst_df_sondear_escr,
                   NULL, NULL) < 0) {
            gtls_error(errno, gtls_msj_error("%s %s",
                                     "gtls_trae_primer_cliente_toma()",
                                     strerror(errno)));
            return CNTR_ERROR;
        }
        /* Atender tomas con eventos de entrada pendientes */
        if (FD_ISSET(toma->servidor, &lst_df_sondear_lect)) {
            /* Inicia sesión TLS si aplica */
            if ((*toma->ini_sesión_tls)(toma->gtls, NULL) != CNTR_HECHO) {
                return CNTR_ERROR;
            }
            /* Extraer primera conexión de la cola de conexiones */
            toma->cliente = accept(toma->servidor, cliente, &lnt);
            /* ¿Es cliente? */
            if (toma->cliente < 0) {
                gtls_error(errno, gtls_msj_error("%s %s",
                                         "gtls_trae_primer_cliente_toma()",
                                         strerror(errno)));
                return CNTR_ERROR;
            }
            /* Sí, es cliente */
sondea_salida:
            FD_ZERO(&lst_df_sondear_lect);
            FD_ZERO(&lst_df_sondear_escr);
            FD_SET(toma->cliente, &lst_df_sondear_lect);
            FD_SET(toma->cliente, &lst_df_sondear_escr);
        } else {
            if (   FD_ISSET(toma->cliente, &lst_df_sondear_lect)
                && FD_ISSET(toma->cliente, &lst_df_sondear_escr))
                break;
            else
                goto sondea_salida;
        }
    }

    /* Pon la toma en estado no bloqueante */
    __cambia_no_bloqueante(toma->cliente);

    /* Inicia diálogo TLS si procede */
    if ((*toma->ini_diálogo_tls)(toma->gtls, toma->cliente) < 0)
        return  CNTR_ERROR;

    return CNTR_HECHO;
}
#endif

#define __cambia_no_bloqueante call function

/* gtls_cierra_toma_cliente */

int
gtls_cierra_toma_cliente(t_gtls_toma_es *toma, int forzar)
{
    (void) forzar;

    /* Termina la conexión TLS si aplica */
    if (   (*toma->cierra_tm_cli_tls)(toma->gtls, toma->cliente)
        != CNTR_HECHO) {
        return CNTR_ERROR;
    }

    return CNTR_HECHO;
}

/* gtls_cierra_toma_servidor */

int
gtls_cierra_toma_servidor(t_gtls_toma_es *toma, int forzar)
{
    extern int errno;
    gtls_limpia_error(errno);

    /* Forzar cierre y evitar (TIME_WAIT) */
    if (forzar) {
        struct linger so_linger;
        so_linger.l_onoff  = 1;
        so_linger.l_linger = 0;
        if (setsockopt(toma->servidor, SOL_SOCKET, SO_LINGER, &so_linger,
                       sizeof(so_linger)) < 0) {
            gtls_error(errno, gtls_msj_error("%s %s",
                                             "gtls_cierra_toma_servidor()",
                                             strerror(errno)));
            return CNTR_ERROR;
        }
    }

    /* Termina la conexión TLS si aplica */
    if (   (*toma->cierra_tm_srv_tls)(toma->gtls, toma->servidor)
        != CNTR_HECHO) {
        return CNTR_ERROR;
    }

    return CNTR_HECHO;
}
