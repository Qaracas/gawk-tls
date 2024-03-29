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

#ifndef CAPA_TLS_H
#define CAPA_TLS_H

#define VERIFICA_ERROR_TLS(valret, cmd, cmdtxt)              \
    if ((valret = cmd) < GNUTLS_E_SUCCESS) {                 \
        gtls_error(valret,                                   \
                   gtls_msj_error("%s %s",                   \
                                  cmdtxt,                    \
                                  gnutls_strerror(valret))); \
        return CNTR_ERROR;                                   \
    }

#define BUCLE_VERIFICA_TLS(valret, cmd)                      \
    do {                                                     \
        valret = cmd;                                        \
    } while(   valret == GNUTLS_E_AGAIN                      \
            || valret == GNUTLS_E_INTERRUPTED)

struct gnutls_certificate_credentials_st;
typedef struct gnutls_certificate_credentials_st
*gnutls_certificate_credentials_t;

struct gnutls_priority_st;
typedef struct gnutls_priority_st *gnutls_priority_t;

struct gnutls_session_int;
typedef struct gnutls_session_int *gnutls_session_t;

struct gnutls_datum_t;
typedef struct gnutls_datum_t *gnutls_dds_t;

#ifndef T_CTRN_VERDAD
#define T_CTRN_VERDAD
typedef enum gtls_verdad {
    gtls_falso  = 0,
    gtls_cierto = 1
} t_gtls_verdad;
#endif

typedef struct capa_gnutls {
    gnutls_certificate_credentials_t credx509;      /* Certificado X.509    */
    gnutls_priority_t                prioridad;     /* De cifrado y claves  */
    gnutls_session_t                 sesión;        /* Sesión TLS           */
    gnutls_dds_t                     dd_sesión;     /* Si reutiliza sesión  */
    t_gtls_verdad                    en_uso : 1;
    t_gtls_verdad                    sesión_iniciada : 1;
    t_gtls_verdad                    sesión_guardada : 1;
} t_capa_gnutls;

/* gtls_arranque_global_capa_tls_cliente --
 *
 * Inicializa parámetros globales de la capa TLS (cliente)
 */

int
gtls_arranque_global_capa_tls_cliente(t_capa_gnutls *capatls);

/* gtls_arranque_global_capa_tls_servidor --
 *
 * Inicializa parámetros globales de la capa TLS (servidor)
 */

int
gtls_arranque_global_capa_tls_servidor(t_capa_gnutls *capatls);

/* gtls_falso_arranque_global_capa_tls --
 *
 * Falsa función
 */
int
gtls_falso_arranque_global_capa_tls(t_capa_gnutls *capatls);

/* gtls_parada_global_capa_tls --
 *
 * Finaliza parámetros globales de la capa TLS
 */

void
gtls_parada_global_capa_tls(t_capa_gnutls *capatls);

/* gtls_parada_global_capa_tls_noprds --
 *
 * Sin la función de borrado de la prioridad GnuTLS (cliente)
 */

void
gtls_parada_global_capa_tls_noprds(t_capa_gnutls *capatls);

/* gtls_falsa_parada_global_capa_tls --
 *
 * Falsa función
 */

void
gtls_falsa_parada_global_capa_tls(t_capa_gnutls *capatls);

/* gtls_inicia_sesion_capa_tls_cliente --
 *
 * Inicia sesión TLS en toma antes de conectar con el nodo remoto (cliente)
 */

int
gtls_inicia_sesion_capa_tls_cliente(t_capa_gnutls *capatls, char *nodo);

/* gtls_inicia_sesion_capa_tls_servidor --
 *
 * Inicia sesión TLS en toma local de escucha (servidor)
 */

int
gtls_inicia_sesion_capa_tls_servidor(t_capa_gnutls *capatls, char *nodo);

/* gtls_falso_inicio_sesion_capa_tls --
 *
 * Falsa función
 */

int
gtls_falso_inicio_sesion_capa_tls(t_capa_gnutls *capatls, char *nodo);

/* gtls_finaliza_sesion_capa_tls --
 *
 * Borra la sesión y los topes que tiene asociados
 */

void
gtls_finaliza_sesion_capa_tls(t_capa_gnutls *capatls);

/* gtls_inicia_diálogo_tls_cliente --
 *
 * Inicia el díalog de la capa TLS
 */

int
gtls_inicia_diálogo_tls_cliente(t_capa_gnutls *capatls, int df_cliente);

/* gtls_inicia_diálogo_tls_servidor --
 *
 * Inicia el díalog de la capa TLS
 */

int
gtls_inicia_diálogo_tls_servidor(t_capa_gnutls *capatls, int df_cliente);

/* gtls_falso_inicio_diálogo_tls
 *
 * Falsa función
 */

int
gtls_falso_inicio_diálogo_tls(t_capa_gnutls *capatls, int df_cliente);

/* gtls_envia_datos_capa_tls --
 *
 * Envía datos cifrados a traves de la capa TLS
 */

ssize_t
gtls_envia_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                          const void *tope, size_t bulto);

/* gtls_recibe_datos_capa_tls --
 *
 * Recibe datos descifrados de la capa TLS
 */

ssize_t
gtls_recibe_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                           void *tope, size_t bulto);

/* gtls_cierra_toma_tls_cliente --
 *
 * Termina la conexión TLS del cliente
 */

int
gtls_cierra_toma_tls_cliente(t_capa_gnutls *capatls, int df_toma);

/* gtls_cierra_toma_tls_servidor --
 *
 * Termina la conexión TLS del servidor
 */

int
gtls_cierra_toma_tls_servidor(t_capa_gnutls *capatls, int df_toma);

/* gtls_falso_cierre_toma_tls --
 *
 * Falsa función
 */

int
gtls_falso_cierre_toma_tls(t_capa_gnutls *capatls, int df_toma);

/* gtls_par_clave_privada_y_certificado_tls --
 *
 *
 */

int
gtls_par_clave_privada_y_certificado_tls(t_capa_gnutls *capatls,
                                         const char *fclave,
                                         const char *fcertificado);

/* gtls_fichero_autoridades_certificadoras_tls --
 *
 * Carga las atoridades certificadores de confianza presentes en el
 * fichero para verificar certificados de cliente o de servidor. Se
 * puede llamar una o más veces.
 */

int
gtls_fichero_autoridades_certificadoras_tls(t_capa_gnutls *capatls,
                                            const char *fautoridades);

#endif /* CAPA_TLS_H */