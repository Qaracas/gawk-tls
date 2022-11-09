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
        cntr_error(valret,                                   \
                   cntr_msj_error("%s %s",                   \
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
typedef enum cntr_verdad {
    cntr_falso  = 0,
    cntr_cierto = 1
} t_ctrn_verdad;
#endif

typedef int (*func_diálogo_capa_tls)(void *capatls, int df_cliente);

typedef struct capa_gnutls {
    gnutls_certificate_credentials_t credx509;      /* Certificado X.509    */
    gnutls_priority_t                prioridad;     /* De cifrado y claves  */
    gnutls_session_t                 sesión;        /* Sesión TLS           */
    gnutls_dds_t                     dd_sesión;     /* Si reutiliza sesión  */
    func_diálogo_capa_tls            dialoga_capa_tls;
    t_ctrn_verdad                    usándose : 1;
    t_ctrn_verdad                    sesión_iniciada : 1;
    t_ctrn_verdad                    sesión_guardada : 1;
} t_capa_gnutls;

/* cntr_arranque_global_capa_tls_cliente --
 *
 * Inicializa parámetros globales de la capa TLS (cliente)
 */

int
cntr_arranque_global_capa_tls_cliente(t_capa_gnutls *capatls);

/* cntr_arranque_global_capa_tls_servidor --
 *
 * Inicializa parámetros globales de la capa TLS (servidor)
 */

int
cntr_arranque_global_capa_tls_servidor(t_capa_gnutls *capatls);

/* cntr_falso_arranque_global_capa_tls --
 *
 * Falsa función
 */
int
cntr_falso_arranque_global_capa_tls(t_capa_gnutls *capatls);

/* cntr_parada_global_capa_tls --
 *
 * Finaliza parámetros globales de la capa TLS
 */

void
cntr_parada_global_capa_tls(t_capa_gnutls *capatls);

/* cntr_parada_global_capa_tls_noprds --
 *
 * Sin la función de borrado de la prioridad GnuTLS (cliente)
 */

void
cntr_parada_global_capa_tls_noprds(t_capa_gnutls *capatls);

/* cntr_falsa_parada_global_capa_tls --
 *
 * Falsa función
 */

void
cntr_falsa_parada_global_capa_tls(t_capa_gnutls *capatls);

/* cntr_inicia_sesion_capa_tls_cliente --
 *
 * Inicia sesión TLS en toma antes de conectar con el nodo remoto (cliente)
 */

int
cntr_inicia_sesion_capa_tls_cliente(t_capa_gnutls *capatls, char *nodo);

/* cntr_inicia_sesion_capa_tls_servidor --
 *
 * Inicia sesión TLS en toma local de escucha (servidor)
 */

int
cntr_inicia_sesion_capa_tls_servidor(t_capa_gnutls *capatls, char *nodo);

/* cntr_falso_inicio_sesion_capa_tls --
 *
 * Falsa función
 */

int
cntr_falso_inicio_sesion_capa_tls(t_capa_gnutls *capatls, char *nodo);

/* cntr_finaliza_sesion_capa_tls --
 *
 * Borra la sesión y los topes que tiene asociados
 */

void
cntr_finaliza_sesion_capa_tls(t_capa_gnutls *capatls);

/* cntr_dialoga_envia_datos_capa_tls --
 *
 * Prinero inicia díalogo TLS y luego envía datos cifrados (Cliente)
 */

ssize_t
cntr_dialoga_envia_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                          const void *tope, size_t bulto);

/* cntr_envia_datos_capa_tls --
 *
 * Envía datos cifrados a traves de la capa TLS
 */

ssize_t
cntr_envia_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                          const void *tope, size_t bulto);

/* cntr_dialoga_recibe_datos_capa_tls --
 *
 * Prinero inicia díalogo TLS y luego recibe datos descifrados (Servidor)
 */

ssize_t
cntr_dialoga_recibe_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                                   void *tope, size_t bulto);

/* cntr_recibe_datos_capa_tls --
 *
 * Recibe datos descifrados de la capa TLS
 */

ssize_t
cntr_recibe_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                           void *tope, size_t bulto);

/* cntr_cierra_toma_tls_cliente --
 *
 * Termina la conexión TLS del cliente
 */

int
cntr_cierra_toma_tls_cliente(t_capa_gnutls *capatls, int df_toma);

/* cntr_cierra_toma_tls_servidor --
 *
 * Termina la conexión TLS del servidor
 */

int
cntr_cierra_toma_tls_servidor(t_capa_gnutls *capatls, int df_toma);

/* cntr_falso_cierre_toma_tls --
 *
 * Falsa función
 */

int
cntr_falso_cierre_toma_tls(t_capa_gnutls *capatls, int df_toma);

/* cntr_par_clave_privada_y_certificado_tls --
 *
 *
 */

int
cntr_par_clave_privada_y_certificado_tls(t_capa_gnutls *capatls,
                                         const char *fclave,
                                         const char *fcertificado);

/* cntr_fichero_autoridades_certificadoras_tls --
 *
 * Carga las atoridades certificadores de confianza presentes en el
 * fichero para verificar certificados de cliente o de servidor. Se
 * puede llamar una o más veces.
 */

int
cntr_fichero_autoridades_certificadoras_tls(t_capa_gnutls *capatls,
                                            const char *fautoridades);

#endif /* CAPA_TLS_H */