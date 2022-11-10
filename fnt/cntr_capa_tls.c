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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>

#include "cntr_defcom.h"
#include "cntr_capa_tls.h"

/* privada - __rellama_verifica_certificado
 *
 * Verifica el certificado del interlocutor y si su nombre DNS coincide, así
 * como su activación y caducidad.
 */

//static int
//__rellama_verifica_certificado(gnutls_session_t sesión)
//{
//    int resul;
//    unsigned int estado;
//    const char *nombre_srv;
//
//    /* Lee nombre del servidor */
//    if ((nombre_srv = gnutls_session_get_ptr(sesión)) == NULL)
//        return GNUTLS_E_CERTIFICATE_ERROR;
//
//    /* Es necesario tener instalados uno o más certificados de AC.
//       Ver cntr_fichero_autoridades_certificadoras_tls() más abajo */
//    VERIFICA_ERROR_TLS(resul,
//        gnutls_certificate_verify_peers3(sesión, nombre_srv, &estado),
//        "__rellama_verifica_certificado()");//
//
//    /* Comprobar si el certificado es de confianza*/
//    if (estado != 0)
//        return GNUTLS_E_CERTIFICATE_ERROR;
//
//    /* Notificar a GnuTLS que continúe el diálogo normalmente */
//    return GNUTLS_E_SUCCESS;
//}

/* privada - __inicia_diálogo_tls */

static int
__inicia_diálogo_tls(t_capa_gnutls *capatls, int df_cliente)
{
    int resul;

    /* Asocia nueva toma del cliente a la sesión TLS */
    gnutls_transport_set_int(capatls->sesión, df_cliente);

    gnutls_handshake_set_timeout(capatls->sesión,
                                 GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Dialoga TLS e inicializa los parámetros de sesión */
    for (;;) {
        cntr_limpia_error(resul);
        BUCLE_VERIFICA_TLS(resul,
            gnutls_handshake(capatls->sesión));
        if (resul == 0) {
            /* Diálogo fructífero */
            break;
        } else if (   resul < 0
                   && gnutls_error_is_fatal(resul) == 0) {
            fprintf(stderr, "\n *** Alerta en %s: %s\n",
                    "__inicia_diálogo_tls()",
                    gnutls_strerror(resul));
        } else if (resul < 0) {
            close(df_cliente);
            cntr_finaliza_sesion_capa_tls(capatls);
            cntr_error(resul, cntr_msj_error("%s %s",
                                 "__inicia_diálogo_tls()",
                                 gnutls_strerror(resul)));
            return CNTR_ERROR;
        } else {
            /* No se puede dar */
            break;
        }
    }
    return resul;
}

/* privada - __arranque_global_capa_tls */

static int
__arranque_global_capa_tls(t_capa_gnutls *capatls)
{
    int resul;
    cntr_limpia_error(resul);

    VERIFICA_ERROR_TLS(resul,
        gnutls_global_init(),
        "__arranque_global_capa_tls()");

    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_allocate_credentials(&(capatls->credx509)),
        "__arranque_global_capa_tls()");

    /* Como mínimo se usan las AC de confianza predeterminadas del sistema con
     * el fin de verificar los certificados de cliente o servidor. Se pueden
     * añadir más AC usando cntr_fichero_autoridades_certificadoras_tls(), ver
     * más abajo */
    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_set_x509_system_trust(capatls->credx509),
        "__arranque_global_capa_tls()");

    /* Rellama a otra función cuanto se recibe el certificado del interlocutor
     * con el fin de verificarlo, en lugar de hacerlo despues de completar el
     * protocolo de enlace */
//    gnutls_certificate_set_verify_function(capatls->credx509,
//                                           __rellama_verifica_certificado);

    return CNTR_HECHO;
}

//#define __rellama_verifica_certificado call function

/* privada - __inicia_sesion_capa_tls */

static int
__inicia_sesion_capa_tls(t_capa_gnutls *capatls, unsigned int perfil)
{
    int resul;
    cntr_limpia_error(resul);

    VERIFICA_ERROR_TLS(resul,
        gnutls_init(&(capatls->sesión), perfil),
        "__inicia_sesion_capa_tls()");

    /* Prioridad de los métodos de cifrado e intercambio de claves */
    VERIFICA_ERROR_TLS(resul,
        gnutls_set_default_priority(capatls->sesión),
        "__inicia_sesion_capa_tls()");

    /* Poner credenciales x509 en la sesión actual */
    VERIFICA_ERROR_TLS(resul,
        gnutls_credentials_set(capatls->sesión,
                               GNUTLS_CRD_CERTIFICATE,
                               capatls->credx509),
        "__inicia_sesion_capa_tls()");

    return CNTR_HECHO;
}

/* cntr_arranque_global_capa_tls_cliente */

int
cntr_arranque_global_capa_tls_cliente(t_capa_gnutls *capatls)
{
    __arranque_global_capa_tls(capatls);

    capatls->usándose = cntr_cierto;

    /* Ver función cntr_dialoga_envia_datos_capa_tls() */
    capatls->sesión_guardada = cntr_falso;
    capatls->sesión_iniciada = cntr_falso;

    return CNTR_HECHO;
}

/* cntr_arranque_global_capa_tls_servidor */

int
cntr_arranque_global_capa_tls_servidor(t_capa_gnutls *capatls)
{
    int resul;
    cntr_limpia_error(resul);

    __arranque_global_capa_tls(capatls);

    VERIFICA_ERROR_TLS(resul,
        gnutls_priority_init2(&(capatls->prioridad),
            "%SERVER_PRECEDENCE", NULL,
            GNUTLS_PRIORITY_INIT_DEF_APPEND),
        "__arranque_global_capa_tls()");

    /* Disponible desde GnuTLS 3.5.6. En versiones anteriores consultar:
     * gnutls_certificate_set_dh_params() */
#if GNUTLS_VERSION_NUMBER >= 0x030506
    /* Configura parámetros Diffie-Hellman para que los use un servidor
       con certificado */
    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_set_known_dh_params(capatls->credx509,
                                               GNUTLS_SEC_PARAM_MEDIUM),
        "cntr_arranque_global_capa_tls_servidor()");
#endif

    capatls->usándose = cntr_cierto;

    /* Ver función cntr_dialoga_envia_datos_capa_tls()
     * Aquí no sirve: el servidor no reanuda sesiones */
    capatls->sesión_guardada = cntr_falso;
    capatls->sesión_iniciada = cntr_falso;

    return CNTR_HECHO;
}

#define __arranque_global_capa_tls call function
#define __diálogo_renaudable_capa_tls call function

/* cntr_falso_arranque_global_capa_tls */
int
cntr_falso_arranque_global_capa_tls(t_capa_gnutls *capatls)
{
    (void) capatls;
    return CNTR_HECHO;
}

/* cntr_parada_global_capa_tls */

void
cntr_parada_global_capa_tls(t_capa_gnutls *capatls)
{
    if (   capatls == NULL
        || capatls->usándose) {
        gnutls_certificate_free_credentials(capatls->credx509);
        gnutls_priority_deinit(capatls->prioridad);
        gnutls_global_deinit();
        capatls->usándose = cntr_falso;
    }
}

/* cntr_parada_global_capa_tls_noprds */

void
cntr_parada_global_capa_tls_noprds(t_capa_gnutls *capatls)
{
    if (   capatls == NULL
        || capatls->usándose) {
        gnutls_certificate_free_credentials(capatls->credx509);
        gnutls_global_deinit();
        capatls->usándose = cntr_falso;
    }
}

/* cntr_falsa_parada_global_capa_tls */

void
cntr_falsa_parada_global_capa_tls(t_capa_gnutls *capatls)
{
    (void) capatls;
}

/* cntr_inicia_sesion_capa_tls_cliente */

int
cntr_inicia_sesion_capa_tls_cliente(t_capa_gnutls *capatls, char *nodo)
{
    int resul;
    cntr_limpia_error(resul);

    __inicia_sesion_capa_tls(capatls, GNUTLS_CLIENT);

   /* Verificar automáticamente el certificado del servidor */
    gnutls_session_set_verify_cert(capatls->sesión, nodo, 0);

    VERIFICA_ERROR_TLS(resul,
        gnutls_server_name_set(capatls->sesión, GNUTLS_NAME_DNS,
                               nodo, strlen(nodo)),
        "cntr_inicia_sesion_capa_tls_cliente()");

    capatls->sesión_iniciada = cntr_cierto;

    return CNTR_HECHO;
}

/* cntr_inicia_sesion_capa_tls_servidor */

int
cntr_inicia_sesion_capa_tls_servidor(t_capa_gnutls *capatls, char *nodo)
{
    (void) nodo;

    __inicia_sesion_capa_tls(capatls, GNUTLS_SERVER);

    /* No solicitar ningún certificado al cliente */
    gnutls_certificate_server_set_request(capatls->sesión,
                                          GNUTLS_CERT_IGNORE);

    capatls->sesión_iniciada = cntr_cierto;

    return CNTR_HECHO;
}

#define __inicia_sesion_capa_tls call function

/* cntr_falso_inicio_sesion_capa_tls */

int
cntr_falso_inicio_sesion_capa_tls(t_capa_gnutls *capatls, char *nodo)
{
    (void) capatls;
    (void) nodo;
    return CNTR_HECHO;
}

/* cntr_finaliza_sesion_capa_tls */

void
cntr_finaliza_sesion_capa_tls(t_capa_gnutls *capatls)
{
    /* Borra la sesión y los topes que tiene asociados */
    if (   capatls == NULL
        || capatls->sesión_iniciada) {
        gnutls_deinit(capatls->sesión);
        /* Sólo cliente */
        if (capatls->sesión_guardada) {
            gnutls_free(((gnutls_datum_t*)capatls->dd_sesión)->data);
            free(capatls->dd_sesión);
        }
        capatls->sesión_guardada = cntr_falso;
        capatls->sesión_iniciada = cntr_falso;
    }
}

/* cntr_inicia_diálogo_tls_cliente */

int
cntr_inicia_diálogo_tls_cliente(t_capa_gnutls *capatls, int df_cliente)
{
    if (__inicia_diálogo_tls(capatls, df_cliente) < 0)
        return CNTR_ERROR;
    return CNTR_HECHO;
}

/* cntr_inicia_diálogo_tls_servidor */

int
cntr_inicia_diálogo_tls_servidor(t_capa_gnutls *capatls, int df_cliente)
{
    if (__inicia_diálogo_tls(capatls, df_cliente) < 0)
        return CNTR_ERROR;
    return CNTR_HECHO;
}

#define __inicia_diálogo_tls call function

/* cntr_falso_inicio_diálogo_tls */

int
cntr_falso_inicio_diálogo_tls(t_capa_gnutls *capatls, int df_cliente)
{
    (void) capatls;
    (void) df_cliente;
    return CNTR_HECHO;
}

/* cntr_envia_datos_capa_tls */

ssize_t
cntr_envia_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                          const void *tope, size_t bulto)
{
    (void) df_cliente;

    /* Una manera de evitar GNUTLS_E_INVALID_REQUEST al enviar datos 
       de logitud 0 */
    if (bulto <= 0)
        return 0;

    int resul;
    cntr_limpia_error(resul);

    BUCLE_VERIFICA_TLS(resul,
        gnutls_record_send(capatls->sesión, tope, bulto));
    if (resul < 0) {
        cntr_error(resul, cntr_msj_error("%s %s",
                             "cntr_envia_datos_capa_tls()",
                             gnutls_strerror(resul)));
        return CNTR_ERROR;
    }

    return resul;
}

/* cntr_recibe_datos_capa_tls */

ssize_t
cntr_recibe_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente, void *tope,
                           size_t bulto)
{
    (void) df_cliente;
    int resul;

    for (;;) {
        cntr_limpia_error(resul);
        BUCLE_VERIFICA_TLS(resul,
            gnutls_record_recv(capatls->sesión, tope, bulto));
        if (resul == 0) {
            /* El interlocutor cierra la conexión TLS (fin de flujo) */
            break;
        } else if (   resul < 0
                   && gnutls_error_is_fatal(resul) == 0) {
            fprintf(stderr, "\n *** Alerta en %s: %s\n",
                    "cntr_recibe_datos_capa_tls()",
                    gnutls_strerror(resul));
        } else if (resul < 0) {
            cntr_error(resul, cntr_msj_error("%s %s %s %s",
                                             "cntr_recibe_datos_capa_tls()",
                                             "datos corruptos",
                                             "cerrando conexión",
                                             gnutls_strerror(resul)));
            return CNTR_ERROR;
        } else {
            /* resul > 0 */
            break;
        }
    }

    return resul;
}

/* cntr_cierra_toma_tls_cliente */

int
cntr_cierra_toma_tls_cliente(t_capa_gnutls *capatls, int df_toma)
{
    int resul;
    extern int errno;
    cntr_limpia_error(errno);

    /* No esperar a que el otro lado cierre la conexión */
    BUCLE_VERIFICA_TLS(resul,
        gnutls_bye(capatls->sesión, GNUTLS_SHUT_WR));
    if (resul < 0) {
        cntr_error(resul, cntr_msj_error("%s %s",
                                         "cntr_cierra_toma_tls_cliente()",
                                         gnutls_strerror(resul)));
        return CNTR_ERROR;
    }
    if (close(df_toma) < 0) {
        cntr_error(errno, cntr_msj_error("%s %s",
                                         "cntr_cierra_toma_tls_cliente()",
                                         strerror(errno)));
        return CNTR_ERROR;
    }
    cntr_finaliza_sesion_capa_tls(capatls);

    return CNTR_HECHO;
}

/* cntr_cierra_toma_tls_servidor */

int
cntr_cierra_toma_tls_servidor(t_capa_gnutls *capatls, int df_toma)
{
    extern int errno;
    cntr_limpia_error(errno);

    if (close(df_toma) < 0) {
        cntr_error(errno, cntr_msj_error("%s %s",
                                         "cntr_cierra_toma_tls()",
                                         strerror(errno)));
        return CNTR_ERROR;
    }
    cntr_parada_global_capa_tls(capatls);

    return CNTR_HECHO;
}

/* cntr_falso_cierre_toma_tls */

int
cntr_falso_cierre_toma_tls(t_capa_gnutls *capatls, int df_toma)
{
    (void) capatls;
    extern int errno;
    cntr_limpia_error(errno);

    if (close(df_toma) < 0) {
        cntr_error(errno, cntr_msj_error("%s %s",
                                         "cntr_cierra_toma()",
                                         strerror(errno)));
        return CNTR_ERROR;
    }
    return CNTR_HECHO;
}

/* cntr_par_clave_privada_y_certificado_tls */

int
cntr_par_clave_privada_y_certificado_tls(t_capa_gnutls *capatls,
                                         const char *fcertificado,
                                         const char *fclave)
{
    int resul;
    cntr_limpia_error(resul);

    if (   capatls == NULL
        || !capatls->usándose) {
        cntr_error(resul, cntr_msj_error("%s %s",
                            "cntr_par_clave_privada_y_certificado_tls()",
                            "no se ha iniciado capa TLS"));
        return CNTR_ERROR;
    }

    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_set_x509_key_file(capatls->credx509,
                                             fcertificado,
                                             fclave,
                                             GNUTLS_X509_FMT_PEM),
        "cntr_par_clave_privada_y_certificado_tls()");
    return CNTR_HECHO;
}

/* cntr_fichero_autoridades_certificadoras_tls */

int
cntr_fichero_autoridades_certificadoras_tls(t_capa_gnutls *capatls,
                                            const char *fautoridades)
{
    int resul;
    cntr_limpia_error(resul);

    if (   capatls == NULL
        || !capatls->usándose) {
        cntr_error(resul, cntr_msj_error("%s %s",
                            "cntr_fichero_autoridades_certificadoras_tls()",
                            "no se ha iniciado capa TLS"));
        return CNTR_ERROR;
    }

    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_set_x509_trust_file(capatls->credx509,
                                               fautoridades,
                                               GNUTLS_X509_FMT_PEM),
        "cntr_fichero_autoridades_certificadoras_tls()");

    return CNTR_HECHO;
}
