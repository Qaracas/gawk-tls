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

#include "gtls_defcom.h"
#include "gtls_capa_tls.h"

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
//       Ver gtls_fichero_autoridades_certificadoras_tls() más abajo */
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
        gtls_limpia_error(resul);
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
            gtls_finaliza_sesion_capa_tls(capatls);
            gtls_error(resul, gtls_msj_error("%s %s",
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
    gtls_limpia_error(resul);

    VERIFICA_ERROR_TLS(resul,
        gnutls_global_init(),
        "__arranque_global_capa_tls()");

    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_allocate_credentials(&(capatls->credx509)),
        "__arranque_global_capa_tls()");

    /* Como mínimo se usan las AC de confianza predeterminadas del sistema con
     * el fin de verificar los certificados de cliente o servidor. Se pueden
     * añadir más AC usando gtls_fichero_autoridades_certificadoras_tls(), ver
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
    gtls_limpia_error(resul);

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

/* gtls_arranque_global_capa_tls_cliente */

int
gtls_arranque_global_capa_tls_cliente(t_capa_gnutls *capatls)
{
    __arranque_global_capa_tls(capatls);

    capatls->en_uso = gtls_cierto;

    /* Ver función gtls_dialoga_envia_datos_capa_tls() */
    capatls->sesión_guardada = gtls_falso;
    capatls->sesión_iniciada = gtls_falso;

    return CNTR_HECHO;
}

/* gtls_arranque_global_capa_tls_servidor */

int
gtls_arranque_global_capa_tls_servidor(t_capa_gnutls *capatls)
{
    int resul;
    gtls_limpia_error(resul);

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
        "gtls_arranque_global_capa_tls_servidor()");
#endif

    capatls->en_uso = gtls_cierto;

    /* Ver función gtls_dialoga_envia_datos_capa_tls()
     * Aquí no sirve: el servidor no reanuda sesiones */
    capatls->sesión_guardada = gtls_falso;
    capatls->sesión_iniciada = gtls_falso;

    return CNTR_HECHO;
}

#define __arranque_global_capa_tls call function
#define __diálogo_renaudable_capa_tls call function

/* gtls_falso_arranque_global_capa_tls */
int
gtls_falso_arranque_global_capa_tls(t_capa_gnutls *capatls)
{
    (void) capatls;
    return CNTR_HECHO;
}

/* gtls_parada_global_capa_tls */

void
gtls_parada_global_capa_tls(t_capa_gnutls *capatls)
{
    if (   capatls == NULL
        || capatls->en_uso) {
        gnutls_certificate_free_credentials(capatls->credx509);
        gnutls_priority_deinit(capatls->prioridad);
        gnutls_global_deinit();
        capatls->en_uso = gtls_falso;
    }
}

/* gtls_parada_global_capa_tls_noprds */

void
gtls_parada_global_capa_tls_noprds(t_capa_gnutls *capatls)
{
    if (   capatls == NULL
        || capatls->en_uso) {
        gnutls_certificate_free_credentials(capatls->credx509);
        gnutls_global_deinit();
        capatls->en_uso = gtls_falso;
    }
}

/* gtls_falsa_parada_global_capa_tls */

void
gtls_falsa_parada_global_capa_tls(t_capa_gnutls *capatls)
{
    (void) capatls;
}

/* gtls_inicia_sesion_capa_tls_cliente */

int
gtls_inicia_sesion_capa_tls_cliente(t_capa_gnutls *capatls, char *nodo)
{
    int resul;
    gtls_limpia_error(resul);

    __inicia_sesion_capa_tls(capatls, GNUTLS_CLIENT);

   /* Verificar automáticamente el certificado del servidor */
    gnutls_session_set_verify_cert(capatls->sesión, nodo, 0);

    VERIFICA_ERROR_TLS(resul,
        gnutls_server_name_set(capatls->sesión, GNUTLS_NAME_DNS,
                               nodo, strlen(nodo)),
        "gtls_inicia_sesion_capa_tls_cliente()");

    capatls->sesión_iniciada = gtls_cierto;

    return CNTR_HECHO;
}

/* gtls_inicia_sesion_capa_tls_servidor */

int
gtls_inicia_sesion_capa_tls_servidor(t_capa_gnutls *capatls, char *nodo)
{
    (void) nodo;

    __inicia_sesion_capa_tls(capatls, GNUTLS_SERVER);

    /* No solicitar ningún certificado al cliente */
    gnutls_certificate_server_set_request(capatls->sesión,
                                          GNUTLS_CERT_IGNORE);

    capatls->sesión_iniciada = gtls_cierto;

    return CNTR_HECHO;
}

#define __inicia_sesion_capa_tls call function

/* gtls_falso_inicio_sesion_capa_tls */

int
gtls_falso_inicio_sesion_capa_tls(t_capa_gnutls *capatls, char *nodo)
{
    (void) capatls;
    (void) nodo;
    return CNTR_HECHO;
}

/* gtls_finaliza_sesion_capa_tls */

void
gtls_finaliza_sesion_capa_tls(t_capa_gnutls *capatls)
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
        capatls->sesión_guardada = gtls_falso;
        capatls->sesión_iniciada = gtls_falso;
    }
}

/* gtls_inicia_diálogo_tls_cliente */

int
gtls_inicia_diálogo_tls_cliente(t_capa_gnutls *capatls, int df_cliente)
{
    if (__inicia_diálogo_tls(capatls, df_cliente) < 0)
        return CNTR_ERROR;
    return CNTR_HECHO;
}

/* gtls_inicia_diálogo_tls_servidor */

int
gtls_inicia_diálogo_tls_servidor(t_capa_gnutls *capatls, int df_cliente)
{
    if (__inicia_diálogo_tls(capatls, df_cliente) < 0)
        return CNTR_ERROR;
    return CNTR_HECHO;
}

#define __inicia_diálogo_tls call function

/* gtls_falso_inicio_diálogo_tls */

int
gtls_falso_inicio_diálogo_tls(t_capa_gnutls *capatls, int df_cliente)
{
    (void) capatls;
    (void) df_cliente;
    return CNTR_HECHO;
}

/* gtls_envia_datos_capa_tls */

ssize_t
gtls_envia_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente,
                          const void *tope, size_t bulto)
{
    (void) df_cliente;

    /* Una manera de evitar GNUTLS_E_INVALID_REQUEST al enviar datos 
       de logitud 0 */
    if (bulto <= 0)
        return 0;

    int resul;
    gtls_limpia_error(resul);

    BUCLE_VERIFICA_TLS(resul,
        gnutls_record_send(capatls->sesión, tope, bulto));
    if (resul < 0) {
        gtls_error(resul, gtls_msj_error("%s %s",
                             "gtls_envia_datos_capa_tls()",
                             gnutls_strerror(resul)));
        return CNTR_ERROR;
    }

    return resul;
}

/* gtls_recibe_datos_capa_tls */

ssize_t
gtls_recibe_datos_capa_tls(t_capa_gnutls *capatls, int df_cliente, void *tope,
                           size_t bulto)
{
    (void) df_cliente;
    int resul;

    for (;;) {
        gtls_limpia_error(resul);
        BUCLE_VERIFICA_TLS(resul,
            gnutls_record_recv(capatls->sesión, tope, bulto));
        if (resul == 0) {
            /* El interlocutor cierra la conexión TLS (fin de flujo) */
            break;
        } else if (   resul < 0
                   && gnutls_error_is_fatal(resul) == 0) {
            fprintf(stderr, "\n *** Alerta en %s: %s\n",
                    "gtls_recibe_datos_capa_tls()",
                    gnutls_strerror(resul));
        } else if (resul < 0) {
            gtls_error(resul, gtls_msj_error("%s %s %s %s",
                                             "gtls_recibe_datos_capa_tls()",
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

/* gtls_cierra_toma_tls_cliente */

int
gtls_cierra_toma_tls_cliente(t_capa_gnutls *capatls, int df_toma)
{
    int resul;
    extern int errno;
    gtls_limpia_error(errno);

    /* No esperar a que el otro lado cierre la conexión */
    BUCLE_VERIFICA_TLS(resul,
        gnutls_bye(capatls->sesión, GNUTLS_SHUT_WR));
    if (resul < 0) {
        gtls_error(resul, gtls_msj_error("%s %s",
                                         "gtls_cierra_toma_tls_cliente()",
                                         gnutls_strerror(resul)));
        return CNTR_ERROR;
    }
    if (close(df_toma) < 0) {
        gtls_error(errno, gtls_msj_error("%s %s",
                                         "gtls_cierra_toma_tls_cliente()",
                                         strerror(errno)));
        return CNTR_ERROR;
    }
    gtls_finaliza_sesion_capa_tls(capatls);

    return CNTR_HECHO;
}

/* gtls_cierra_toma_tls_servidor */

int
gtls_cierra_toma_tls_servidor(t_capa_gnutls *capatls, int df_toma)
{
    extern int errno;
    gtls_limpia_error(errno);

    if (close(df_toma) < 0) {
        gtls_error(errno, gtls_msj_error("%s %s",
                                         "gtls_cierra_toma_tls()",
                                         strerror(errno)));
        return CNTR_ERROR;
    }
    gtls_parada_global_capa_tls(capatls);

    return CNTR_HECHO;
}

/* gtls_falso_cierre_toma_tls */

int
gtls_falso_cierre_toma_tls(t_capa_gnutls *capatls, int df_toma)
{
    (void) capatls;
    extern int errno;
    gtls_limpia_error(errno);

    if (close(df_toma) < 0) {
        gtls_error(errno, gtls_msj_error("%s %s",
                                         "gtls_cierra_toma()",
                                         strerror(errno)));
        return CNTR_ERROR;
    }
    return CNTR_HECHO;
}

/* gtls_par_clave_privada_y_certificado_tls */

int
gtls_par_clave_privada_y_certificado_tls(t_capa_gnutls *capatls,
                                         const char *fcertificado,
                                         const char *fclave)
{
    int resul;
    gtls_limpia_error(resul);

    if (   capatls == NULL
        || !capatls->en_uso) {
        gtls_error(resul, gtls_msj_error("%s %s",
                            "gtls_par_clave_privada_y_certificado_tls()",
                            "no se ha iniciado capa TLS"));
        return CNTR_ERROR;
    }

    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_set_x509_key_file(capatls->credx509,
                                             fcertificado,
                                             fclave,
                                             GNUTLS_X509_FMT_PEM),
        "gtls_par_clave_privada_y_certificado_tls()");
    return CNTR_HECHO;
}

/* gtls_fichero_autoridades_certificadoras_tls */

int
gtls_fichero_autoridades_certificadoras_tls(t_capa_gnutls *capatls,
                                            const char *fautoridades)
{
    int resul;
    gtls_limpia_error(resul);

    if (   capatls == NULL
        || !capatls->en_uso) {
        gtls_error(resul, gtls_msj_error("%s %s",
                            "gtls_fichero_autoridades_certificadoras_tls()",
                            "no se ha iniciado capa TLS"));
        return CNTR_ERROR;
    }

    VERIFICA_ERROR_TLS(resul,
        gnutls_certificate_set_x509_trust_file(capatls->credx509,
                                               fautoridades,
                                               GNUTLS_X509_FMT_PEM),
        "gtls_fichero_autoridades_certificadoras_tls()");

    return CNTR_HECHO;
}
