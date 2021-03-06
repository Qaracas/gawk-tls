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

#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "gawkapi.h"

#include <arpa/inet.h>

#include "cntr_capa_tls.h"
#include "cntr_defcom.h"
#include "cntr_ruta.h"
#include "cntr_toma.h"
#include "cntr_stoma.h"
#include "cntr_tope.h"
#include "cntr_serie.h"

static const gawk_api_t *api; /* Conveniencia para usar macros */
static awk_ext_id_t ext_id;
static const char *ext_version = "extensión conector: versión 1.0";

static awk_bool_t inicia_conector(void);
static awk_bool_t (*init_func)(void) = inicia_conector;

int plugin_is_GPL_compatible;

/* Definiciones y variables globales */

typedef char * (*recibe_toma)(t_cntr_toma_es *toma, char **sdrt, size_t *tsr);

static t_cntr_ruta *rt;    /* Ruta de conexión en uso                       */
static recibe_toma recibe; /* Puntero a función que recibe datos de la toma */
static size_t      v_tpm;  /* Toma el valor de la variable global TPM       */

/* pon_num_en_coleccion --
 *
 * Añadir elemento numérico a la colección
 */

static void
pon_num_en_coleccion(awk_array_t coleccion, const char *sub, double num)
{
    awk_value_t index, value;

    set_array_element(coleccion,
        make_const_string(sub, strlen(sub), &index),
        make_number(num, &value));
}

/* pon_txt_en_coleccion --
 *
 * Añadir elemento textual a la colección
 */

static void
pon_txt_en_coleccion(awk_array_t coleccion, const char *sub, const char *txt)
{
    awk_value_t index, value;

    set_array_element(coleccion,
        make_const_string(sub, strlen(sub), &index),
        make_const_string(txt, strlen(txt), &value));
}

/* comprueba_actualiza_ruta --
 *
 * Comprueba si el nombre del fichero especial está registrado como ruta de
 * red y actualiza valor de <<rt>> si es necesario
 */

static int
comprueba_actualiza_ruta(const char *nombre_func, const char *nombre_ruta)
{
    extern t_cntr_ruta *rt;

    if (strcmp(nombre_ruta, "") == 0 || nombre_ruta == NULL) {
        fatal(ext_id, cntr_msj_error("%s %s",
                             nombre_func,
                             "error leyendo nombre de fichero especial"));
    }

    if (   (   rt != NULL
            && strcmp(nombre_ruta, (const char *)rt->nombre) == 0)
        || (rt = cntr_busca_ruta_en_serie(nombre_ruta)) != NULL) {
        return CNTR_HECHO;
    } else {
        cntr_error(CNTR_ERROR, cntr_msj_error("%s",
                             "toma de datos inexistente"));
        return CNTR_ERROR;
    }
}

/* trae_tope_maximo --
 *
 * Trae el valor de la variable global TMP
 */

static size_t
trae_tope_maximo()
{
    awk_value_t valor_tpm;
    size_t tpm;
    extern recibe_toma recibe;

    if (!(sym_lookup("TPM", AWK_NUMBER, &valor_tpm)))
        fatal(ext_id, "creatoma: error leyendo variable TPM");

    if (valor_tpm.num_value < 0)
        fatal(ext_id, "creatoma: valor de TPM incorrecto");

    tpm = (size_t) valor_tpm.num_value;

    /* Si TMP = 0 leemos datos hasta CNTR_TOPE_MAX_X_DEF */
    if (tpm == 0)
        recibe = &cntr_recibe_linea_toma;
    else
        recibe = &cntr_recibe_flujo_toma;

    return tpm;
}

/* trae_separador_de_registro --
 *
 * Trae el valor de la variable global RS
 */

static char *
trae_separador_de_registro()
{
    awk_value_t valor_rs;

    if (!(sym_lookup("RS",  AWK_STRING, &valor_rs)))
        fatal(ext_id, "creatoma: error leyendo variable RS");

    return (char *)valor_rs.str_value.str;
}

/**
 * Funciones que proporciona 'conector.c' a GAWK
 */

/* haz_crea_toma --
 *
 * Crea una toma de datos y escucha en ella
 */

static awk_value_t *
haz_crea_toma(int nargs, awk_value_t *resultado,
              struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t nombre;
    extern size_t v_tpm;
    extern t_cntr_ruta *rt;
    extern t_cntr_error cntr_error;

    /* Sólo acepta 1 argumento */
    if (nargs != 1)
        fatal(ext_id, "creatoma: nº de argumentos incorrecto");

    if (! get_argument(0, AWK_STRING, &nombre))
        fatal(ext_id, "creatoma: tipo de argumento incorrecto");

    const char *nombre_ruta = (const char *)nombre.str_value.str;
    if (comprueba_actualiza_ruta("creatoma:",
                                 nombre_ruta) == CNTR_HECHO) {
        lintwarn(ext_id, "creatoma: la ruta ya existe");
        return make_number(rt->toma->servidor, resultado);
    }

    if (cntr_nueva_ruta(nombre_ruta, &rt) == CNTR_ERROR) {
        cntr_borra_ruta(rt);
        fatal(ext_id, cntr_msj_error("%s %s",
                                     "creatoma:",
                                     cntr_error.descripción));
    }

    /* Fuera de ssdv esto no sería un error */
    if (!rt->local) {
        cntr_borra_ruta(rt);
        fatal(ext_id, "creatoma: la ruta no es local");
    }

    if (cntr_nueva_toma(rt) == NULL)
        fatal(ext_id, cntr_msj_error("%s %s",
                                     "creatoma:",
                                     cntr_error.descripción));

    v_tpm = trae_tope_maximo();
    cntr_nueva_pila_toma(rt->toma, trae_separador_de_registro(),
                         v_tpm);
    if (cntr_error.número < 0)
        fatal(ext_id, cntr_msj_error("%s %s",
                                     "creatoma:",
                                     cntr_error.descripción));

    if (cntr_nueva_infred(rt->nodo_local, rt->puerto_local,
                          rt->toma) == CNTR_ERROR)
        fatal(ext_id, cntr_msj_error("%s %s",
                                     "creatoma:",
                                     cntr_error.descripción));

    if (cntr_pon_a_escuchar_toma(rt->toma) == CNTR_ERROR)
        fatal(ext_id, cntr_msj_error("%s %s",
                                     "creatoma:",
                                     cntr_error.descripción));

    if (cntr_pon_ruta_en_serie(rt) == NULL) {
        cntr_borra_ruta(rt);
        fatal(ext_id, "creatoma: error registrando ruta");
    }

    return make_number(rt->toma->servidor, resultado);
}

/* haz_destruye_toma --
 *
 * Borra toma de datos de la memoria y de la serie
 */

static awk_value_t *
haz_destruye_toma(int nargs, awk_value_t *resultado,
                  struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t nombre;
    extern t_cntr_ruta *rt;

    /* Sólo acepta 1 argumento */
    if (nargs != 1)
        fatal(ext_id, "matatoma: nº de argumentos incorrecto");

    if (! get_argument(0, AWK_STRING, &nombre))
        fatal(ext_id, "matatoma: tipo de argumento incorrecto");

    const char *nombre_ruta = (const char *)nombre.str_value.str;
    if (comprueba_actualiza_ruta("matatoma:",
                                 nombre_ruta) == CNTR_HECHO) {
        cntr_borra_ruta_de_serie(nombre_ruta);
        cntr_borra_ruta(rt);
    } else {
        lintwarn(ext_id, "matatoma: la ruta no existe");
        return make_number(-1, resultado);
    }

    return make_number(0, resultado);
}

/* haz_acaba_toma_srv --
 *
 * Cierra toma de datos local
 */

static awk_value_t *
haz_acaba_toma_srv(int nargs, awk_value_t *resultado,
                   struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t nombre;
    extern t_cntr_error cntr_error;
    extern t_cntr_ruta *rt;

    /* Sólo acepta 1 argumento */
    if (nargs != 1) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                             "acabasrv:",
                             "nº de argumentos incorrecto"));
        return make_number(-1, resultado);
    }

    if (! get_argument(0, AWK_STRING, &nombre)) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                             "acabasrv:",
                             "tipo de argumento incorrecto"));
        return make_number(-1, resultado);
    }

    if (comprueba_actualiza_ruta("acabasrv:",
                                 (const char *)nombre.str_value.str) < 0) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                                     "acabasrv:",
                                     cntr_error.descripción));
        return make_number(-1, resultado);
    }

    if (cntr_cierra_toma_servidor(rt->toma, 0) == CNTR_ERROR)
        lintwarn(ext_id, cntr_msj_error("%s %s",
                                        "acabasrv:",
                                        cntr_error.descripción));

    return make_number(0, resultado);
}

/* haz_acaba_toma_cli --
 *
 * Cierra toma de datos local
 */

static awk_value_t *
haz_acaba_toma_cli(int nargs, awk_value_t *resultado,
                    struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t nombre;
    extern t_cntr_error cntr_error;
    extern t_cntr_ruta *rt;

    /* Sólo acepta 1 argumento */
    if (nargs != 1) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                             "acabacli:",
                             "nº de argumentos incorrecto"));
        return make_number(-1, resultado);
    }

    if (! get_argument(0, AWK_STRING, &nombre)) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                             "acabacli:",
                             "tipo de argumento incorrecto"));
        return make_number(-1, resultado);
    }

    if (comprueba_actualiza_ruta("acabacli:",
                                 (const char *)nombre.str_value.str) < 0) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                                     "acabacli:",
                                     cntr_error.descripción));
        return make_number(-1, resultado);
    }

    if (cntr_cierra_toma_cliente(rt->toma, 0) == CNTR_ERROR)
        lintwarn(ext_id, cntr_msj_error("%s %s",
                                        "acabacli:",
                                        cntr_error.descripción));

    return make_number(0, resultado);
}

/* haz_trae_primer_cli --
 *
 * Extrae primera conexión de la cola de conexiones
 */

static awk_value_t *
haz_trae_primer_cli(int nargs, awk_value_t *resultado,
                    struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t valorarg;
    extern t_cntr_ruta *rt;
    extern t_cntr_error cntr_error;

    /* Sólo acepta 2 argumentos como máximo */
    if (nargs < 1 || nargs > 2)
        fatal(ext_id, "traepcli: nº de argumentos incorrecto");

    if (! get_argument(0, AWK_STRING, &valorarg))
        fatal(ext_id, "traepcli: tipo de argumento incorrecto");

    if (comprueba_actualiza_ruta("traepcli:",
                                 (const char *)
                                 valorarg.str_value.str) < 0)
            fatal(ext_id, "traepcli: toma de datos inexistente");

    struct sockaddr_in cliente;

    if (   cntr_trae_primer_cliente_toma(rt->toma,
                                         (struct sockaddr*) &cliente)
        == CNTR_ERROR)
        fatal(ext_id, cntr_msj_error("%s %s",
                                     "traepcli:",
                                     cntr_error.descripción));

    /* Anunciar cliente */
    if (nargs == 2) {
        if (get_argument(1, AWK_ARRAY, &valorarg)) {
llena_coleccion:
            pon_txt_en_coleccion(valorarg.array_cookie, "dir",
                                 inet_ntoa(cliente.sin_addr));
            pon_num_en_coleccion(valorarg.array_cookie, "pto",
                                 (double)ntohs(cliente.sin_port));
        } else {
            if (valorarg.val_type == AWK_UNDEFINED) {
                set_argument(1, create_array());
                goto llena_coleccion;
            } else {
                lintwarn(ext_id,
                         "traepcli: segundo argumento incorrecto");
            }
        }
    }

    /* Devuelve accept(), es decir, el descriptor de fichero de la
       toma de datos recién creada para comunicar con el cliente. */
    return make_number(rt->toma->cliente, resultado);
}

/* haz_par_clave_y_certificado_tls --
 *
 * Certificado de servidor y clave privada usado para la conexión TLS
 */

static awk_value_t *
haz_par_clave_y_certificado_tls(int nargs, awk_value_t *resultado,
                                struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t valorarg;
    extern t_cntr_ruta *rt;
    extern t_cntr_error cntr_error;

    /* Sólo acepta 2 argumentos como máximo */
    if (nargs != 3)
        fatal(ext_id, "pcertcla: nº de argumentos incorrecto");

    if (! get_argument(0, AWK_STRING, &valorarg))
        fatal(ext_id, "pcertcla: tipo de argumento incorrecto");

    if (comprueba_actualiza_ruta("pcertcla:",
                                 (const char *)
                                 valorarg.str_value.str) < 0)
            fatal(ext_id, "pcertcla: toma de datos inexistente");

    if (! get_argument(1, AWK_STRING, &valorarg))
        fatal(ext_id, "pcertcla: tipo de argumento incorrecto");

    const char *f_certificado = (const char *) valorarg.str_value.str;

    if (! get_argument(2, AWK_STRING, &valorarg))
        fatal(ext_id, "pcertcla: tipo de argumento incorrecto");

    const char *f_clave_privada = (const char *) valorarg.str_value.str;

    if (   cntr_par_clave_privada_y_certificado_tls(rt->toma->gtls,
                                                    f_certificado,
                                                    f_clave_privada)
        == CNTR_ERROR)
            lintwarn(ext_id, cntr_msj_error("%s %s",
                                    "pcertcla:",
                                    cntr_error.descripción));

    return make_number(0, resultado);
}


/* haz_lista_autoridades_tls --
 *
 * Fichero con lista de autoridades certificadoras usado para la conexión TLS
 */

static awk_value_t *
haz_lista_autoridades_tls(int nargs, awk_value_t *resultado,
                          struct awk_ext_func *desusado)
{
    (void) desusado;
    awk_value_t valorarg;
    extern t_cntr_ruta *rt;
    extern t_cntr_error cntr_error;

    /* Sólo acepta 2 argumentos como máximo */
    if (nargs != 2)
        fatal(ext_id, "lisautor: nº de argumentos incorrecto");

    if (! get_argument(0, AWK_STRING, &valorarg))
        fatal(ext_id, "lisautor: tipo de argumento incorrecto");

    if (comprueba_actualiza_ruta("lisautor:",
                                 (const char *)
                                 valorarg.str_value.str) < 0)
            fatal(ext_id, "lisautor: toma de datos inexistente");

    if (! get_argument(1, AWK_STRING, &valorarg))
        fatal(ext_id, "lisautor: tipo de argumento incorrecto");

    const char *f_auto_certificadoras = (const char *) valorarg.str_value.str;

    if (   cntr_fichero_autoridades_certificadoras_tls(rt->toma->gtls,
                                                       f_auto_certificadoras)
        == CNTR_ERROR)
            lintwarn(ext_id, cntr_msj_error("%s %s",
                                    "lisautor:",
                                    cntr_error.descripción));

    return make_number(0, resultado);
}

/**
 * Procesador bidireccional que proporciona 'conector' a GAWK
 */

/* No hay puntero oculto */

/* cierra_toma_entrada --
 *
 * Cerrar toma de entrada
 */

static void
cierra_toma_entrada(awk_input_buf_t *tpent)
{
    tpent->fd = INVALID_HANDLE;
}

/* cierra_toma_salida --
 *
 * Cerrar toma de salida
 */

static int
cierra_toma_salida(FILE *pf, void *opaco)
{
    (void) pf;
    (void) opaco;

    return 0;
}

/* limpia_toma_salida --
 *
 * Apagar toma de salida
 */

static int
limpia_toma_salida(FILE *pf, void *opaco)
{
    (void) pf;
    (void) opaco;

    return 0;
}

/* maneja_error --
 *
 * De momento no hacer nada
 */

static int
maneja_error(FILE *pf, void *opaco)
{
    (void) pf;
    (void) opaco;

    return 0;
}

/* conector_recibe_datos --
 *
 * Lee un registro cada vez
 */

static int
conector_recibe_datos(char **out, awk_input_buf_t *tpent, int *errcode,
                      char **rt_start, size_t *rt_len,
                      const awk_fieldwidth_info_t **desusado)
{
    if (out == NULL || tpent == NULL)
        return EOF;

    (void) desusado;
    size_t tpm;
    extern size_t v_tpm;
    extern t_cntr_ruta *rt;
    extern recibe_toma recibe;
    extern t_cntr_error cntr_error;

    /* Relee variable global TPM cada vez */
    if((tpm = trae_tope_maximo()) != v_tpm) {
        v_tpm = tpm;
        cntr_borra_tope(rt->toma->pila->tope);
        cntr_nuevo_tope(&rt->toma->pila->tope, tpm);
    }

    cntr_error.número = 0;
    *out = (*recibe)(rt->toma, rt_start, rt_len);

    if (cntr_error.número < 0)
    {
        *errcode = cntr_error.número;
        update_ERRNO_int(*errcode);
        update_ERRNO_string(cntr_msj_error("%s %s",
                                     "conector_recibe_datos:",
                                     cntr_error.descripción));
        return CNTR_ERROR;
    }

    return rt->toma->pila->lgtreg;
}

/* conector_envia_datos --
 *
 * Envía respuesta a solicitud del cliente
 */

static size_t
conector_envia_datos(const void *tope, size_t bulto, size_t ndatos, FILE *pf,
                     void *opaco)
{
    (void) pf;
    (void) opaco;
    extern t_cntr_ruta *rt;
    extern t_cntr_error cntr_error;

    if (cntr_envia_toma(rt->toma, tope, (bulto * ndatos)) == CNTR_ERROR) {
        lintwarn(ext_id, cntr_msj_error("%s %s",
                                        "conector_envia_datos:",
                                        cntr_error.descripción));
        return EOF;
    }

    return (bulto * ndatos);
}

/* conector_puede_aceptar_fichero --
 *
 * Decide si aceptamos fichero
 */

static awk_bool_t
conector_puede_aceptar_fichero(const char *nombre)
{
    extern t_cntr_ruta *rt;

/* 1 ¿Es la toma en uso?
   2 ¿Está registrada? ('creatoma') */
    return (   nombre != NULL
            && (   strcmp(nombre, rt->nombre) == 0                    /* 1 */
                || (rt = cntr_busca_ruta_en_serie(nombre)) != NULL)); /* 2 */
}

/* conector_tomar_control_de --
 *
 * Prepara procesador bidireccional
 */

static awk_bool_t
conector_tomar_control_de(const char *nombre, awk_input_buf_t *tpent,
                          awk_output_buf_t *tpsal)
{
    if (tpent == NULL || tpsal == NULL)
        return awk_false;

    extern t_cntr_ruta *rt;

    /* Entrada */
    tpent->opaque = NULL;
    tpent->get_record = conector_recibe_datos;
    tpent->close_func = cierra_toma_entrada;

    /* Salida */
    tpsal->name = nombre;
    tpsal->mode = "w";
    tpsal->fp = fdopen(rt->toma->cliente, "w");
    tpsal->redirected = awk_true;
    tpsal->opaque = NULL;
    tpsal->gawk_fwrite = conector_envia_datos;
    tpsal->gawk_fflush = limpia_toma_salida;
    tpsal->gawk_ferror = maneja_error;
    tpsal->gawk_fclose = cierra_toma_salida;

    return awk_true;
}

/* Registra nuevo procesador bidireccional llamado 'conector' */

static awk_two_way_processor_t conector_es = {
    "conector",
    conector_puede_aceptar_fichero,
    conector_tomar_control_de,
    NULL
};

/* inicia_conector --
 *
 * Incicia conector bidireccional
 */

static awk_bool_t
inicia_conector()
{
    register_ext_version(ext_version);
    register_two_way_processor(&conector_es);
    return awk_true;
}

/* Define nuevos comantos para GAWK */

static awk_ext_func_t lista_de_funciones[] = {
    { "creatoma", haz_crea_toma,                   1, 1, awk_false, NULL },
    { "dtrytoma", haz_destruye_toma,               1, 1, awk_false, NULL },
    { "acabasrv", haz_acaba_toma_srv,              1, 1, awk_false, NULL },
    { "acabacli", haz_acaba_toma_cli,              1, 1, awk_false, NULL },
    { "traepcli", haz_trae_primer_cli,             2, 1, awk_false, NULL },
    { "pcertcla", haz_par_clave_y_certificado_tls, 3, 1, awk_false, NULL },
    { "lisautor", haz_lista_autoridades_tls,       2, 1, awk_false, NULL },
};

/* Cargar funciones */

dl_load_func(lista_de_funciones, conector, "")
