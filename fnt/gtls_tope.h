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

#ifndef TOPE_H
#define TOPE_H

#define CNTR_TOPE_VACIO (-3)
#define CNTR_TOPE_RESTO (-4)

#define CNTR_TOPE_MAX_X_DEF 8192

#define BUCLE_VERIFICA(valret, cmd) \
    do { \
        valret = cmd; \
    } while(valret == EAGAIN)

typedef struct gtls_tope {
    size_t  bulto; /* Volumen o capacidad del tope */
    int    ldatos; /* Cantidad datos almacenados   */
    char   *datos; /* Datos almacenados            */
    int    ptrreg; /* Inicio registro actual       */
} t_gtls_tope;

/* gtls_nuevo_tope --
 *
 * Crea nuevo tope de tamaño 'bulto'
 */

int
gtls_nuevo_tope(t_gtls_tope **tope, size_t bulto);

/* gtls_borra_tope --
 *
 * Libera memoria y destruye tope
 */

void
gtls_borra_tope(t_gtls_tope **tope);

/* gtls_envia_datos --
 *
 * Recubrimiento para enviar datos por la toma
 */

ssize_t
gtls_envia_datos(t_capa_gnutls *capatls, int df_cliente,
                 const void *tope, size_t bulto);

/* gtls_recibe_datos --
 *
 * Recubrimiento para recibir datos por la toma
 */

ssize_t
gtls_recibe_datos(t_capa_gnutls *capatls, int df_cliente, void *tope,
                  size_t bulto);

/* gtls_rcbl_llena_tope --
 *
 * Llenar hasta el tope con líneas terminadas en RS
 */

int
gtls_rcbl_llena_tope(t_gtls_toma_es *toma);

/* gtls_rcbf_llena_tope --
 *
 * Llenar hasta el tope con flujo contínuo de datos
 */

int
gtls_rcbf_llena_tope(t_gtls_toma_es *toma);

/* gtls_vacía_tope --
 *
 * Vacía tope a cantidades de tamaño TPM (si es menor se vacía completamente)
 */

ssize_t
gtls_vacía_tope(t_gtls_toma_es *toma, char **sal, size_t tpm,
                char **sdrt, size_t *tsr);

#endif /* TOPE_H */