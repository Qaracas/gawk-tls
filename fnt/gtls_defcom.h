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

#include <stdio.h>

#ifndef DEFCOM_H
#define DEFCOM_H

#define CNTR_HECHO      (0)
#define CNTR_ERROR      (-5)
#define CNTR_DF_NULO    (-1)

#define gtls_ltd(x) (sizeof(x) / sizeof((x)[0]))

#define gtls_asigmem(puntero, tipo, cabida, mensaje) \
    do { \
        if ((puntero = (tipo) malloc(cabida)) == 0) \
            printf("%s: fallo reservando %d octetos de memoria", \
                   mensaje, (int)cabida); \
    } while(0)

#define gtls_limpia_error_simple() \
    do { \
        extern t_gtls_error gtls_error; \
        gtls_error.número = 0; \
        gtls_error.descripción = NULL; \
    } while(0)

#define gtls_limpia_error(numerror) \
    do { \
        extern t_gtls_error gtls_error; \
        numerror = 0; \
        gtls_error.número = 0; \
        gtls_error.descripción = NULL; \
    } while(0)

#define gtls_error(numerror, descripción_error) \
    do { \
        extern t_gtls_error gtls_error; \
        gtls_error.número = numerror; \
        gtls_error.descripción = descripción_error; \
    } while(0)

#ifndef T_CTRN_VERDAD
#define T_CTRN_VERDAD
typedef enum gtls_verdad {
    gtls_falso  = 0,
    gtls_cierto = 1
} t_gtls_verdad;
#endif

typedef struct gtls_error {
    int  número;       /* Número de error       */
    char *descripción; /* Descripción del error */
} t_gtls_error;

/* gtls_msj_error --
 *
 * Forma mensaje de error a partir de un resultado y un texto dado
 */

char *
gtls_msj_error(const char *desc, ...);

#endif /* DEFCOM_H */