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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "gtls_defcom.h"

t_gtls_error gtls_error = {0, NULL};

/* gtls_msj_error */

char *
gtls_msj_error(const char *desc, ...)
{
    /* Variable para almacenar la lista de argumentos */
    va_list lista_args;
    char *ds;
    char msj_error[128] = "";

    va_start(lista_args, desc);

    while (*desc) {
        switch (*desc++) {
        case '%':   /* Prefijo texto */
            if (*desc++ == 's') {
                ds = va_arg(lista_args, char *);
                strcat(msj_error, ds);
            } else
                return NULL;
            break;
        case ' ':   /* Espacio */
            strcat(msj_error, " ");
            break;
        default:
            return NULL;
       }
    }

    va_end(lista_args);

    return strdup(msj_error);
}