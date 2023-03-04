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

#include "gtls_defcom.h"
#include "gtls_ruta.h"
#include "gtls_toma.h"
#include "gtls_stoma.h"
#include "gtls_serie.h"

static t_gtls_pieza *serie;

/* privada - __pon_ruta_en_serie */

static t_gtls_ruta *
__pon_ruta_en_serie(t_gtls_ruta *ruta, t_gtls_pieza **serie)
{
    if (*serie == NULL) {
        gtls_asigmem(*serie, t_gtls_pieza *,
                     sizeof(t_gtls_pieza), "gtls_pon_ruta_en_serie");
        (*serie)->ruta = ruta;
        (*serie)->siguiente = NULL;
    } else if (strcmp(ruta->nombre, (*serie)->ruta->nombre) == 0) {
        return NULL;
    } else
        return __pon_ruta_en_serie(ruta, &(*serie)->siguiente);

    return (*serie)->ruta;
}

/* privada - __borra_ruta_en_serie */

static void
__borra_ruta_en_serie(const char *nombre_ruta, t_gtls_pieza **serie)
{
    if (nombre_ruta != NULL && *serie != NULL) {
        if (strcmp(nombre_ruta,
                   (const char *)(*serie)->ruta->nombre) == 0) {
            //gtls_borra_ruta((*serie)->ruta);
            if ((*serie)->siguiente == NULL ) {
                free(*serie);
                *serie = NULL;
            } else {
                *serie = (*serie)->siguiente;
            }
        } else {
            __borra_ruta_en_serie(nombre_ruta, &(*serie)->siguiente);
        }
    }
}

/* privada - __busca_ruta_en_serie */

static t_gtls_ruta *
__busca_ruta_en_serie(const char *nombre_ruta, t_gtls_pieza *serie)
{
    if (nombre_ruta == NULL || serie == NULL)
        return NULL;
    else if (strcmp(nombre_ruta, serie->ruta->nombre) == 0)
        return serie->ruta;
    else
        return __busca_ruta_en_serie(nombre_ruta, serie->siguiente);
    return NULL;
}

/* gtls_pon_ruta_en_serie */

t_gtls_ruta *
gtls_pon_ruta_en_serie(t_gtls_ruta *ruta)
{
    extern t_gtls_pieza *serie;

    return __pon_ruta_en_serie(ruta, &serie);
}

#define __pon_ruta_en_serie call function

/* gtls_borra_ruta_de_serie */

void
gtls_borra_ruta_de_serie(const char *nombre_ruta)
{
    extern t_gtls_pieza *serie;

    __borra_ruta_en_serie(nombre_ruta, &serie);
}

#define __borra_ruta_en_serie call function

/* gtls_busca_ruta_en_serie */

t_gtls_ruta *
gtls_busca_ruta_en_serie(const char *nombre_ruta)
{
    extern t_gtls_pieza *serie;

    return __busca_ruta_en_serie(nombre_ruta, serie);
}

#define __busca_ruta_en_serie call function
