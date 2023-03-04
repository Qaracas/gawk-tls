#!/usr/bin/gawk -E

# Autor: Ulpiano Tur de Vargas <ulpiano.tur.devargas@gmail.com>
#
# Este programa es software libre; puedes distribuirlo y/o
# modificarlo bajo los términos de la Licencia Pública General de GNU
# según la publicó la Fundación del Software Libre; ya sea la versión 3, o
# (a su elección) una versión superior.
#
# Este programa se distribuye con la esperanza de que sea útil,
# pero SIN NINGUNA GARANTIA; ni siquiera la garantía implícita de
# COMERCIABILIDAD o APTITUD PARA UN PROPÓSITO DETERMINADO. Vea la
# Licencia Pública General de GNU para más detalles.
#
# Deberías haber recibido una copia de la Licencia Pública General
# de GNU junto con este software; mira el fichero LICENSE. Si
# no, mira <https://www.gnu.org/licenses/>.

# Author: Ulpiano Tur de Vargas <ulpiano.tur.devargas@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this software; see the file LICENSE. If
# not, see <https://www.gnu.org/licenses/>.

@load "gawk_tls";

BEGIN {
    # HTTP/1.1 define la secuencia <retorno de carro> \r <salto de línea> \n
    # como delimitador para todos los elementos, excepto en el cuerpo del
    # mensaje.
    RS = ORS = "\r\n";

    # Si el tope máximo (TMP) es 0 leeremos datos hasta RS, si es mayor que
    # cero leeremos una cantidad TPM de 'bytes' cada vez.
    TPM = 0;

    ServidorHttp = ARGV[1];
    #ServicioHttp = "/ired/tcp/0/0/" ServidorHttp "/80";
    ServicioHttp = "/ired/tls/0/0/" ServidorHttp "/443";

    creatoma(ServicioHttp);

    # Añade certificados de AC (opcional)
    lisautor(ServicioHttp, "certificados/certificados_acs_raiz.pem");

    # Cabecera de la petición HTTP

    print "GET " ARGV[2] " HTTP/1.1"  |& ServicioHttp;
    print "Host: " ServidorHttp                |& ServicioHttp;
    print                                      |& ServicioHttp;

    # Cabecera de la respuesta HTTP

    lgtd = 0;
    metd = "";
    while (resul = (ServicioHttp |& getline)) {
#        print $0;
        if (tolower($1) == "content-length:")
            lgtd = $2;
        if (tolower($1) == "transfer-encoding:")
            metd = $2;
        if (length($0) == 0)
            break;
    }

    # Cuerpo de la respuesta HTTP

    if (lgtd > 0 && metd == "") {
        lee_bulto(ServicioHttp, lgtd)
    } else if (lgtd == 0 && metd == "chunked") {
        lee_trozos(ServicioHttp);
    } else {
        print "Error: respuesta http incorrecta."
        exit 0;
    }

    acabacli(ServicioHttp);
    dtrytoma(ServicioHttp);
    exit 0;
}

function lee_trozos(canalxxxIP,      ors, tpm, v_tpm)
{
    tpm = TPM;
    ors = ORS;

    ORS = "";

    while (canalxxxIP |& getline) {
        if ($0 == "")
            continue;
        if ((v_tpm = sprintf("%d", strtonum("0x"$0)) + 0) == 0)
            break;

        TPM = 2; (canalxxxIP |& getline); TPM = v_tpm;

        while (canalxxxIP |& getline) {
            print $0;
            if ((TPM -= LTD) == 0) {
                break;
            }
        }

        TPM = 0;
    }

    TPM = tpm;
    ORS = ors;
}

function lee_bulto(canalxxxIP, bulto,      ors, cnt, tpm) {
    tpm = TPM;
    ors = ORS;

    ORS = "";

    TPM = 2;
    (canalxxxIP |& getline)
    TPM = bulto;

    cnt = 0;
    while (ServicioHttp |& getline) {
        print $0;
        if ((cnt += LTD) >= bulto)
            break;
    }

    TPM = tpm;
    ORS = ors;
}