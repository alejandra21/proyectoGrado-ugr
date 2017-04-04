#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

module HTTP;
@load segmentacion
@load evaluacion
@load entrenamiento

#------------------------------------------------------------------------------#
#                                 REGISTROS                                    #
#------------------------------------------------------------------------------#

type Model: record {

        clave : string;
};


type Valor: record {

        valor : string;
};

#------------------------------------------------------------------------------#
#                             VARIABLES GLOBALES                               #
#------------------------------------------------------------------------------#

global stringModelo: URI;
global modelo : table[string] of string;
global modelTable: table[string] of string;
global Btable: table[string,string] of Evaluacion::Probability = table();

# Claves del modelo.
global Bss: string   = "Bss";
global Bsp: string   = "Bsp";
global Bsv: string   = "Bsv";
global Bsa: string   = "Bsa";
global Poov: string  = "Poov";
global Theta: string = "Theta";

#------------------------------------------------------------------------------#
#                                FUNCIONES                                     #
#------------------------------------------------------------------------------#

function evaluarUri(host: string, uri: string){

    local indicesDeAnormalidad: table[count] of double;
    local probabilidad: double;
    local Ns: double;

    #print "---------------##------";
    #print "Estoy en GET";
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);
    indicesDeAnormalidad = Evaluacion::evaluar(Segmentacion::parsedUri,
                                            Btable,
                                            to_double(modelo[Poov]));

    Evaluacion::verifiarAnomalia(to_double(modelo[Theta]),indicesDeAnormalidad);
    print Segmentacion::parsedUri;
    print indicesDeAnormalidad;
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);
    print "---------------##------";

}

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio";
    # Se leen los datos del modelo.

    # Robustecer cuando leo los datos
    stringModelo  = decompose_uri(Modelo::leerModelo("modelo"));
    modelo = stringModelo$params;

    # Se extraen de un archivo de texto los vectores de probabilidad B
    Input::add_table([$source="modeloBro.log", $name="modeloBro.log",
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=Btable]);

    Segmentacion::parseHost("https://localhost:8080");
    Segmentacion::parseUrl("/search?client=ùbuntu&channel=fs&q%42=hacer+arroz&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=LNrGWOjdK-eJ8QeOzoaQBA");
    #print Segmentacion::parsedUri;
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);
    Segmentacion::parseHost("http://192.168.1.1:8080");
    #print Segmentacion::parsedUri;
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);

}

#------------------------------------------------------------------------------#

event Input::end_of_data(name: string, source: string) {

    print "LEI LOS ARCHIVOS";
    print Btable;
}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            evaluarUri(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#
