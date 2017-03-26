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
global BSsTable: table[string] of Evaluacion::Probability = table();
global BSpTable: table[string] of Evaluacion::Probability = table();
global BSaTable: table[string] of Evaluacion::Probability = table();
global BSvTable: table[string] of Evaluacion::Probability = table();
global A:    table[string] of Evaluacion::Rows = table();
global vectorProbabilidad: vector of table[string] of Evaluacion::Probability = { BSsTable , BSpTable, BSvTable , BSaTable };

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

    print "---------------##------";
    print "Estoy en GET";
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);
    indicesDeAnormalidad = Evaluacion::evaluar(Segmentacion::parsedUri,
                                            vectorProbabilidad,
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
    Input::add_table([$source=modelo[Bss], $name=modelo[Bss],
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=BSsTable]);

    Input::add_table([$source=modelo[Bsp], $name=modelo[Bsp],
                          $idx=Evaluacion::Word, 
                          $val=Evaluacion::Probability,
                          $destination=BSpTable]);

    Input::add_table([$source=modelo[Bsa], $name=modelo[Bsa],
                          $idx=Evaluacion::Word, 
                          $val=Evaluacion::Probability, 
                          $destination=BSaTable]);

    Input::add_table([$source=modelo[Bsv], $name=modelo[Bsv],
                        $idx=Evaluacion::Word, 
                        $val=Evaluacion::Probability, 
                        $destination=BSvTable]);

}

#------------------------------------------------------------------------------#

event Input::end_of_data(name: string, source: string) {

}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            evaluarUri(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#
