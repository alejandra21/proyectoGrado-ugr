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

function entrenamiento(host: string, uri: string){


    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    print "---------------##------";
    print "Estoy en GET";
    print host;
    print uri;
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);
    print Segmentacion::parsedUri;
    Entrenamiento::entrenar(Segmentacion::parsedUri);
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);
    print "---------------##------";

}

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Iniciando entrenamiento...";
}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "HEAD" ){

            entrenamiento(c$http$host,c$http$uri);

    }
    
    }

#------------------------------------------------------------------------------#

event bro_done(){

    print "Finalizacion del entrenamiento...";
    Entrenamiento::escribirArchivo(Entrenamiento::tablaEntrenamieto);
    #exit(0);

}

#------------------------------------------------------------------------------#
