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

function entrenamiento(host: string, uri: string){



    print "---------------##------";
    print "Estoy en GET";
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


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

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
