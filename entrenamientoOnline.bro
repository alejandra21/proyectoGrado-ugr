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

type Clave: record {

        clave : string;
};


#------------------------------------------------------------------------------#
#                             VARIABLES GLOBALES                               #
#------------------------------------------------------------------------------#

global stringModelo: URI;
global config : table[string] of Evaluacion::Valor;
global modelTable: table[string] of string;
global Btable: table[string,string] of Evaluacion::Probability = table();

# Claves del modelo.
global Poov: string  = "Poov";
global Theta: string = "Theta";

#------------------------------------------------------------------------------#
#                                FUNCIONES                                     #
#------------------------------------------------------------------------------#

function entrenarOnline(host: string, uri: string){

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    local indiceDeAnormalidad: double;
    local probabilidad: double;
    local Ns: double;

    print "---------------##------------------------------------";
    print host;
    print uri;
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);
    Entrenamiento::entrenarOnline(Segmentacion::parsedUri);
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);
    print "---------------##------------------------------------";

}

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio entrenamiento Online";

    # Se leen los datos del modelo
    Input::add_table([$source="modeloBro.log", $name="modeloBro.log",
                          $idx=Entrenamiento::Word, $val=Entrenamiento::Probability, 
                          $destination=Entrenamiento::Btable]);
}

#------------------------------------------------------------------------------#

event Input::end_of_data(name: string, source: string) {

    print "LEI LOS ARCHIVOS";
    print Entrenamiento::Btable;

}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            entrenarOnline(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#

event bro_done(){

    print "Finalizacion del entrenamiento...";
    #Entrenamiento::escribirArchivo(Entrenamiento::tablaEntrenamieto);
    #exit(0);

}

#------------------------------------------------------------------------------#

