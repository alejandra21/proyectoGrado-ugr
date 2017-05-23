#
# Universidad de Granada
# Departamento de Teoría de la Señal, Telemática y Comunicaciones.
#
# Archivo : mainEntrenamiento.bro
#
# Autor :
#       Alejandra Cordero 
#   


#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

module HTTP;
@load segmentacion
@load entrenamiento

#------------------------------------------------------------------------------#
#                                FUNCIONES                                     #
#------------------------------------------------------------------------------#

function entrenamiento(host: string, uri: string){


    # Descripción de la función: Funcion que se encarga de llamar a las 
    #                            funciones de segmentacion y entrenamiento.
    #
    # Variables de entrada:
    #    * host : Parte correspondiente al host del URI.
    #    * uri : Parte correspondiente al path, el query y el fragment del URI.
    #
    # Variables de salida:
    #    * Ninguna
    #    


    # Se segmenta tanto el "host" como el "uri" y el resultado de dicha 
    # operacion se alacena en el registro "Segmentacion::parsedUri" 
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);
 
    # Una vez segmentado el uri, se procede a evaluar la expresion del
    # entrenamiento.
    Entrenamiento::entrenar(Segmentacion::parsedUri);

    # Se inicializa el registro que almacena el uri segmentado
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);


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

        # Si el method es HEAD se hace la llamada a la funcion "entrenamiento"
        if ( c$http$method == "GET" ){

                entrenamiento(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#

event bro_done(){

    print "Finalizacion del entrenamiento...";

    # Se escribe en el archivo modelBro.log los resultados obtenidos en el 
    # entrenamiento.
    Entrenamiento::escribirArchivo(Entrenamiento::tablaEntrenamieto);

}

#------------------------------------------------------------------------------#
