#
# Universidad de Granada
# Departamento de Teoría de la Señal, Telemática y Comunicaciones.
#
# Archivo : mainEntrenamientoOnline.bro
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
@load evaluacion


#------------------------------------------------------------------------------#
#                             VARIABLES GLOBALES                               #
#------------------------------------------------------------------------------#


global nombreArchivoModel  = "modeloBro.log";# Nombre del archivo que contiene
                                             # el modelo.

#------------------------------------------------------------------------------#
#                                FUNCIONES                                     #
#------------------------------------------------------------------------------#

function entrenarOnline(host: string, uri: string){

    # Descripción de la función: Funcion que se encarga de llamar a las 
    #                            funciones de segmentacion y 
    #                            entrenamiento Online .
    #
    # Variables de entrada:
    #    * host : Parte correspondiente al host del URI.
    #    * uri : Parte correspondiente al path, el query y el fragment del URI.
    #
    # Variables de salida:
    #    * Ninguna
    #   

    # Se segmenta tanto el "host" como el "uri" y el resultado de dicha 
    # operacion se alacena en el registro "Segmentacion::parsedUri".
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);

    print Segmentacion::parsedUri;

    # Una vez segmentado el uri, se procede a evaluar la expresion del
    # entrenamiento.
    Entrenamiento::entrenarOnline(Segmentacion::parsedUri);

    # Se inicializa el registro que almacena el uri segmentado.
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);

}

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio entrenamiento Online";

    # Se leen los datos del modelo y se almacenan en la tabla llamada "Btable".
    Input::add_table([$source=nombreArchivoModel, $name=nombreArchivoModel,
                          $idx=Entrenamiento::Word, $val=Entrenamiento::Probability, 
                          $destination=Entrenamiento::Btable]);

    Input::remove(nombreArchivoModel);
}

#------------------------------------------------------------------------------#

# Este evento es llamado una vez se hayan leido todos los datos del archivo
# "modeloBro.log".

event Input::end_of_data(name: string, source: string) {

    # Se verifica si el archivo que contiene los datos del modelo se encuentra
    # vacio o no.
    if (name == nombreArchivoModel && |Entrenamiento::Btable| > 0){

        # Se lee el numero de palabras que existe en cada estado.
        for (i in Entrenamiento::numPalabrasTable){

            Entrenamiento::numPalabrasTable[i] = Entrenamiento::Btable[i,"numTotal"]$probability;
        }
        
    }

}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    # Si el method es HEAD se hace la llamada a la funcion "entrenarOnline"
    if ( c$http$method == "HEAD" ){

            entrenarOnline(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#

event bro_done(){

    print "Finalizacion del entrenamiento...";

    # Se escribe en el archivo modelBro.log los resultados obtenidos en el 
    # entrenamiento.
    Entrenamiento::escribirArchivoOnline(Entrenamiento::Btable);

}

#------------------------------------------------------------------------------#

