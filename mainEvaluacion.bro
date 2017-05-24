#
# Universidad de Granada
# Departamento de Teoría de la Señal, Telemática y Comunicaciones.
#
# Archivo : mainEvaluacion.bro
#
# Autor :
#       Alejandra Cordero 
#   


#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

module HTTP;
@load segmentacion
@load evaluacion

#------------------------------------------------------------------------------#
#                                 REGISTROS                                    #
#------------------------------------------------------------------------------#

# Registro que almacenara las claves de la tabla "config".
type Clave: record {

        clave : string;
};


#------------------------------------------------------------------------------#
#                             VARIABLES GLOBALES                               #
#------------------------------------------------------------------------------#

global config : table[string] of Evaluacion::Valor; # Tabla que almacena los 
                                                    # parametros de configuracion.

# Tabla que almacena los datos provenientes del modelo del sistema.                                                  
global Btable: table[string,string] of Evaluacion::Probability = table();

global nombreArchivoConfig = "config";  # Nombre del archivo que contiene los
                                        # parametros de configuracion.

# Claves para acceder a la entrada de la tabla "config" que alamcena el valor 
# del valor Thetha.
global Theta: string = "Theta";

#------------------------------------------------------------------------------#
#                                FUNCIONES                                     #
#------------------------------------------------------------------------------#

function evaluarUri(host: string, uri: string){

    # Descripción de la función: Esta funcion dado un URI, lo segmenta y luego
    #                            evalua si este es anomalo o no.
    #
    # Variables de entrada:
    #    * host : Parte correspondiente al host del URI.
    #    * uri : Parte correspondiente al path, el query y el fragment del URI.
    #
    # Variables de salida:
    #    * Ninguna
    #  


    local indiceDeAnormalidad: double; # Variable que almacenara el indice de
                                       # anormalidad del URI segmentado.

    # Se segmenta tanto el "host" como el "uri" y el resultado de dicha 
    # operacion se alacena en el registro "Segmentacion::parsedUri".
    Segmentacion::parseHost(host);
    Segmentacion::parseUrl(uri);

    # Se almacena el uri completo en la estructura de datos que almacenara al uri
    # segmentado.
    Segmentacion::parsedUri$uri = cat(host,uri);

    # Se evalua el uri segmentado con el modelo cargado.
    indiceDeAnormalidad = Evaluacion::evaluar(Segmentacion::parsedUri,
                                                Btable,config);

    # Se veridica si existe alguna anormalidad con el uri.
    Evaluacion::verifiarAnomalia(config[Theta]$valor,indiceDeAnormalidad);

    # Se inicializa el registro que almacena el uri segmentado
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);

}

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){


    local nombreArchivo       = "alertas";      # Nombre del LOG de los URIs 
                                                # anomalos.

    local nombreArchivoModel  = "modeloBro.log";# Nombre del archivo que contiene
                                                # el modelo.

    print "Inicio de la evaluacion...";

    # Se crea el LOG que contendra los URIs anomalos en caso de que
    # existir.
    Log::create_stream(Evaluacion::LOG, [$columns=Evaluacion::InfoAtaque,
                                        $path=nombreArchivo]);

    # Se leen los datos del archivo de configuracion y se almacenan en la tabla
    # llamada "config".
    Input::add_table([$source=nombreArchivoConfig, $name=nombreArchivoConfig,
                          $idx=Clave, $val=Evaluacion::Valor, 
                          $destination=config]);


    # Se leen los datos del modelo y se almacenan en la tabla llamada "Btable".
    Input::add_table([$source=nombreArchivoModel, $name=nombreArchivoModel,
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=Btable]);
}

#------------------------------------------------------------------------------#

# Este evento es llamado una vez se hayan leido todos los datos del archivo
# "modeloBro.log" o del archivo "config".
event Input::end_of_data(name: string, source: string) {

    # Si existe el archivo "config" sin nada escrito en su interior,
    # el sistema lanzara un error anunciando que se deben introducir
    # los parametros de configuracion.
    if (name == "config" && |config| == 0){

        print "Se deben introducir los parametros de configuracion en el archivo";
        print "\"config\".";
        exit(0);
    }
    # Caso en el que el archivo "config" tenga informacion en su interior.
    else if (name == "config") {

        # Se verifica que todos los parametros de configuracion esten en el
        # archivo de configuracion.
        
        # Si falta algun parametro de configuracion se emitira un error.
        if (Theta !in config || "Poov1" !in config || "Poov2" !in config ||
            "Poov3" !in config || "Poov4" !in config){

            print "Se deben introducir los parametros de configuracion de forma correcta.";
            exit(0);

        }

        # Si alguno de los parametros de configuracion es negativo, entonces, se
        # emitira un error.
        if (config[Theta]$valor < 0.0 || config["Poov1"]$valor < 0.0 ||
            config["Poov2"]$valor < 0.0 || config["Poov3"]$valor < 0.0 ||
            config["Poov4"]$valor < 0.0){

            print "Se deben introducir los parametros de configuracion positivos.";
            exit(0);

        }

    }
}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    # Si el method es de tipo "HEAD" se procedera a evaluar si el URI
    # es anomalo o no.
    if ( c$http$method == "HEAD" ){

            evaluarUri(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#

event bro_done(){

    print "Finalizacion de la evaluacion...";
    print "-------------------------------------------------";
    print "Las alertas se han escrito en el LOG: alertas.log";
    print "-------------------------------------------------";

}

#------------------------------------------------------------------------------#
