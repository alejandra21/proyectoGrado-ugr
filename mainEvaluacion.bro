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

function evaluarUri(host: string, uri: string){

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

    # Se almacena el uri en la estructura de datos que almacenara al uri
    # segmentado.
    Segmentacion::parsedUri$uri = cat(host,uri);

    # Se evalua el uri segmentado con el modelo cargado.
    indiceDeAnormalidad = Evaluacion::evaluar(Segmentacion::parsedUri,
                                                Btable,config);

    # Se veridica si existe alguna anormalidad con el uri.
    Evaluacion::verifiarAnomalia(config["Theta"]$valor,indiceDeAnormalidad);

    print indiceDeAnormalidad;
    print Segmentacion::parsedUri;
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);
    print "---------------##------------------------------------";

}

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio";

    local nombreArchivo = "alertas";
    Log::create_stream(Evaluacion::LOG, [$columns=Evaluacion::InfoAtaque, $path=nombreArchivo]);

    # Se leen los datos del archivo de configuracion.
    Input::add_table([$source="config", $name="config",
                          $idx=Clave, $val=Evaluacion::Valor, 
                          $destination=config]);


    # Se leen los datos del modelo
    Input::add_table([$source="modeloBro.log", $name="modeloBro.log",
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=Btable]);
}

#------------------------------------------------------------------------------#

event Input::end_of_data(name: string, source: string) {

    print "LEI LOS ARCHIVOS";

    if (name == "config" && |config| == 0){

        print "Se deben introducir los parametros de configuracion";
        exit(0);
    }
    else if (name == "config") {

        # Se verifica que todos los parametros de configuracion esten en el
        # archivo de configuracion.
        
        # Si falta algun parametro de configuracion se emitira un error.
        if (Theta !in config || "Poov1" !in config || "Poov2" !in config || "Poov3" !in config || "Poov4" !in config){

            print "Se deben introducir los parametros de configuracion de forma correcta.";
            exit(0);

        }

        # Si alguno de los parametros de configuracion es negativo, entonces, se
        # emitira un error.
        if (config[Theta]$valor < 0.0 || config["Poov1"]$valor < 0.0 || config["Poov2"]$valor < 0.0 || config["Poov3"]$valor < 0.0 || config["Poov4"]$valor < 0.0){

            print "Se deben introducir los parametros de configuracion positivos.";
            exit(0);

        }

    }
}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            evaluarUri(c$http$host,c$http$uri);

        }
    
    }

#------------------------------------------------------------------------------#
