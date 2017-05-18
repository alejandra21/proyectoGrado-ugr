#------------------------------------------------------------------------------#
#                                IMPORTES                                      #
#------------------------------------------------------------------------------#

@load segmentacion
@load evaluacion
@load entrenamiento

#------------------------------------------------------------------------------#

type Host: record {
        host: string;
};

type Path: record {
        path: string;
};

type Clave: record {

        clave : string;
};

global config : table[string] of Evaluacion::Valor;
global modelTable: table[string] of string;
global Btable: table[string,string] of Evaluacion::Probability = table();

#------------------------------------------------------------------------------#

# Create an ID for our new stream. By convention, this is
# called "LOG".
redef enum Log::ID += { LOG };

# Define the record type that will contain the data to log.


#------------------------------------------------------------------------------#

global uriTable: table[string] of Path = table();

#------------------------------------------------------------------------------#

event bro_init(){

    local nombreArchivo = "alertas";
    Log::create_stream(Evaluacion::LOG, [$columns=Evaluacion::InfoAtaque, $path=nombreArchivo]);

	# Se inicializa el registro que guardara los segmentos del URI parseado.
	Input::add_table([$source="uriExample/urls", $name="uriExample/urls",
	                   $idx=Host, $val=Path, $destination=uriTable]
				    );

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

event Input::end_of_data(name: string, source: string) {

        local indicesDeAnormalidad: table[count] of double;
        local queryUri : URI;
        # now all data is in the table
        for (i in uriTable){

            print "-------------";
            #Segmentacion::parseHost(i);
            #Segmentacion::parseUrl(uriTable[i]$path);
            evaluarUri(i,uriTable[i]$path);
            #print "uri sin segmentar";
            #print uriTable[i]$path;

            #print Segmentacion::parsedUri;
            # Se almacena el uri en la estructura de datos que almacenara al uri
            # segmentado.
            #Segmentacion::parsedUri$uri = cat(i,uriTable[i]$path);

            #queryUri = decompose_uri(Segmentacion::parsedUri$uri);
            #print queryUri;

            #Segmentacion::inicializarRecord(Segmentacion::parsedUri);

            print "-------------";

        }

}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            #evaluarUri(c$http$host,c$http$uri);
        }
    
    }