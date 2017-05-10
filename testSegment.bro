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

event Input::end_of_data(name: string, source: string) {

        local indicesDeAnormalidad: table[count] of double;
        local queryUri : URI;
        # now all data is in the table
        for (i in uriTable){

            print "-------------";
            Segmentacion::parseHost(i);
            Segmentacion::parseUrl(uriTable[i]$path);
            print Segmentacion::parsedUri;

            # Se almacena el uri en la estructura de datos que almacenara al uri
            # segmentado.
            Segmentacion::parsedUri$uri = cat(i,uriTable[i]$path);
            Segmentacion::inicializarRecord(Segmentacion::parsedUri);
            print "-------------";

        }

}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            print "";
        }
    
    }