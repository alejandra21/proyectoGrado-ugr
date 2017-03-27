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


}

#------------------------------------------------------------------------------#

event Input::end_of_data(name: string, source: string) {

        # now all data is in the table
        for (i in uriTable){

            print "-------------";
            print i;
            print uriTable[i]$path;
            Segmentacion::parseHost(i);
            Segmentacion::parseUrl(uriTable[i]$path);
            print "-------------";

        }

}

#------------------------------------------------------------------------------#

event http_reply(c: connection, version: string, code: count, reason: string)
    {


    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            print c;

        }
    
    }