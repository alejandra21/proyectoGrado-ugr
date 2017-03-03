#------------------------------------------------------------------------------#
#					 			 IMPORTES           						   #
#------------------------------------------------------------------------------#

module HTTP;


#------------------------------------------------------------------------------#
#					 			REGISTROS           						   #
#------------------------------------------------------------------------------#

type MyRecordType: record {

    host: table [count] of string;
    path: table [count] of string;
    query: table[string] of string &default = table();
    fragment: string &default = "";

};

type Word: record {
        word: string;
};

type Probability: record {
        probability: double;
};


global BS1: table[string] of Probability = table();
global parsedUri: MyRecordType;
global epsilon : double = 0.0001;


#------------------------------------------------------------------------------#
#					 FUNCIONES PARA SEGMENTAR EL URI 						   #
#------------------------------------------------------------------------------#

function inicializarRecord(datos: MyRecordType){

	datos$host = table();
	datos$path = table();
	datos$query = table();;
	datos$fragment = "";

}


function parsePath(url:string){

	print url;
	# Se comprueba que exista un host con su ruta.
	local test_pattern = /\//;
	local results = split(url, test_pattern);
	parsedUri$path = results;

}

function parseFragment(url:string){
	
	local test_pattern = /\/#.*/;
	local results = split(url, test_pattern);
	if (|results| == 2){

		if (results[1] == ""){

			parsedUri$fragment = results[2];

		}
		else{

			print "ERROR fragment 1!";
			exit(0);	

		}

	}
	else{
		print "ERROR fragment 2!";
		exit(0);		
	}

}

function parseQueryFragment(url:string){

	local test_pattern = /\/\?([A-Za-z0-9_\-]+(=[A-Za-z0-9_\-]*)?(&[A-Za-z0-9_\-]+(=[A-Za-z0-9_\-]*)?)*)?/;
	local results = split_all(url, test_pattern);
	local queryUri : URI;

	if (|results|==3){

		queryUri = decompose_uri(results[2]);
		parsedUri$query = queryUri$params;

		# Se verifica si el "fragment" hace match con la expresion regular
		# correspondiente.
		parseFragment(results[3]);

		#print parsedUri$query;
		#print parsedUri$fragment;

		# Itero sobre los atributos
		for ([i] in parsedUri$query) {

		    if (parsedUri$query[i] == "done")
		        break;
		    if (parsedUri$query[i] == "skip")
		        next;
		    print i;

		}

	}

	else if (|results|==2){

		queryUri = decompose_uri(results[2]);
		parsedUri$query = queryUri$params;

		# Itero sobre los atributos.
		for ([i] in parsedUri$query) {

		    if (parsedUri$query[i] == "done")
		        break;
		    if (parsedUri$query[i] == "skip")
		        next;
		    print i;

		}

	}
	else{

		print "ERROR QUERY FRAGMENT";
		exit(0);
	}

}

function fragmentHost(url: string){


	if (url == ""){

		print "ERROR";
		exit(0);

	}
	else{

		local test_pattern = /\./;
		local results = split(url, test_pattern);
		parsedUri$host = results;

	}

}

function parseHost(url: string){

	local test_pattern = /(http(s)?:\/\/)?(([a-z]+[a-z0-9\-]*[.])?([a-z0-9]+[a-z0-9\-]*[.])+[a-z]{2,3}|localhost)/;
	local results = split_all(url, test_pattern);

	if (results[1]=="" && ((|results| == 2)||(|results|==3 && results[3]=="") ) ){

		fragmentHost(results[2]);

	}
	else {

		print "ERROR EN HOST";
		exit(0);

	}

}

function parseUrl(url: string) {

	# Se parsea el host y la ruta
	local test_pattern = /(\/[a-z0-9_-]+[a-z0-9_.-]*)*/;
	local results = split_all(url, test_pattern);

	# El primer fragmento debe estar vacio
	if ( results[1] != "" ){
		print "ERROR PARSE URI 1";
		print results[1];
		return;
		
	}

	#El segundo fragmento contendra el host y la ruta correspondiente.
	if (results[2] != ""){
		parsePath(results[2]);		
	}

	else {
		print "ERROR PARSE URI 2";
		return;
	}

	# El tercer fragmento (opcional) contendrá los datos para realizar
	# el query y el fragment.
	if (results[3] != ""){
		parseQueryFragment(results[3]);
	}

}

#------------------------------------------------------------------------------#
#			         FUNCIONES PARA EL MODULO DE EVALUACION                    #
#------------------------------------------------------------------------------#

function evaluarValores(wordList:table[string] of string, pVector: table[string] of Probability): double{

	local results : double;
	local OOV : bool = T;

	results = 0.0;

	for ( i in wordList){

		for ([key] in pVector){

			if (wordList[i] == key){

				# Se suma la probabilidad de la palabra que se encuentra en el
				# diccionario.
				print "estoy en la funcion";
				results =  results + pVector[key]$probability;
				OOV = F;
			}
		}
	
		# Si la palabra esta fuera del vocabulario se le asigna una probabilidad
		# muy baja.

		if (OOV){

			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;
		}
		else{

			# Se entra en este caso si la palabra estaba en el vocabulario.
			OOV = T;
		}
	
	}

	return results;

}

function evaluarAtributos(wordList:table[string] of string, pVector: table[string] of Probability): double{

	local results : double;
	local OOV : bool = T;

	results = 0.0;

	for ( [word] in wordList ){

		for ([key] in pVector){

			if (word == key){

				# Se suma la probabilidad de la palabra que se encuentra en el
				# diccionario.
				print "estoy en la funcion";
				results =  results + pVector[key]$probability;
				OOV = F;
			}
		}
	
		# Si la palabra esta fuera del vocabulario se le asigna una probabilidad
		# muy baja.

		if (OOV){

			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;
		}
		else{

			# Se entra en este caso si la palabra estaba en el vocabulario.
			OOV = T;
		}
	
	}

	return results;

}

function evaluarHostPath(wordList:table [count] of string, pVector: table[string] of Probability): double{

	local results : double;
	local OOV : bool = T;

	results = 0.0;

	for ( i in wordList){

		for ([key] in pVector){

			if (wordList[i] == key){

				# Se suma la probabilidad de la palabra que se encuentra en el
				# diccionario.
				print "estoy en la funcion";
				results =  results + pVector[key]$probability;
				OOV = F;
			}
		}
	
		# Si la palabra esta fuera del vocabulario se le asigna una probabilidad
		# muy baja.

		if (OOV){

			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;
		}
		else{

			# Se entra en este caso si la palabra estaba en el vocabulario.
			OOV = T;
		}
	
	}

	return results;
}

#------------------------------------------------------------------------------#
#							 EVENTO PRINCIPAL                                  #
#------------------------------------------------------------------------------#

event bro_init(){

	# Se extraen de un archivo de texto los vectores de probabilidad B
	Input::add_table([$source="B1", $name="BS1",
	                      $idx=Word, $val=Probability, $destination=BS1]);

	parseHost("http://www.waldronsphotography.com");
	parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");
	print evaluarHostPath(parsedUri$host,BS1);
	print evaluarValores(parsedUri$query,BS1);
	print evaluarAtributos(parsedUri$query,BS1);

}

event Input::end_of_data(name: string, source: string) {
        # now all data is in the table
        #print BS1;
}

event http_reply(c: connection, version: string, code: count, reason: string)
	{

	if ( c$http$method == "GET" && c$http$status_code == 200 ){
			local uri = c$http$uri;
			print "EL URI ES:";
			print uri;
			print "El host es:";
			print c$http$host;
			#parseHost(c$http$host);
			#parseUrl(c$http$uri);
			#print evaluarHostPath(parsedUri$host,BS1);
			#print evaluarValores(parsedUri$query,BS1);
			inicializarRecord(parsedUri);
		}
	
	}