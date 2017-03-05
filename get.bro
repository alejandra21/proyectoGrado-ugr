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


global BSsx: table[string] of Probability = table();
global BSpx: table[string] of Probability = table();
global BSax: table[string] of Probability = table();
global BSvx: table[string] of Probability = table();
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

	results = 0.0;

	for ( i in wordList){

		print wordList[i];

		if (wordList[i] in pVector){

			print "LA PALABRA ESTA";

			# Se suma la probabilidad de la palabra que se encuentra en el
			# diccionario.
			results =  results + pVector[wordList[i]]$probability;

		}
		else{

			print "NO ESTA LA PALABRA";
			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;

		}
	}

	return results;

}

function evaluarAtributos(wordList:table[string] of string, pVector: table[string] of Probability): double{

	local results : double;

	results = 0.0;

	for ( [word] in wordList ){

		print "WORD";
		print word;

		if (word in pVector){

			print "LA PALABRA ESTA";

			# Se suma la probabilidad de la palabra que se encuentra en el
			# diccionario.
			results =  results + pVector[word]$probability;

		}
		else{

			print "NO ESTA LA PALABRA";

			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;

		}
	}

	return results;

}

function evaluarHostPath(wordList:table [count] of string, pVector: table[string] of Probability): double{

	local results : double;
	results = 0.0;

	print pVector;
	for ( i in wordList){

		print wordList[i];

		if (wordList[i] in pVector){

			print "LA PALABRA ESTA";

			# Se suma la probabilidad de la palabra que se encuentra en el
			# diccionario.
			results =  results + pVector[wordList[i]]$probability;

		}
		else{

			print "NO ESTA LA PALABRA";

			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;

		}

	}
	
	return results;
}

function evaluar(uriParsed:MyRecordType, pVector: table[string] of Probability): vector of double {

	local host : double;
	local valores : double;
	local atributos : double;


	host = evaluarHostPath(parsedUri$host,pVector);
	valores = evaluarValores(parsedUri$query,pVector);
	atributos = evaluarAtributos(parsedUri$query,pVector);

	local results: vector of double = { host , valores , atributos };

	return results;

}

#------------------------------------------------------------------------------#
#			            FUNCIONES PARA EL ENTRENAMIENTO                        #
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
#							 EVENTO PRINCIPAL                                  #
#------------------------------------------------------------------------------#

event bro_init(){

	# Se extraen de un archivo de texto los vectores de probabilidad B
	Input::add_table([$source="BSs", $name="BSs",
	                      $idx=Word, $val=Probability, $destination=BSsx]);

	Input::add_table([$source="BSp", $name="BSp",
	                      $idx=Word, $val=Probability, $destination=BSpx]);

	Input::add_table([$source="BSa", $name="BSa",
	                      $idx=Word, $val=Probability, $destination=BSax]);

	Input::add_table([$source="BSv", $name="BSv",
	                      $idx=Word, $val=Probability, $destination=BSvx]);

	parseHost("http://www.hola.com");
	parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");

	

	#print evaluarHostPath(parsedUri$host,BS1);
	#print evaluarValores(parsedUri$query,BS1);
	#print evaluarAtributos(parsedUri$query,BS1);

}

event Input::end_of_data(name: string, source: string) {
        # Pensar un poco cual es la solucion mas efeciente.
        print evaluar(parsedUri,BSsx);
        print BSsx;

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