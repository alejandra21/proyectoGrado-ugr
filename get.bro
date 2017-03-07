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

#------------------------------------------------------------------------------#
# 						REGISTROS PARA LOS VECTORES B
#------------------------------------------------------------------------------#

type Word: record {
        word: string;
};

type Probability: record {
        probability: double;
};

#------------------------------------------------------------------------------#
# 						REGISTRO PARA LA MATRIZ A
#------------------------------------------------------------------------------#

type Column: record {
        column: string;
};

type Rows: record {
        Ssi: int;
        Spi: int;
        Sai: int;
        Svi: int;
};

#------------------------------------------------------------------------------#
# 						REGISTRO USADO EN EL ENTRENAMIENTO
#------------------------------------------------------------------------------#

type Entrenamiento: record {

		numPalabras : int &default = 1;
        probability: double &default = 0.0;
};


#------------------------------------------------------------------------------#

global BSsx: table[string] of Probability = table();
global BSpx: table[string] of Probability = table();
global BSax: table[string] of Probability = table();
global BSvx: table[string] of Probability = table();
global A: 	 table[string] of Rows = table();
global parsedUri: MyRecordType;
global vectorProbabilidad: vector of table[string] of Probability = { BSsx , BSpx, BSvx , BSax };

# Variables utilizadas en el modulo de entrenamiento.
global numeroPalabraSs : int = 0;
global numeroPalabraSp : int = 0;
global numeroPalabraSv : int = 0;
global numeroPalabraSa : int = 0;

global entrenamientoSs: table[string] of Entrenamiento = table();
global entrenamientoSp: table[string] of Entrenamiento = table();
global entrenamientoSa: table[string] of Entrenamiento = table();
global entrenamientoSv: table[string] of Entrenamiento = table();

# Variables para experimentar
global epsilon : double = 0.0001;
global probA : int = 0;
global theta: double = 5;

#------------------------------------------------------------------------------#
#					 FUNCIONES PARA SEGMENTAR EL URI 						   #
#------------------------------------------------------------------------------#

function inicializarRecord(datos: MyRecordType){

	datos$host = table();
	datos$path = table();
	datos$query = table();;
	datos$fragment = "";

}

#------------------------------------------------------------------------------#

function parsePath(url:string){

	# Se comprueba que exista un host con su ruta.
	local test_pattern = /\//;
	local results = split(url, test_pattern);

	# Se elimina el primer elemento.
	if (results[1] == ""){

		delete results[1];

	}

	parsedUri$path = results;

}

#------------------------------------------------------------------------------#

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

#------------------------------------------------------------------------------#

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
		    #print i;

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

#------------------------------------------------------------------------------#

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

#------------------------------------------------------------------------------#

function returnUri(uri:string):string{

	local test_pattern = /(http(s)?:\/\/)?/;
	local results = split(uri,test_pattern);

	if (|results| == 2){
		return results[2];
	}
	else if (|results| == 1){
		return results[1];
	}
	else{

		print "ERROR RETURN URI!";
		exit(0);
	}


}

#------------------------------------------------------------------------------#

function parseHost(url: string){

	# Se extrae el squematic.
	local urlResult = returnUri(url);

	# Se parsea el host
	local test_pattern = /(([a-z]+[a-z0-9\-]*[.])?([a-z0-9]+[a-z0-9\-]*[.])+[a-z]{2,3}|localhost)/;
	local results = split_all(urlResult, test_pattern);

	# Se verifica si el host esta bien construido
	if (results[1]=="" && ((|results| == 2)||(|results|==3 && results[3]=="") ) ){

		fragmentHost(results[2]);

	}
	else {

		print "ERROR EN HOST";
		exit(0);

	}

}

#------------------------------------------------------------------------------#

function parseUrl(url: string) {

	# Se parsea la ruta
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

		#print wordList[i];

		if (wordList[i] in pVector){

			#print "LA PALABRA ESTA";

			# Se suma la probabilidad de la palabra que se encuentra en el
			# diccionario.
			results =  results + pVector[wordList[i]]$probability;

		}
		else{

			#print "NO ESTA LA PALABRA";
			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;

		}
	}

	return results;

}

#------------------------------------------------------------------------------#

function evaluarAtributos(wordList:table[string] of string, pVector: table[string] of Probability): double{

	local results : double;

	results = 0.0;

	for ( [word] in wordList ){

		#print "WORD";
		#print word;

		if (word in pVector){

			#print "LA PALABRA ESTA";

			# Se suma la probabilidad de la palabra que se encuentra en el
			# diccionario.
			results =  results + pVector[word]$probability;

		}
		else{

			#print "NO ESTA LA PALABRA";

			# Se entra en este caso si la palabra no estaba en el vocabulario.
			results = results + epsilon;

		}
	}

	return results;

}

#------------------------------------------------------------------------------#

function evaluarHostPath(wordList:table [count] of string, pVector: table[string] of Probability): double{

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

#------------------------------------------------------------------------------#

function evaluar(uriParsed:MyRecordType, pVector: vector of table[string] of Probability): table[count] of double {

	local host : double;
	local path : double;
	local valores : double;
	local atributos : double;

	host = evaluarHostPath(parsedUri$host,pVector[0]);
	path = evaluarHostPath(parsedUri$path,pVector[1]);
	valores = evaluarValores(parsedUri$query,pVector[2]);
	atributos = evaluarAtributos(parsedUri$query,pVector[3]);

	local results : table[count] of double = { [1] = host , 
											   [2] = path, 
											   [3] = valores, 
											   [4] = atributos };

	if (path == 0.0 && valores == 0.0 && atributos == 0.0){

		# results = { host };
		delete results[2];
		delete results[3];
		delete results[4];
	
	}
	else if (valores == 0.0 && atributos == 0.0){

		# results = { host , path };
		delete results[3];
		delete results[4];

	}
	else if (path == 0.0 ){

		# results  = { host , valores , atributos };
		delete results[2];

	}

	return results;

}

#------------------------------------------------------------------------------#

function calcularProbabilidad(vectorB: table[count] of double) : double {

	local resultVectorB : double;
	resultVectorB = 0.0;

	# Se calcula la sumatoria de las probabilidades que contiene el vectorB
	for (i in vectorB){

		resultVectorB = resultVectorB + Math::logaritmo(vectorB[i]);
	}

	return resultVectorB;

}

#------------------------------------------------------------------------------#

function calcularIndiceAnormalidad(probabilidad: double) : double {

	local indiceAnormalidad : double;
	indiceAnormalidad = - (probabilidad);

	return indiceAnormalidad;

}

#------------------------------------------------------------------------------#

function verifiarAnomalia(theta: double, indiceAnormalidad: double){

	if (indiceAnormalidad >= theta){
		print "EMITIR ALARMA";
	}
	else {
		print "TODO ESTA NORMAL";
	}
}

#------------------------------------------------------------------------------#
#			            FUNCIONES PARA EL ENTRENAMIENTO                        #
#------------------------------------------------------------------------------#

function entrenamientoPathHost(wordList: table [count] of string, vocabulario: table[string] of Entrenamiento,numPalabras: int): int{

	for (i in wordList){

		if (wordList[i] in vocabulario){

			# Se suma una unidad a la palabra que ya se encontraba en el 
			# vocabulario.
			vocabulario[wordList[i]]$numPalabras = vocabulario[wordList[i]]$numPalabras + 1;

		}
		else{

			# Se agrega la nueva palabra al vocabulario
			vocabulario[wordList[i]] = Entrenamiento();

		}
	
		# Se cuenta el numero de palabras que hay en el arreglo wordList
		numPalabras = numPalabras + 1;
	
	}

	return numPalabras;
}

#------------------------------------------------------------------------------#

function entrenamientoAtributos(wordList: table [string] of string, vocabulario: table[string] of Entrenamiento, numPalabras: int): int{

	
	for (i in wordList){

		if (wordList[i] in vocabulario){

			# Se suma una unidad a la palabra que ya se encontraba en el 
			# vocabulario.
			vocabulario[wordList[i]]$numPalabras = vocabulario[wordList[i]]$numPalabras + 1;

		}
	
		else{

			# Se agrega la nueva palabra al vocabulario
			vocabulario[wordList[i]] = Entrenamiento();

		}
	
		# Se cuenta el numero de palabras que hay en el arreglo wordList
		numPalabras = numPalabras + 1;
	
	}

	return numPalabras;
	
}

#------------------------------------------------------------------------------#

function entrenamientoValores(wordList: table [string] of string, vocabulario: table[string] of Entrenamiento, numPalabras: int): int {
	
	for ( [word] in wordList){

		if (word in vocabulario){

			# Se suma una unidad a la palabra que ya se encontraba en el 
			# vocabulario.
			vocabulario[word]$numPalabras = vocabulario[word]$numPalabras + 1;

		}
	
		else{

			# Se agrega la nueva palabra al vocabulario
			vocabulario[word] = Entrenamiento();

		}
	
		# Se cuenta el numero de palabras que hay en el arreglo wordList
		numPalabras = numPalabras + 1;
	
	}

	return numPalabras;
	
}

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

	Input::add_table([$source="A", $name="A",
                      $idx=Column, $val=Rows, $destination=A]);

	#parseHost("http://www.hola.com");
	#parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");

}

event Input::end_of_data(name: string, source: string) {

	parseHost("http://www.hola.com");
	parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");
	numeroPalabraSs = entrenamientoPathHost(parsedUri$host, entrenamientoSs ,numeroPalabraSs);
	numeroPalabraSp = entrenamientoPathHost(parsedUri$path, entrenamientoSp ,numeroPalabraSp);
	numeroPalabraSa = entrenamientoAtributos(parsedUri$query, entrenamientoSa ,numeroPalabraSa);
	numeroPalabraSv = entrenamientoValores(parsedUri$query, entrenamientoSv ,numeroPalabraSv);

	print "---------------------------------------------------------------------";
	print numeroPalabraSs;
	print entrenamientoSs;
	print "---------------";
	print numeroPalabraSp;
	print entrenamientoSp;
	print "---------------";
	print numeroPalabraSa;
	print entrenamientoSa;
	print "---------------";
	print numeroPalabraSv;
	print entrenamientoSv;
	print "---------------";

}

event http_reply(c: connection, version: string, code: count, reason: string)
	{

	local vectorR: table[count] of double;
	local probabilidad: double;
	local Ns: double;

	if ( c$http$method == "GET" && c$http$status_code == 200 ){
			local uri = c$http$uri;
			print "EL URI ES:";
			print uri;
			print "El host es:";
			print c$http$host;
			parseHost(c$http$host);
			parseUrl(c$http$uri);
			vectorR = evaluar(parsedUri,vectorProbabilidad);
			print vectorR;
			probabilidad = calcularProbabilidad(vectorR);
			print "Probability";
			print probabilidad;
			Ns = calcularIndiceAnormalidad(probabilidad);
			print "Ns";
			print Ns;
			verifiarAnomalia(theta, Ns);
			inicializarRecord(parsedUri);
		}
	
	}