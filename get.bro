#------------------------------------------------------------------------------#
#					 			 IMPORTES           						   #
#------------------------------------------------------------------------------#

module HTTP;
@load segmentacion

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

		numPalabras : double &default = 1.0;
        probability: double &default = 0.0;
};


# Define the record type that will contain the data to log.
type Info: record {

		word : string &log &default = "";
        probability: double &log &default = 0.0;
};

# Create an ID for our new stream
redef enum Log::ID += { LOG };

#------------------------------------------------------------------------------#

global BSsx: table[string] of Probability = table();
global BSpx: table[string] of Probability = table();
global BSax: table[string] of Probability = table();
global BSvx: table[string] of Probability = table();
global A: 	 table[string] of Rows = table();

global vectorProbabilidad: vector of table[string] of Probability = { BSsx , BSpx, BSvx , BSax };

#------------------------------------------------------------------------------#

# Variables utilizadas en el modulo de entrenamiento.

# Variables que almacenan el numero total de palabras en el vocabulario.
global numeroPalabraSs : double = 0.0;
global numeroPalabraSp : double = 0.0;
global numeroPalabraSv : double = 0.0;
global numeroPalabraSa : double = 0.0;

# Tablas que almacenan el vocabulario de cada uno de los estados del automata
global entrenamientoSs: table[string] of Entrenamiento = table();
global entrenamientoSp: table[string] of Entrenamiento = table();
global entrenamientoSa: table[string] of Entrenamiento = table();
global entrenamientoSv: table[string] of Entrenamiento = table();

#------------------------------------------------------------------------------#

# Variables para experimentar
global epsilon : double = 0.0001;
global probA : int = 0;
global theta: double = 5;


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

function evaluar(uriParsed: Segmentacion::uriSegmentado, pVector: vector of table[string] of Probability): table[count] of double {

	local host : double;
	local path : double;
	local valores : double;
	local atributos : double;

	host = evaluarHostPath(Segmentacion::parsedUri$host,pVector[0]);
	path = evaluarHostPath(Segmentacion::parsedUri$path,pVector[1]);
	valores = evaluarValores(Segmentacion::parsedUri$query,pVector[2]);
	atributos = evaluarAtributos(Segmentacion::parsedUri$query,pVector[3]);

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

function entrenamientoPathHost(wordList: table [count] of string, vocabulario: table[string] of Entrenamiento,numPalabras: double): double{

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

function entrenamientoAtributos(wordList: table [string] of string, vocabulario: table[string] of Entrenamiento, numPalabras: double): double{

	
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

function entrenamientoValores(wordList: table [string] of string, vocabulario: table[string] of Entrenamiento, numPalabras: double): double {
	
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

function evaluarProbabilidad(vocabulario: table[string] of Entrenamiento, numPalabras: double){

	for (i in vocabulario){

		# Se calcula la probabilidad de la palabra.
		vocabulario[i]$probability = (vocabulario[i]$numPalabras)/(numPalabras);
	} 
}

#------------------------------------------------------------------------------#

function escribirArchivo(vocabulario: table[string] of Entrenamiento,nombreArchivo: string) {

	# Se crea el archivo.
	Log::create_stream(LOG, [$columns=Info, $path=nombreArchivo]);

	# Se incializa el registro que se utilizara para escribir sobre el 
	# archivo.
	local rec: Info;
	rec = Info();

	# Se itera sobre las palabras del vocabulario para guardarlas en el log.
	for (palabra in vocabulario){

		rec$word = palabra;
		rec$probability = vocabulario[palabra]$probability;

		# Se escribe en el archivo
		Log::write(LOG, rec);
	}

}

#------------------------------------------------------------------------------#
#							 EVENTO PRINCIPAL                                  #
#------------------------------------------------------------------------------#

event bro_init(){

	print "Inicio";
	# Se extraen de un archivo de texto los vectores de probabilidad B
	#Input::add_table([$source="BssPrueba.log", $name="BssPrueba.log",
	#                      $idx=Word, $val=Probability, $destination=BSsx]);

	#Input::add_table([$source="BspPrueba.log", $name="BspPrueba.log",
	#                      $idx=Word, $val=Probability, $destination=BSpx]);

	#Input::add_table([$source="BsaPrueba.log", $name="BsaPrueba.log",
	#                      $idx=Word, $val=Probability, $destination=BSax]);

	#Input::add_table([$source="BsvPrueba.log", $name="BsvPrueba.log",
	#                      $idx=Word, $val=Probability, $destination=BSvx]);

	#Input::add_table([$source="A", $name="A",
    #                  $idx=Column, $val=Rows, $destination=A]);

	Segmentacion::parseHost("http://www.hola.com");
	Segmentacion::parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");
	#print Segmentacion::parsedUri;

}

event Input::end_of_data(name: string, source: string) {

	#parseHost("http://www.hola.com");
	#parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");
	#numeroPalabraSs = entrenamientoPathHost(Segmentacion::parsedUri$host, entrenamientoSs ,numeroPalabraSs);
	#numeroPalabraSp = entrenamientoPathHost(Segmentacion::parsedUri$path, entrenamientoSp ,numeroPalabraSp);
	#numeroPalabraSa = entrenamientoAtributos(Segmentacion::parsedUri$query, entrenamientoSa ,numeroPalabraSa);
	#numeroPalabraSv = entrenamientoValores(Segmentacion::parsedUri$query, entrenamientoSv ,numeroPalabraSv);


	#evaluarProbabilidad(entrenamientoSs ,numeroPalabraSs);
	#evaluarProbabilidad(entrenamientoSp ,numeroPalabraSp);
	#evaluarProbabilidad(entrenamientoSa ,numeroPalabraSa);
	#evaluarProbabilidad(entrenamientoSv ,numeroPalabraSv);

	#escribirArchivo(entrenamientoSs,"BssPrueba");
	#escribirArchivo(entrenamientoSp,"BspPrueba");
	#escribirArchivo(entrenamientoSa,"BsaPrueba");
	#escribirArchivo(entrenamientoSv,"BsvPrueba");



	#print BSsx;
	#print BSpx;
	#print BSax;
	#print BSvx;


	#print numeroPalabraSs;
	#print entrenamientoSs;
	#print "---------------";
	#print numeroPalabraSp;
	#print entrenamientoSp;
	#print "---------------";
	#print numeroPalabraSa;
	#print entrenamientoSa;
	#print "---------------";
	#print numeroPalabraSv;
	#print entrenamientoSv;
	#print "---------------##------";


}

#event http_reply(c: connection, version: string, code: count, reason: string)
#	{

#	local vectorR: table[count] of double;
#	local probabilidad: double;
#	local Ns: double;

#	if ( c$http$method == "GET" && c$http$status_code == 200 ){
#			local uri = c$http$uri;
#			print "EL URI ES:";
#			print uri;
#			print "El host es:";
#			print c$http$host;
#			parseHost(c$http$host);
#			parseUrl(c$http$uri);
#			vectorR = evaluar(parsedUri,vectorProbabilidad);
#			print vectorR;
#			probabilidad = calcularProbabilidad(vectorR);
#			print "Probability";
#			print probabilidad;
#			Ns = calcularIndiceAnormalidad(probabilidad);
#			print "Ns";
#			print Ns;
#			verifiarAnomalia(theta, Ns);
#			inicializarRecord(parsedUri);
#		}
	
#	}

event bro_done(){

	print "ESTOY LISTO";
	print Segmentacion::parsedUri;
	Segmentacion::inicializarRecord(Segmentacion::parsedUri);
	print Segmentacion::parsedUri;
}