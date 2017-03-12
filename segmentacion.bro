module Segmentacion;

#------------------------------------------------------------------------------#
#					 		EXPORTACIONES           						   #
#------------------------------------------------------------------------------#

export {

	type uriSegmentado: record {

	    host: table [count] of string;
	    path: table [count] of string;
	    query: table[string] of string &default = table();
	    fragment: string &default = "";

	};

    global inicializarRecord: function(datos: uriSegmentado);
    global parseHost: function(url: string);
    global parseUrl: function(url: string);
    global parsedUri: uriSegmentado;

}

#------------------------------------------------------------------------------#
#					 FUNCIONES PARA SEGMENTAR EL URI 						   #
#------------------------------------------------------------------------------#

function inicializarRecord(datos: uriSegmentado){

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

	}

	else if (|results|==2){

		queryUri = decompose_uri(results[2]);
		parsedUri$query = queryUri$params;

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

