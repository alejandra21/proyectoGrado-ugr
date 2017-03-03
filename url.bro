# Segmentador de URI.
# Este programa toma un URI, lo segmenta y lo almacena en un tipo de datos
# record


type MyRecordType: record {

    host: string;
    path: table [count] of string;
    query: table[string] of string &optional;
    fragment: string &optional;

};

global parsedUri: MyRecordType;


function inicializarRecord(datos: MyRecordType){

	datos$host = "";
	datos$path = table();
	datos$query = table();;
	datos$fragment = "";

}


function parseAuthorityPath(url:string){

	# Se comprueba que exista un host con su ruta.
	if (url == ""){

		print "ERROR";

	}
	else{

		local test_pattern = /\//;

		local results = split(url, test_pattern);

	
		if (|results| > 2){

			parsedUri$host = results[1];
			parsedUri$path = results;

			print parsedUri$host;
			print parsedUri$path;

		}
		else if (|results| == 1){

			parsedUri$host = results[1];
			print parsedUri$host;

		}
		else {

			print "ERROR!";
			exit(0);

		}
	}
}

function parseFragment(url:string){

	local test_pattern = /\/#.*/;
	local results = split_all(url, test_pattern);

	if (|results| == 2){

		if (results[1] == ""){

			parsedUri$fragment = results[2];

		}
		else{

			print "ERROR fragment!";
			exit(0);	

		}

	}
	else{
		print "ERROR fragment!";
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

		print "ERROR";
		exit(0);
	}

}

function parseUrl(url: string) {

	# Se parsea el host y la ruta
	local test_pattern = /(([a-z]+[a-z0-9\-]*[.])?([a-z0-9]+[a-z0-9\-]*[.])+[a-z]{2,3}|localhost)(\/[a-z0-9_-]+[a-z0-9_.-]*)*/;
	local results = split_all(url, test_pattern);

	# El primer fragmento debe estar vacio
	if ( results[1] != "" ){
		print "ERROR";
		return;
		
	}

	#El segundo fragmento contendra el host y la ruta correspondiente.
	if (results[2] != ""){
		parseAuthorityPath(results[2]);		
	}

	else {
		print "ERROR";
		return;
	}

	# El tercer fragmento (opcional) contendrá los datos para realizar
	# el query y el fragment.
	if (results[3] != ""){
		parseQueryFragment(results[3]);
	}

}

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

		print "ERROR!";
		exit(0);
	}


}

event bro_init(){

	# Se inicializa el registro que guardara los segmentos del URI parseado.
	inicializarRecord(parsedUri);
    local test_string = "https://www.bro.org/documentation/index.html/?pepe=maria&&ana=juana/#holis";
    local results = returnUri(test_string);
    parseUrl(results);

}
