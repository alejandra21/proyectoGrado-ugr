function parseAuthorityPath(url:string){

	local test_pattern = /\//;
	local results = split(url, test_pattern);

	for (i in results) {
	    print results[i];
	}

}

function parseQueryFragment(url:string){

	print url;
	local test_pattern = /(\?[^"'\r\n><#]*)?/;
	local results = split_all(url, test_pattern);
	for (i in results) {
	    print results[i];
	}

}

function parseUrl(url: string) {

	local test_pattern = /(([a-z]+[a-z0-9\-]*[.])?([a-z0-9]+[a-z0-9\-]*[.])+[a-z]{2,3}|localhost)(\/[a-z0-9_-]+[a-z0-9_.-]*)*/;
	local results = split_all(url, test_pattern);

	if ( results[1] != "" ){
		print "ERROR";
		return;
		
	}

	if (results[2] != ""){
		parseAuthorityPath(results[2]);		
	}

	else {
		print "ERROR";
		return;
	}

	if (results[3] != ""){
		parseQueryFragment(results[3]);
	}

}

function returnUri(uri:string){

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

    local test_string = "https://www.bro.org/documentation/index.html/?pepe=maria/#ref";
    local results = returnUri(test_string);
    parseUrl(results);


}