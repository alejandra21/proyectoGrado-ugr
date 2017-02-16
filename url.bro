function parseAuthorityPath(url:string){

	print url;
}

function parseQueryFragment(url:string){

	print url;
}

function parseUrl(url: string) {

	local test_pattern = /(http(s)?:\/\/)?(([a-z]+[a-z0-9\-]*[.])?([a-z0-9]+[a-z0-9\-]*[.])+[a-z]{2,3}|localhost)(\/[a-z0-9_-]+[a-z0-9_.-]*)*/;
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

		parseAuthorityPath(results[3]);
	}

}

event bro_init(){

    local test_string = "https://www.bro.org/documentation/index.html/#ref";
    parseUrl(test_string);

}