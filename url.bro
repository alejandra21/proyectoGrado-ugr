function parseAuthorityPath(url:string){

	local test_pattern = /\//;
	local results = split(url, test_pattern);

	for (i in results2) {
	    print results2[i];
	}

}

function parseQueryFragment(url:string){

	print url;
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

event bro_init(){

    local test_string = "https://www.bro.org/documentation/index.html/#ref";
    local test_pattern = /(http(s)?:\/\/)?/;
    local results = split(test_string,test_pattern);
    if (|results| == 2){
    	parseUrl(results[2]);
    }
    else if (|results| == 1){
    	parseUrl(results[1]);
    }
    else{
    	print "ERROR!";
    }

}