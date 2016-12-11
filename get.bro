module HTTP;

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( c$http$method == "GET" && c$http$status_code == 200 ){
			print fmt(c$http$uri);
			Demo::rot13(c$http$uri);
		}
	}