#
# Universidad de Granada
# Departamento de Teoría de la Señal, Telemática y Comunicaciones.
#
# Archivo : mainEntrenamientoOnline.bro
#
# Autor :
#       Alejandra Cordero 
#  

module Segmentacion;

#------------------------------------------------------------------------------#
#                             EXPORTACIONES                                    #
#------------------------------------------------------------------------------#

export {

    # Registro que almacenara el URI segmentado
    type uriSegmentado: record {

        uri : string &default = "";    # Almacena el URI completo.
        host: table [count] of string; # Almacena el host segmentado
        path: table [count] of string; # Almacena el path segmentado
        query: table[string] of string &default = table(); # Almacena el query
                                                           # segmentado.
        fragment: string &default = "";# Almacena el fragment segmentado.
        numEstados: int &default = 0;  # Indica el numero de estado del automata
                                       # fueron visitados para reconocer el URI
        uriCorrecto: bool &default = T;# Booleano que indica si el URI esta 
                                       # sintacticamente bien construido o no.

    };

    # Funcion para inicializar el record que almacena el URI segmentado.
    global inicializarRecord: function(datos: uriSegmentado);

    # Funcion para parsear y segmentar el host.
    global parseHost: function(url: string);

    # Funcion para parsear y segmentar el path, el query y el fragment del URI.
    global parseUrl: function(url: string);
    global parsedUri: uriSegmentado;

}


#------------------------------------------------------------------------------#
#                             TABLA HTML ENCODING                              #
#------------------------------------------------------------------------------#

global encoding : table[string] of string = {    ["+"]    =    "%20" , 
                                                [" "]    =    "%20" ,
                                                ["\x0"]  = "%00",
                                                ["\x00"] = "%00",
                                                ["%21"] =    "!"     ,
                                                ["%22"] =    "”"    ,                                        
                                                ["%23"] =    "#"    ,
                                                ["%24"] =    "$"    ,
                                                ["%25"] =    "%"    ,
                                                ["%F3"]    =    "\xc3\xb3"    ,
                                                ["%3B"]    =    ";"    ,
                                                ["%B9"]    =    "\xc2\xb9"    ,
                                                ["%63"]    =    "c"    ,
                                                ["%73"]    =    "s"    ,
                                                ["%35"]    =    "5"    ,
                                                ["%86"]    =    "\xe2\x80\xa0"    ,
                                                ["%B3"]    =    "\xc2\xb3"    ,
                                                ["%4C"]    =    "L"    ,
                                                ["%AA"]    =    "\xc2\xaa"    ,
                                                ["%69"]    =    "i"    ,
                                                ["%59"]    =    "Y"    ,
                                                ["%5D"]    =    "]"    ,
                                                ["%2D"]    =    "\xe2\x80\x93"    ,
                                                ["%46"]    =    "F"    ,
                                                ["%38"]    =    "8"    ,
                                                ["%39"]    =    "9"    ,
                                                ["%E6"]    =    "\xc3\xa6"    ,
                                                ["%2F"]    =    "/"    ,
                                                ["%AB"]    =    "\xc2\xab"    ,
                                                ["%57"]    =    "W"    ,
                                                ["%3F"]    =    "?"    ,
                                                ["%83"]    =    "\xc6\x92"    ,
                                                ["%C4"]    =    "\xc3\x84"    ,
                                                ["%DD"]    =    "\xc3\x9d"    ,
                                                ["%F8"]    =    "\xc3\xb8"    ,
                                                ["%FB"]    =    "\xc3\xbb"    ,
                                                ["%D8"]    =    "\xc3\x98"    ,
                                                ["%F4"]    =    "\xc3\xb4"    ,
                                                ["%B5"]    =    "\xc2\xb5"    ,
                                                ["%DC"]    =    "\xc3\x9c"    ,
                                                ["%DE"]    =    "\xc3\x9e"    ,
                                                ["%2B"]    =    "+"    ,
                                                ["%A6"]    =    "|"    ,
                                                ["%26"]    =    "&"    ,
                                                ["%9C"]    =    "\xc5\x93"    ,
                                                ["%BF"]    =    "\xc2\xbf"    ,
                                                ["%E9"]    =    "\xc3\xa9"    ,
                                                ["%4E"]    =    "N"    ,
                                                ["%47"]    =    "G"    ,
                                                ["%C5"]    =    "\xc3\x85"    ,
                                                ["%C6"]    =    "\xc3\x86"    ,
                                                ["%E8"]    =    "\xc3\xa8"    ,
                                                ["%D4"]    =    "\xc3\x94"    ,
                                                ["%FA"]    =    "\xc3\xba"    ,
                                                ["%28"]    =    "("    ,
                                                ["%A2"]    =    "\xc2\xa2"    ,
                                                ["%7B"]    =    "{"    ,
                                                ["%6D"]    =    "m"    ,
                                                ["%53"]    =    "S"    ,
                                                ["%C0"]    =    "\xc3\x80"    ,
                                                ["%C1"]    =    "\xc3\x81"    ,
                                                ["%CB"]    =    "\xc3\x8b"    ,
                                                ["%62"]    =    "b"    ,
                                                ["%74"]    =    "t"    ,
                                                ["%BE"]    =    "\xc2\xbe"    ,
                                                ["%E4"]    =    "\xc3\xa4"    ,
                                                ["%92"]    =    "\xe2\x80\x99"    ,
                                                ["%FD"]    =    "\xc3\xbd"    ,
                                                ["%DF"]    =    "\xc3\x9f"    ,
                                                ["%EA"]    =    "\xc3\xaa"    ,
                                                ["%ED"]    =    "\xc3\xad"    ,
                                                ["%F1"]    =    "\xc3\xb1"    ,
                                                ["%54"]    =    "T"    ,
                                                ["%49"]    =    "I"    ,
                                                ["%68"]    =    "h"    ,
                                                ["%AE"]    =    "\xc2\xae"    ,
                                                ["%D1"]    =    "\xc3\x91"    ,
                                                ["%95"]    =    "\xe2\x80\xa2"    ,
                                                ["%61"]    =    "a"    ,
                                                ["%65"]    =    "e"    ,
                                                ["%F7"]    =    "\xc3\xb7"    ,
                                                ["%48"]    =    "H"    ,
                                                ["%FC"]    =    "\xc3\xbc"    ,
                                                ["%9F"]    =    "\xc5\xb8"    ,
                                                ["%B1"]    =    "\xc2\xb1"    ,
                                                ["%F2"]    =    "\xc3\xb2"    ,
                                                ["%71"]    =    "q"    ,
                                                ["%7D"]    =    "}"    ,
                                                ["%5E"]    =    "^"    ,
                                                ["%A5"]    =    "\xc2\xa5"    ,
                                                ["%D6"]    =    "\xc3\x96"    ,
                                                ["%9B"]    =    "\xe2\x80\xba"    ,
                                                ["%8B"]    =    "\xe2\x80\xb9"    ,
                                                ["%6B"]    =    "k"    ,
                                                ["%36"]    =    "6"    ,
                                                ["%58"]    =    "X"    ,
                                                ["%B2"]    =    "\xc2\xb2"    ,
                                                ["%51"]    =    "Q"    ,
                                                ["%6F"]    =    "o"    ,
                                                ["%33"]    =    "3"    ,
                                                ["%AC"]    =    "\xc2\xac"    ,
                                                ["%C8"]    =    "\xc3\x88"    ,
                                                ["%B7"]    =    "\xc2\xb7"    ,
                                                ["%BA"]    =    "\xc2\xba"    ,
                                                ["%CF"]    =    "\xc3\x8f"    ,
                                                ["%75"]    =    "u"    ,
                                                ["%EB"]    =    "\xc3\xab"    ,
                                                ["%4A"]    =    "J"    ,
                                                ["%30"]    =    "0"    ,
                                                ["%94"]    =    "\xe2\x80\x9d"    ,
                                                ["%F5"]    =    "\xc3\xb5"    ,
                                                ["%82"]    =    "\xe2\x80\x9a"    ,
                                                ["%CD"]    =    "\xc3\x8d"    ,
                                                ["%EC"]    =    "\xc3\xac"    ,
                                                ["%2A"]    =    "*"    ,
                                                ["%77"]    =    "w"    ,
                                                ["%2E"]    =    "."    ,
                                                ["%6E"]    =    "n"    ,
                                                ["%B6"]    =    "\xc2\xb6"    ,
                                                ["%F6"]    =    "\xc3\xb6"    ,
                                                ["%4F"]    =    "O"    ,
                                                ["%67"]    =    "g"    ,
                                                ["%78"]    =    "x"    ,
                                                ["%4B"]    =    "K"    ,
                                                ["%3D"]    =    "="    ,
                                                ["%64"]    =    "d"    ,
                                                ["%D0"]    =    "\xc3\x90"    ,
                                                ["%E2"]    =    "\xc3\xa2"    ,
                                                ["%45"]    =    "E"    ,
                                                ["%A8"]    =    "\xc2\xa8"    ,
                                                ["%E3"]    =    "\xc3\xa3"    ,
                                                ["%E7"]    =    "\xc3\xa7"    ,
                                                ["%50"]    =    "P"    ,
                                                ["%CC"]    =    "\xc3\x8c"    ,
                                                ["%4D"]    =    "M"    ,
                                                ["%87"]    =    "\xe2\x80\xa1"    ,
                                                ["%7A"]    =    "z"    ,
                                                ["%7E"]    =    "~"    ,
                                                ["%85"]    =    "\xe2\x80\xa6"    ,
                                                ["%DB"]    =    "\xc3\x9b"    ,
                                                ["%C9"]    =    "\xc3\x89"    ,
                                                ["%5B"]    =    "["    ,
                                                ["%CE"]    =    "\xc3\x8e"    ,
                                                ["%99"]    =    "\xe2\x84\xa2"    ,
                                                ["%3C"]    =    "<"    ,
                                                ["%7C"]    =    "|"    ,
                                                ["%DA"]    =    "\xc3\x9a"    ,
                                                ["%88"]    =    "\xcb\x86"    ,
                                                ["%5A"]    =    "Z"    ,
                                                ["%66"]    =    "f"    ,
                                                ["%34"]    =    "4"    ,
                                                ["%BD"]    =    "\xc2\xbd"    ,
                                                ["%EE"]    =    "\xc3\xae"    ,
                                                ["%79"]    =    "y"    ,
                                                ["%EF"]    =    "\xc3\xaf"    ,
                                                ["%8C"]    =    "\xc5\x92"    ,
                                                ["%27"]    =    "\xe2\x80\x98"    ,
                                                ["%97"]    =    "\xe2\x80\x94"    ,
                                                ["%91"]    =    "\xe2\x80\x98"    ,
                                                ["%89"]    =    "\xe2\x80\xb0"    ,
                                                ["%9E"]    =    "\xc5\xbe"    ,
                                                ["%A1"]    =    "\xc2\xa1"    ,
                                                ["%AD"]    =    "\xc2\xaf"    ,
                                                ["%6C"]    =    "l"    ,
                                                ["%B0"]    =    "\xc2\xb0"    ,
                                                ["%2C"]    =    ","    ,
                                                ["%42"]    =    "B"    ,
                                                ["%84"]    =    "\xe2\x80\x9e"    ,
                                                ["%70"]    =    "p"    ,
                                                ["%44"]    =    "D"    ,
                                                ["%41"]    =    "A"    ,
                                                ["%BC"]    =    "\xc2\xbc"    ,
                                                ["%F0"]    =    "\xc3\xb0"    ,
                                                ["%76"]    =    "v"    ,
                                                ["%29"]    =    ")"    ,
                                                ["%C7"]    =    "\xc3\x87"    ,
                                                ["%D5"]    =    "\xc3\x95"    ,
                                                ["%6A"]    =    "j"    ,
                                                ["%72"]    =    "r"    ,
                                                ["%43"]    =    "C"    ,
                                                ["%55"]    =    "U"    ,
                                                ["%3E"]    =    ">"    ,
                                                ["%FE"]    =    "\xc3\xbe"    ,
                                                ["%8E"]    =    "\xc5\xbd"    ,
                                                ["%8A"]    =    "\xc5\xa0"    ,
                                                ["%37"]    =    "7"    ,
                                                ["%AF"]    =    "\xc2\xaf"    ,
                                                ["%D2"]    =    "\xc3\x92"    ,
                                                ["%E1"]    =    "\xc3\xa1"    ,
                                                ["%F9"]    =    "\xc3\xb9"    ,
                                                ["%96"]    =    "\xe2\x80\x93"    ,
                                                ["%C3"]    =    "\xc3\x83"    ,
                                                ["%32"]    =    "2"    ,
                                                ["%80"]    =    "\xe2\x82\xac"    ,
                                                ["%56"]    =    "V"    ,
                                                ["%A7"]    =    "\xc2\xa7"    ,
                                                ["%E0"]    =    "\xc3\xa0"    ,
                                                ["%60"]    =    "`"    ,
                                                ["%31"]    =    "1"    ,
                                                ["%A9"]    =    "\xc2\xa9"    ,
                                                ["%B4"]    =    "\xc2\xb4"    ,
                                                ["%D3"]    =    "\xc3\x93"    ,
                                                ["%D9"]    =    "\xc3\x99"    ,
                                                ["%A3"]    =    "\xc2\xa3"    ,
                                                ["%93"]    =    "\xe2\x80\x9c"    ,
                                                ["%B8"]    =    "\xc2\xb8"    ,
                                                ["%40"]    =    "@"    ,
                                                ["%98"]    =    "\xcb\x9c"    ,
                                                ["%BB"]    =    "\xc2\xbb"    ,
                                                ["%E5"]    =    "\xc3\xa5"    ,
                                                ["%FF"]    =    "\xc3\xbf"    ,
                                                ["%9A"]    =    "\xc5\xa1"    ,
                                                ["%52"]    =    "R"    ,

};

#------------------------------------------------------------------------------#
#                     FUNCIONES PARA SEGMENTAR EL URI                          #
#------------------------------------------------------------------------------#

function inicializarRecord(datos: uriSegmentado){

    # Descripción de la función: Inicializa todos los campos de un registro de
    #                            tipo "uriSegmentado".
    #
    # Variables de entrada:
    #    * datos : Registro a ser inicializado.
    #
    # Variables de salida:
    #    * Ninguna.


    datos$uri = "";
    datos$host = table();
    datos$path = table();
    datos$query = table();
    datos$fragment = "";
    datos$numEstados = 0;
    datos$uriCorrecto = T;

}

#------------------------------------------------------------------------------#

function normalizarUri(url: string): string {

    # Descripción de la función: Dado un URI esta funcion sustituye 
    #                            ciertos caracteres por sus correspondiente
    #                            codificacion UTF-8.
    #
    # Variables de entrada:
    #    * url : URI a normalizar.
    #
    # Variables de salida:
    #    * urlFinal : URI normalizado.

    local urlFinal: string = url;


    # La complejidad es de O(n) siendo n el numero de elementos que hay en la 
    # tabla encoding.
    for (word in encoding){

        if (word in urlFinal){
            urlFinal = subst_string(urlFinal,word,encoding[word]);
        }
    
    }

    return urlFinal;
}

#------------------------------------------------------------------------------#

function parsePath(url:string){

    # Descripción de la función: Esta funcion, dada la ruta correspondiente a
    #                            un URI, segmenta y almacena en una tabla cada 
    #                            una de las palabras separadas por el 
    #                            separador: "/".
    #
    # Variables de entrada:
    #    * url : Ruta de un URI que sera segmentada.
    #
    # Variables de salida:
    #    * Ninguna.


    # Se comprueba que exista una ruta.
    if (url == "/" || url == ""){

      # Si la ruta es igual a "" o "/" no se segmenta el contenido de la variable
      # "url".
      local path: table [count] of string = {[1] = "/"};

      # Se almacena el resultado en el registro que guardara todo el URI 
      #segmentado.
      parsedUri$path = path;

    }
    else{

      # Se segmenta el contenido de la variable URL haciendo uso del separador
      # "/".
      local test_pattern = /\//;
      local results = split(url, test_pattern);

      # Se eliminan los elementos vacios que resultan en la tabla resultante.
      for (i in results){

            if (results[i] == ""){
                  delete results[i];
            }
      }

      # Se almacena el resultado en el registro que guardara todo el URI 
      # segmentado.
      parsedUri$path = results;

    }

    # Se aumenta una unidad en el numero de estados ya que simbolicamente 
    # se ha llegado al estado Sp.
    parsedUri$numEstados = parsedUri$numEstados + 1;


}

#------------------------------------------------------------------------------#

function parseFragment(url:string){

    # Descripción de la función: Esta funcion, dada una palabra verifica si 
    #                            la misma es el fragmen de un URI o no.
    #
    # Variables de entrada:
    #    * url :  Palabra a ser analizada.
    #
    # Variables de salida:
    #    * Ninguna.

    if (url == ""){

        return;

    }
    else{
        
        # Se segmenta el contenido de la variable URL haciendo uso del separador
        # "/".
        local test_pattern = /#.*/;
        local patternHashtag = /#/;
        local results = split_all(url, test_pattern);

        # Si el contenido de "url" corresponde al framgent de un URI, entonces
        # el resultado de la funcion "split_all" deberia dar como resultado una
        # tabla de longitud igual a 3, donde el fragment este almacenado en 
        # la segunda entrada de la misma.
        if (|results| == 3){

            if (results[1] == "" && results[3] == ""){

                # Se almacena el fragment en el registro que almacena todo
                # el URI segmentado.
                parsedUri$fragment = sub(results[2],patternHashtag,"");;

            }

            # Si existen elementos en la primera o tercera entrada de la tabla 
            # resultante, entonces se puede decir que el URI esta 
            # sintacticamente mal construido.
            else{

                print "ERROR fragment 1!";
                parsedUri$uriCorrecto = F;
                return;    

            }

        }

        # Si la longitud de la tabla resultante no es igual a 3, entonces
        # se puede decir que el URI esta sintacticamente mal construido.
        else{

            print "ERROR fragment 2!";
            parsedUri$uriCorrecto = F;
            return;       
        }
    }

}

#------------------------------------------------------------------------------#
function setQuery(url: string){

      # Descripción de la función: Esta funcion, descompone el string 
      #                            correspondiente al query string de un URI.
      #
      # Variables de entrada:
      #    * url :  Query string.
      #
      # Variables de salida:
      #    * Ninguna.


      local queryUri : URI;
      local emptyTable: table[string] of string;

      emptyTable = table();

      # Se segmenta el query string.
      queryUri = decompose_uri(url);

      if (|queryUri$params| > 0 ){

           # query$params almacena una tabla cuyas claves son los valores
           # del query string y el contenido asociado a esas claves son los
           # astributos.
           parsedUri$query = queryUri$params;

           # Se aumenta una unidad en el numero de estados ya que simbolicamente 
           # se ha llegado al estado Sv y Sa.
           parsedUri$numEstados = parsedUri$numEstados + 2;

      }

      # Si la longitud de la tabla que almacena el query string segmentado
      # es igual a 0, entonces se dira que el URI esta incorrecto sintacticamente.
      else{
            parsedUri$uriCorrecto = F; 
      }

}

#------------------------------------------------------------------------------#

function parseQueryFragment(url:string){

    # Descripción de la función: Funcion que parsea y segmenta el query y
    #                            fragment de un URI.
    #
    # Variables de entrada:
    #    * uri : Palabra a ser parseada y segmentada.
    #
    # Variables de salida:
    #    * Ninguna.

    if (url == "" || !parsedUri$uriCorrecto){

      return;

    }
    else {

        # Expresion regular para parsear el query string.
        local test_pattern = /\?[^#&]+((=[^#&]*)?(&[^#&]+(=[^#&]*)?)*)?/;
        local results = split_all(url, test_pattern);

        if (|results|==3){

            # Se verifica la correctitud del query string.
            setQuery(results[2]);

            # Se verifica si el "fragment" hace match con la expresion regular
            # correspondiente.
            parseFragment(results[3]);

        }

        else if (|results|==2){

            # Se verifica la correctitud del query string.
            setQuery(results[2]);

        }
        else{

            # Caso en el que el URI no hace match con la expresion regular 
            # expuesta con anterioridad.
            print "ERROR QUERY FRAGMENT";
            parsedUri$uriCorrecto = F;
        }

    }

}

#------------------------------------------------------------------------------#

function fragmentHost(url: string){

    # Descripción de la función: Esta funcion, dada la host correspondiente a
    #                            un URI, segmenta y almacena en una tabla cada 
    #                            una de las palabras separadas por el 
    #                            separador: "." o ":".
    # Variables de entrada:
    #    * url : Host de un URI que sera segmentado.
    #
    # Variables de salida:
    #    * Ninguna.

    # Si no existe un host, entonces se dira que el URI esta sintacticamente mal
    # formado.
    if (url == ""){

        print "ERROR";
        parsedUri$uriCorrecto = F;
        return;

    }
    else{

        # Se segmenta el contenido de la variable URL haciendo uso del separador
        # "." y ":".
        local test_pattern = /\.|:/;
        local results = split(url, test_pattern);
        parsedUri$host = results;

        # Se aumenta una unidad en el numero de estados ya que simbolicamente 
        # se ha llegado al estado Ss.
        parsedUri$numEstados = parsedUri$numEstados + 1;

    }

}

#------------------------------------------------------------------------------#

function fragmentIp(ip: string){

    # Descripción de la función: Esta funcion, dada la host correspondiente a
    #                            un URI, segmenta y almacena en una tabla cada 
    #                            una de las palabras separadas por el 
    #                            separador: ":".
    # Variables de entrada:
    #    * url : Host de un URI que sera segmentado.
    #
    # Variables de salida:
    #    * Ninguna.

    if (ip == ""){

        print "ERROR";
        parsedUri$uriCorrecto = F;
        return;

    }
    else{

        # Se segmenta el contenido de la variable URL haciendo uso del separador
        # ":".
        local test_pattern = /:/;
        local results = split(ip, test_pattern);
        parsedUri$host = results;

        # Se aumenta una unidad en el numero de estados ya que simbolicamente 
        # se ha llegado al estado Ss.
        parsedUri$numEstados = parsedUri$numEstados + 1;

    }

}

#------------------------------------------------------------------------------#

function returnUri(uri:string):string{

    # Descripción de la función: Esta funcion, dado un URI 
    #                            retorna el mismo URI sin el squeme.
    #
    # Variables de entrada:
    #    * uri : URI de entrada.
    #
    # Variables de salida:
    #    * results[2]/results[1] : URI sin el squeme.


    # Se segmenta el contenido de la variable URL haciendo uso del separador
    # /(http(s)?:\/\/)?/.
    local test_pattern = /(http(s)?:\/\/)?/;
    local results = split(uri,test_pattern);

    # Caso en el que el URI posee scheme.
    if (|results| == 2){

        return results[2];

    }
    # Caso en el que el URI no posee scheme.
    else if (|results| == 1){

        return results[1];

    }
    # Caso en el que el URI esta mal formado sintacticamente.
    else{

      print "ERROR RETURN URI!";
      parsedUri$uriCorrecto = F;
      return "";

    }
    
}

#------------------------------------------------------------------------------#
function verificarCorrectitudIp(ip: table[count] of string){

    # Descripción de la función: Esta funcion parsea y segmenta una direccion ip.
    #
    # Variables de entrada:
    #    * ip : Tabla que contiende la posible direccion ip.
    #
    # Variables de salida:
    #    * Ninguna.

    # Se segmenta la dereccion IP.
    if (|ip| == 3 && ip[1] == "" && ip[3] == ""){

        fragmentIp(ip[2]);

    }
    # Caso en el que existe un error sintactico.
    else {
        print "ERROR EN HOST";
        parsedUri$uriCorrecto = F;
        return;
    }

}

#------------------------------------------------------------------------------#

function parseHost(url: string){

    # Descripción de la función: Funcion que parsea, segmenta y almacena en una
    #                            tabla el host de un URI.
    #
    # Variables de entrada:
    #    * url : Host a ser parseado y segmentado.
    #
    # Variables de salida:
    #    * Ninguna.


    if (url!= ""){

          # Se extrae el scheme.
          local urlResult = returnUri(url);

          # Se normaliza el formato del host.
          urlResult = normalizarUri(urlResult);

          # Se parsea el host
          local test_pattern = /(([a-z]+[a-z0-9\-]*[.])?([a-z0-9]+[a-z0-9\-]*[.])+[a-z]{2,3}|localhost)(:([0-9]{1,5}))?/;
          local ip_pattern = /((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:([0-9]{1,5}))?/;
          local results = split_all(urlResult, test_pattern);

          # Se verifica si el host esta bien construido
          if (results[1]=="" && ((|results| == 2)||(|results|==3 && results[3]=="") ) ){

              # Se procede a segmentar el host.
              fragmentHost(results[2]);

          }
          else if (|results| == 1){

              # Si el host no es un nombre de dominio se verifica si el mismo
              # corresponde a una direccion IP.
              results = split_all(urlResult, ip_pattern);
              verificarCorrectitudIp(results);

          }
          else {

            # Existe algun error de sintaxis en el URI.
            print "ERROR EN HOST";
            parsedUri$uriCorrecto = F;
            return;

          }

    }
    else{

      # Si no existe un host, entonces se dira que el URI esta mal construido
      # sintacticamente.
      parsedUri$uriCorrecto = F;
      return;
    }

}

#------------------------------------------------------------------------------#

function parseUrl(url: string) {

    # Descripción de la función: Funcion que parsea, segmenta y almacena en una
    #                            tabla el path, el query y el fragment de un URI.
    #
    # Variables de entrada:
    #    * url : URI a ser parseado y segmentado.
    #
    # Variables de salida:
    #    * Ninguna.

    if (url == "" || !parsedUri$uriCorrecto){

        return;

    }
    else{

        # Se normaliza el formato del URI.
        local urlResult: string;
        urlResult = normalizarUri(url);

        # Se parsea la ruta
        local test_pattern = /[^?#]*\/?/;
        local results = split_all(urlResult, test_pattern);

        # El primer fragmento debe estar vacio
        if ( results[1] != "" ){

            print "ERROR PARSE URI 1";
            parsedUri$uriCorrecto = F;
            return;

            
        }

        #El segundo fragmento contendra el host y la ruta correspondiente.
        if (results[2] != ""){

            parsePath(results[2]);        
        }
       # De no ser asi el URI sera considerara que el URI esta mal construido. 
        else {

            print "ERROR PARSE URI 2";
            parsedUri$uriCorrecto = F;
            return;
        }

        # El tercer fragmento (opcional) contendrá los datos para realizar
        # el query y el fragment.
        if (results[3] != ""){

            local query: string;
            query = cat_string_array_n(results,3,|results|);
            parseQueryFragment(query);

        }

        
    }

}

#------------------------------------------------------------------------------#

