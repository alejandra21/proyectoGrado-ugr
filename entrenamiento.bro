module Entrenamiento;

#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

@load segmentacion

#------------------------------------------------------------------------------#
#                                 REGISTROS                                    #
#------------------------------------------------------------------------------#

type Entrenamiento: record {

        numPalabras : double &default = 1.0;
        probability: double &default = 0.0;
};


# Define the record type that will contain the data to log.
type Info: record {

        word : string &log &default = "";
        probability: double &log &default = 0.0;
        state: string &log &default = "";
};

# Create an ID for our new stream
redef enum Log::ID += { LOG };

#------------------------------------------------------------------------------#
#                               EXPORTACIONES                                  #
#------------------------------------------------------------------------------#

export{


    global entrenar: function(uriParsed: Segmentacion::uriSegmentado);
    global escribirArchivo: function(vocabulario: table[count] of table[string] of Entrenamiento);

    # Tablas que almacenan el vocabulario de cada uno de los estados del automata
    global entrenamientoSs: table[string] of Entrenamiento = table();
    global entrenamientoSp: table[string] of Entrenamiento = table();
    global entrenamientoSa: table[string] of Entrenamiento = table();
    global entrenamientoSv: table[string] of Entrenamiento = table();


    global tablaEntrenamieto : table[count] of table[string] of Entrenamiento = {[1] = entrenamientoSs, 
                                                      [2] = entrenamientoSp,
                                                      [3] = entrenamientoSa,
                                                      [4] = entrenamientoSv };


}


#------------------------------------------------------------------------------#

# Variables utilizadas en el modulo de entrenamiento.

# Variables que almacenan el numero total de palabras en el vocabulario.
global numeroPalabraSs : double = 0.0;
global numeroPalabraSp : double = 0.0;
global numeroPalabraSv : double = 0.0;
global numeroPalabraSa : double = 0.0;
global numeroUriProcesado : int = 0;


#------------------------------------------------------------------------------#

# Variables para experimentar
global epsilon : double = 0.0001;
global probA : int = 0;
global theta: double = 5;


#------------------------------------------------------------------------------#
#                        FUNCIONES PARA EL ENTRENAMIENTO                       #
#------------------------------------------------------------------------------#

function evaluarProbabilidad(vocabulario: table[string] of Entrenamiento, 
                             numPalabras: double) {

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    for (i in vocabulario){

        # Se calcula la probabilidad de la palabra.
        vocabulario[i]$probability = (vocabulario[i]$numPalabras)/(numPalabras);
    } 
}

#------------------------------------------------------------------------------#

function entrenamientoPathHost(wordList: table [count] of string, 
                                vocabulario: table[string] of Entrenamiento,
                                numPalabras: double): double {

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

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

    evaluarProbabilidad(vocabulario, numPalabras);

    return numPalabras;
}

#------------------------------------------------------------------------------#

function entrenamientoAtributos(wordList: table [string] of string, 
                                vocabulario: table[string] of Entrenamiento, 
                                numPalabras: double): double{

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados
    

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

    evaluarProbabilidad(vocabulario, numPalabras);

    return numPalabras;
    
}

#------------------------------------------------------------------------------#

function entrenamientoValores(wordList: table [string] of string, 
                              vocabulario: table[string] of Entrenamiento, 
                              numPalabras: double): double {
    
    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados


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

    evaluarProbabilidad(vocabulario, numPalabras);

    return numPalabras;
    
}

#------------------------------------------------------------------------------#


function escribirArchivo(vocabulario: table[count] of table[string] of Entrenamiento) {

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    # Se crea el archivo.

    local tablaEstados: table[count] of string = { [1] = "Bss", [2] = "Bsp",
                                                    [3] = "Bsa", [4] = "Bsv"};
    local nombreArchivo = "modeloBro";
    Log::create_stream(LOG, [$columns=Info, $path=nombreArchivo]);



    # Se incializa el registro que se utilizara para escribir sobre el 
    # archivo.
    local rec: Info;
    rec = Info();

    # Se itera sobre el vector de tablas que contienen la informacion obtenida
    # durante el entrenamiento.
    for (i in vocabulario){

        # Se itera sobre las palabras del vocabulario para guardarlas en el log.
        for (palabra in vocabulario[i]){

            rec$word = palabra;
            rec$probability = vocabulario[i][palabra]$probability;
            rec$state = tablaEstados[i];

            # Se escribe en el archivo
            Log::write(LOG, rec);
            
        }

    }

}

#------------------------------------------------------------------------------#

function entrenar(uriParsed: Segmentacion::uriSegmentado){

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados


    numeroPalabraSs = entrenamientoPathHost(uriParsed$host, entrenamientoSs ,
                                            numeroPalabraSs);
    numeroPalabraSp = entrenamientoPathHost(uriParsed$path, entrenamientoSp ,
                                            numeroPalabraSp);
    numeroPalabraSa = entrenamientoAtributos(uriParsed$query, entrenamientoSa ,
                                            numeroPalabraSa);
    numeroPalabraSv = entrenamientoValores(uriParsed$query, entrenamientoSv ,
                                            numeroPalabraSv);

}

#------------------------------------------------------------------------------#


