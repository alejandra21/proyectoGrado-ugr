#
# Universidad de Granada
# Departamento de Teoría de la Señal, Telemática y Comunicaciones.
#
# Archivo : entrenamiento.bro
#
# Autor :
#       Alejandra Cordero 
#  

module Entrenamiento;

#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

@load segmentacion

#------------------------------------------------------------------------------#
#                                 REGISTROS                                    #
#------------------------------------------------------------------------------#

# Registro que almacenara las palabras durante el entrenamiento.
type Entrenamiento: record {

        numPalabras : double &default = 1.0;
        probability: double &default = 0.0;
};


# Registro que contendra los datos del LOG del modelo.
type Info: record {

        state: string &log &default = "";
        word : string &log &default = "";
        probability: double &log &default = 0.0;
};

# Se crea el ID del Log.
redef enum Log::ID += { LOG };


# Nombre de las variables que almacenan el numero total de palabras en el 
# vocabulario.
global numeroPalabraSs : string = "numeroPalabraSs";
global numeroPalabraSp : string = "numeroPalabraSp";
global numeroPalabraSv : string = "numeroPalabraSv";
global numeroPalabraSa : string = "numeroPalabraSa";

#------------------------------------------------------------------------------#
#                               EXPORTACIONES                                  #
#------------------------------------------------------------------------------#

export{


    #--------------------------------------------------------------------------#
    #                         REGISTROS PARA LOS VECTORES B
    #--------------------------------------------------------------------------#

    type Word: record {
            state: string;
            word: string;
    };

    type Probability: record {
            probability: double;
    };

    #--------------------------------------------------------------------------#
    #                      VARIABLES Y FUNCIONES GLOBALES
    #--------------------------------------------------------------------------#
    global entrenar: function(uriParsed: Segmentacion::uriSegmentado);
    global escribirArchivo: function(vocabulario: table[count] of table[string] of Entrenamiento);
    global escribirArchivoOnline: function(vocabulario: table[string,string] of Probability);
    global entrenarOnline: function(uriParsed: Segmentacion::uriSegmentado);



    # Tablas que almacenan el vocabulario de cada uno de los estados del automata
    global entrenamientoSs: table[string] of Entrenamiento = table();
    global entrenamientoSp: table[string] of Entrenamiento = table();
    global entrenamientoSa: table[string] of Entrenamiento = table();
    global entrenamientoSv: table[string] of Entrenamiento = table();
    
    # Tabla que contiene las tablas de entrenamiento de cada uno de los 
    # estados del automata.
    global tablaEntrenamieto : table[count] of table[string] of Entrenamiento = {[1] = entrenamientoSs, 
                                                      [2] = entrenamientoSp,
                                                      [3] = entrenamientoSa,
                                                      [4] = entrenamientoSv };

    # Tabla que contiene los datos de un modelo (esta variable sera utilizada
    # solo en el entrenamiento Online)
    global Btable: table[string,string] of Probability = table();


    # Tabla que contiene el numero total de palabras que contiene cada uno 
    # de los estados del automata.
    global numPalabrasTable : table[string] of double = {
                        [numeroPalabraSs] = 0.0,
                        [numeroPalabraSp] = 0.0,
                        [numeroPalabraSv] = 0.0,
                        [numeroPalabraSa] = 0.0 };

}

#------------------------------------------------------------------------------#
#                   FUNCIONES PARA EL ENTRENAMIENTO OFFLINE                    #
#------------------------------------------------------------------------------#

function evaluarProbabilidad(vocabulario: table[string] of Entrenamiento, 
                             numPalabras: double) {

    # Descripción de la función: Esta funcion, dada una tabla  que contiene una 
    #                            lista de palabras y el numero de apariciones que 
    #                            han tenido las mismas, calcula la probabilidad
    #                            de aparicion de cada una de las palabras.
    #
    # Variables de entrada:
    #    * vocabulario : Tabla que contiene un listado de palabras y el numero
    #                    de apaiciones de las mismas.
    #    * numPalabras : Suma del numero de apariciones de todas las palabras de
    #                    la tabla.
    #
    # Variables de salida:
    #    * Ninguna.

    for (i in vocabulario){

        # Se calcula la probabilidad de la palabra.
        vocabulario[i]$probability = (vocabulario[i]$numPalabras)/(numPalabras);
    } 
}

#------------------------------------------------------------------------------#

function entrenamientoPathHost(wordList: table [count] of string, 
                                vocabulario: table[string] of Entrenamiento,
                                numPalabras: double): double {

    # Descripción de la función: Esta funcion itera sobre la tabla de palabras
    #                            "wordList" y verifica si las palabras estan 
    #                             dentro de la tabla "vocabulario". Si la 
    #                             palabra esta dentro de la misma, se le sumara
    #                             uno al numero de aparicion de dicha palabra. 
    #                             Si por el contrario, la palabra no esta en la
    #                             tabla de vocabulario, entonces la misma sera 
    #                             añadida al vocabulario.
    #
    # Variables de entrada:
    #
    #    * wordList    : Lista de palabras.
    #    * vocabulario : Tabla que contiene una lista de palabras y una lista de
    #                    numeros que corresponde al numero de apariciones de 
    #                    las mismas.
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    #
    # Variables de salida:
    #
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".

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

    # Se calcula la probabilidad de aparicion de cada una de las palabras de la
    # tabla "vocabulario".
    evaluarProbabilidad(vocabulario, numPalabras);

    return numPalabras;
}

#------------------------------------------------------------------------------#

function entrenamientoAtributos(wordList: table [string] of string, 
                                vocabulario: table[string] of Entrenamiento, 
                                numPalabras: double): double{

    # Descripción de la función: Esta funcion itera sobre la tabla de palabras
    #                            "wordList" y verifica si las palabras estan 
    #                             dentro de la tabla "vocabulario". Si la 
    #                             palabra esta dentro de la misma, se le sumara
    #                             uno al numero de aparicion de dicha palabra. 
    #                             Si por el contrario, la palabra no esta en la
    #                             tabla de vocabulario, entonces la misma sera 
    #                             añadida al vocabulario.
    #
    # Variables de entrada:
    #
    #    * wordList    : Lista de palabras.
    #    * vocabulario : Tabla que contiene una lista de palabras y una lista de
    #                    numeros que corresponde al numero de apariciones de 
    #                    las mismas.
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    #
    # Variables de salida:
    #
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    

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


    # Se calcula la probabilidad de aparicion de cada una de las palabras de la
    # tabla "vocabulario".
    evaluarProbabilidad(vocabulario, numPalabras);

    return numPalabras;
    
}

#------------------------------------------------------------------------------#

function entrenamientoValores(wordList: table [string] of string, 
                              vocabulario: table[string] of Entrenamiento, 
                              numPalabras: double): double {
    
    # Descripción de la función: Esta funcion itera sobre las claves de la tabla
    #                            "wordList" y verifica si las palabras estan 
    #                             dentro de la tabla "vocabulario". Si la 
    #                             palabra esta dentro de la misma, se le sumara
    #                             uno al numero de aparicion de dicha palabra. 
    #                             Si por el contrario, la palabra no esta en la
    #                             tabla de vocabulario, entonces la misma sera 
    #                             añadida al vocabulario.
    #
    # Variables de entrada:
    #
    #    * wordList    : Lista de palabras.
    #    * vocabulario : Tabla que contiene una lista de palabras y una lista de
    #                    numeros que corresponde al numero de apariciones de 
    #                    las mismas.
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    #
    # Variables de salida:
    #
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".


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


    # Se calcula la probabilidad de aparicion de cada una de las palabras de la
    # tabla "vocabulario".
    evaluarProbabilidad(vocabulario, numPalabras);

    return numPalabras;
    
}

#------------------------------------------------------------------------------#


function escribirArchivo(vocabulario: table[count] of table[string] of Entrenamiento) {

    # Descripción de la función: Esta funcion se encarga de escribir en un log
    #                            la informacion almacenada en la tabla
    #                            "vocabulario".
    #
    # Variables de entrada:
    #
    #    * vocabulario : Tabla que almacena varias tablas que contienen las 
    #                    palabras onservadas durante el entrenamiento y la 
    #                    probabilidad de aparicion de las mismas.
    #                       
    #
    # Variables de salida:
    #    * Ninguna.


    local tablaEstados: table[count] of string = { [1] = "Bss", [2] = "Bsp",
                                                    [3] = "Bsa", [4] = "Bsv"};


    # Se crea el archivo.
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

    # Se escribe en el modelo el numero total de palabras que hay en cada estado.
    rec$word = "numTotal";

    for (word in numPalabrasTable){

        rec$state = word;
        rec$probability = numPalabrasTable[word];

        # Se escribe en el archivo
        Log::write(LOG, rec);

    }


}

#------------------------------------------------------------------------------#

function entrenar(uriParsed: Segmentacion::uriSegmentado){

    # Descripción de la función: Se encarga de llamar a todas las funciones
    #                            correspondientes para realizar el 
    #                            entrenamiento.
    #
    # Variables de entrada:
    #    * uriParsed : Estructura que contiene el URI segmentado.
    #
    # Variables de salida:
    #    * Ninguna.

    numPalabrasTable[numeroPalabraSs] = entrenamientoPathHost(uriParsed$host, 
                                        entrenamientoSs,numPalabrasTable[numeroPalabraSs]);

    numPalabrasTable[numeroPalabraSp] = entrenamientoPathHost(uriParsed$path, 
                                        entrenamientoSp,numPalabrasTable[numeroPalabraSp]);

    numPalabrasTable[numeroPalabraSa] = entrenamientoAtributos(uriParsed$query, 
                                        entrenamientoSa,numPalabrasTable[numeroPalabraSa]);

    numPalabrasTable[numeroPalabraSv] = entrenamientoValores(uriParsed$query, 
                                        entrenamientoSv,numPalabrasTable[numeroPalabraSv]);

}

#------------------------------------------------------------------------------#
#                   FUNCIONES PARA EL ENTRENAMIENTO ONLINE                     #
#------------------------------------------------------------------------------#

function escribirArchivoOnline(vocabulario: table[string,string] of Probability) {

    # Descripción de la función: Esta funcion se encarga de escribir en un log
    #                            la informacion almacenada en la tabla
    #                            "vocabulario".
    #
    # Variables de entrada:
    #
    #    * vocabulario : Tabla que almacena varias tablas que contienen las 
    #                    palabras onservadas durante el entrenamiento y la 
    #                    probabilidad de aparicion de las mismas.
    #                       
    #
    # Variables de salida:
    #    * Ninguna.

    # Se crea el archivo.
    local nombreArchivo = "modeloBro";
    Log::create_stream(LOG, [$columns=Info, $path=nombreArchivo]);


    # Se incializa el registro que se utilizara para escribir sobre el 
    # archivo.
    local rec: Info;
    rec = Info();


    # Se lee el numero total de palabras que existe por cada estado.
    for (i in numPalabrasTable){

        Btable[i,"numTotal"]$probability = numPalabrasTable[i];
    }


    # Se itera sobre las palabras del vocabulario para guardarlas en el log.
    for ([estado,palabra] in vocabulario){

        rec$word = palabra;
        rec$probability = vocabulario[estado,palabra]$probability;
        rec$state = estado;

        # Se escribe en el archivo
        Log::write(LOG, rec);
        
    }

}

#------------------------------------------------------------------------------#

function entrenamientoPathHostOnline(wordList: table [count] of string, 
                                vocabulario: table[string,string] of Probability,
                                numPalabras: double, state: string): double {

    # Descripción de la función: Esta funcion itera sobre la tabla de palabras
    #                            "wordList" y verifica si las palabras estan 
    #                             dentro de la tabla "vocabulario". Si la 
    #                             palabra esta dentro de la misma, se le sumara
    #                             uno al numero de aparicion de dicha palabra. 
    #                             Si por el contrario, la palabra no esta en la
    #                             tabla de vocabulario, entonces la misma sera 
    #                             añadida al vocabulario.
    #
    # Variables de entrada:
    #
    #    * wordList    : Lista de palabras.
    #    * vocabulario : Tabla que contiene una lista de palabras y una lista de
    #                    numeros que corresponde al numero de apariciones de 
    #                    las mismas.
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    #
    #    * state       : Estado del automata.
    #
    # Variables de salida:
    #
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".

    local x : double;
    local probabilidad: double;

    for (i in wordList){

        if ([state,wordList[i]] in vocabulario){

            # Se calcula el numero de palabras que existe en el vocabulario.
            x =  numPalabras*vocabulario[state,wordList[i]]$probability;

            # Se suma una unidad al numero de palabras total.
            numPalabras = numPalabras + 1;

            # Se calcula y se almacena la probabilidad de la palabra.
            vocabulario[state,wordList[i]]$probability = (x + 1)/(numPalabras);


        }
        else{

            # Se cuenta el numero de palabras que hay en el arreglo wordList
            numPalabras = numPalabras + 1;

            # Se suma una unidad al numero de palabras total.
            probabilidad = 1 / (numPalabras);
            vocabulario[state,wordList[i]] = Probability($probability=probabilidad);

        }
    
    
    }

    return numPalabras;
}

#------------------------------------------------------------------------------#

function entrenamientoAtributosOnline(wordList: table [string] of string, 
                                vocabulario: table[string,string] of Probability, 
                                numPalabras: double, state: string): double{

    # Descripción de la función: Esta funcion itera sobre la tabla de palabras
    #                            "wordList" y verifica si las palabras estan 
    #                             dentro de la tabla "vocabulario". Si la 
    #                             palabra esta dentro de la misma, se le sumara
    #                             uno al numero de aparicion de dicha palabra. 
    #                             Si por el contrario, la palabra no esta en la
    #                             tabla de vocabulario, entonces la misma sera 
    #                             añadida al vocabulario.
    #
    # Variables de entrada:
    #
    #    * wordList    : Lista de palabras.
    #    * vocabulario : Tabla que contiene una lista de palabras y una lista de
    #                    numeros que corresponde al numero de apariciones de 
    #                    las mismas.
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    #
    #    * state       : Estado del automata.
    #
    # Variables de salida:
    #
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    

    local x : double;
    local probabilidad: double;

    for (i in wordList){

        if ([state,wordList[i]] in vocabulario){

            # Se calcula el numero de palabras que existe en el vocabulario.
            x =  numPalabras*vocabulario[state,wordList[i]]$probability;

            # Se suma una unidad al numero de palabras total.
            numPalabras = numPalabras + 1;

            # Se calcula y se almacena la probabilidad de la palabra.
            vocabulario[state,wordList[i]]$probability = (x + 1)/(numPalabras);

        }
        else{

            # Se suma una unidad al numero de palabras total.
            numPalabras = numPalabras + 1;

            # Se calcula y se almacena la probabilidad de la palabra.
            probabilidad = 1 / (numPalabras);
            vocabulario[state,wordList[i]] = Probability($probability=probabilidad);

        }
    }

    return numPalabras;
    
}

#------------------------------------------------------------------------------#

function entrenamientoValoresOnline(wordList: table [string] of string, 
                              vocabulario: table[string,string] of Probability, 
                              numPalabras: double, state: string): double {
    
    # Descripción de la función: Esta funcion itera sobre las claves de la tabla
    #                            "wordList" y verifica si las palabras estan 
    #                             dentro de la tabla "vocabulario". Si la 
    #                             palabra esta dentro de la misma, se le sumara
    #                             uno al numero de aparicion de dicha palabra. 
    #                             Si por el contrario, la palabra no esta en la
    #                             tabla de vocabulario, entonces la misma sera 
    #                             añadida al vocabulario.
    #
    # Variables de entrada:
    #
    #    * wordList    : Lista de palabras.
    #    * vocabulario : Tabla que contiene una lista de palabras y una lista de
    #                    numeros que corresponde al numero de apariciones de 
    #                    las mismas.
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".
    #
    #    * state       : Estado del automata.
    #
    # Variables de salida:
    #
    #    * numPalabras : Numero total de apariciones de todas las palabras de la
    #                    tabla "vocabulario".


    local x : double;
    local probabilidad: double;

    for ( [word] in wordList){

        if ( [state,word] in vocabulario){

            # Se calcula el numero de palabras que existe en el vocabulario.
            x =  numPalabras*vocabulario[state,word]$probability;

            # Se suma una unidad al numero de palabras total.
            numPalabras = numPalabras + 1;
            vocabulario[state,word]$probability = (x + 1)/(numPalabras);

        }
    
        else{

            # Se calcula el numero de palabras que existe en el vocabulario.
            numPalabras = numPalabras + 1;

            # Se suma una unidad al numero de palabras total.
            probabilidad = 1 / (numPalabras);
            vocabulario[state,word] = Probability($probability=probabilidad);

        }
        
    }

    return numPalabras;
    
}

#------------------------------------------------------------------------------#

function entrenarOnline(uriParsed: Segmentacion::uriSegmentado){

    # Descripción de la función: Se encarga de llamar a todas las funciones
    #                            correspondientes para realizar el 
    #                            entrenamiento.
    #
    # Variables de entrada:
    #    * uriParsed : Estructura que contiene el URI segmentado.
    #
    # Variables de salida:
    #    * Ninguna.


    numPalabrasTable[numeroPalabraSs] = entrenamientoPathHostOnline(uriParsed$host,
                                        Btable,numPalabrasTable[numeroPalabraSs],
                                        "Bss");

    numPalabrasTable[numeroPalabraSp] = entrenamientoPathHostOnline(uriParsed$path,
                                        Btable,numPalabrasTable[numeroPalabraSp],
                                        "Bsp");

    numPalabrasTable[numeroPalabraSa] = entrenamientoAtributosOnline(uriParsed$query,
                                        Btable,numPalabrasTable[numeroPalabraSa],
                                        "Bsa");

    numPalabrasTable[numeroPalabraSv] = entrenamientoValoresOnline(uriParsed$query,
                                        Btable,numPalabrasTable[numeroPalabraSv],
                                        "Bsv");

}

#------------------------------------------------------------------------------#


