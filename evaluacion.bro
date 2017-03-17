module Evaluacion;

#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

@load segmentacion

#------------------------------------------------------------------------------#
#                             EXPORTACIONES                                    #
#------------------------------------------------------------------------------#


export {

    #--------------------------------------------------------------------------#
    #                         REGISTROS PARA LOS VECTORES B
    #--------------------------------------------------------------------------#

    type Word: record {
            word: string;
    };

    type Probability: record {
            probability: double;
    };

    #--------------------------------------------------------------------------#
    #                         REGISTRO PARA LA MATRIZ A
    #--------------------------------------------------------------------------#

    type Column: record {
            column: string;
    };

    type Rows: record {
            Ssi: int;
            Spi: int;
            Sai: int;
            Svi: int;
    };

    #--------------------------------------------------------------------------#

    global evaluar: function(uriParsed: Segmentacion::uriSegmentado, 
                            pVector: vector of table[string] of Probability,
                            epsilon: double): table[count] of double;

    global calcularProbabilidad: function(vectorB: table[count] of double) : double;

    global calcularIndiceAnormalidad: function(epsilon0: double, N: double, 
                                                sumaLogaritmos: double) : double;

    global verifiarAnomalia: function(theta: double, indiceAnormalidad: double);

}

#------------------------------------------------------------------------------#
#                     FUNCIONES PARA EL MODULO DE EVALUACION                   #
#------------------------------------------------------------------------------#

function evaluarValores(wordList:table[string] of string, 
                        pVector: table[string] of Probability, 
                        epsilon : double): table[count] of double{

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    local results : double;
    results = 0.0;

    local sumLogaritmos : double;
    sumLogaritmos = 0.0;

    local tablaEvaluacion: table[count] of double = table();

    for ( i in wordList){

        #print wordList[i];

        if (wordList[i] in pVector){

            #print "LA PALABRA ESTA";

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[wordList[i]]$probability;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(pVector[wordList[i]]$probability);

        }
        else{

            #print "NO ESTA LA PALABRA";
            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(epsilon);

        }
    }


    results = results /|wordList|;

    tablaEvaluacion[1] = results;
    tablaEvaluacion[2] = sumLogaritmos;

    # Se retorna el valor de epsilon sub cero.
    return tablaEvaluacion;

}

#------------------------------------------------------------------------------#

function evaluarAtributos(wordList:table[string] of string,
                          pVector: table[string] of Probability, 
                          epsilon : double): table[count] of double{

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    local results : double;
    results = 0.0;

    local sumLogaritmos : double;
    sumLogaritmos = 0.0;

    local tablaEvaluacion: table[count] of double = table();


    for ( [word] in wordList ){

        #print "WORD";
        #print word;

        if (word in pVector){

            #print "LA PALABRA ESTA";

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[word]$probability;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(pVector[word]$probability);

        }
        else{

            #print "NO ESTA LA PALABRA";

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(epsilon);

        }
    }

    results = results /|wordList|;

    tablaEvaluacion[1] = results;
    tablaEvaluacion[2] = sumLogaritmos;

    # Se retorna el valor de epsilon sub cero.
    return tablaEvaluacion;

}

#------------------------------------------------------------------------------#

function evaluarHostPath(wordList:table [count] of string, 
                        pVector: table[string] of Probability, 
                        epsilon : double): table[count] of double{

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    local results : double;
    results = 0.0;

    local sumLogaritmos : double;
    sumLogaritmos = 0.0;

    local tablaEvaluacion: table[count] of double = table();

    for ( i in wordList){

        #print wordList[i];

        if (wordList[i] in pVector){

            #print "LA PALABRA ESTA";

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[wordList[i]]$probability;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(pVector[wordList[i]]$probability);

        }
        else{

            #print "NO ESTA LA PALABRA";

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(epsilon);
            
        }

    }
    
    results = results /|wordList|;

    tablaEvaluacion[1] = results;
    tablaEvaluacion[2] = sumLogaritmos;

    # Se retorna el valor de epsilon sub cero.
    return tablaEvaluacion;
}

#------------------------------------------------------------------------------#

function calcularIndiceAnormalidad(epsilon0: double, N: double, 
                                    sumaLogaritmos: double) : double {

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #   * self : Corresponde a la instancia del objeto Lexer.
    #   * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #   * Tokens : Lista de tokens correctos
    #   * Errores : Lista de tokens con los errores lexicograficos encontrados

    local indiceAnormalidad : double;
    indiceAnormalidad = - (N * Math::logaritmo(epsilon0)) - sumaLogaritmos;

    return indiceAnormalidad;

}

#------------------------------------------------------------------------------#

function evaluar(uriParsed: Segmentacion::uriSegmentado, 
                pVector: vector of table[string] of Probability, 
                epsilon: double): table[count] of double{

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    local tablaIndiceAnormalidad : table[count] of double;

    local host : table[count] of double;
    local path : table[count] of double;
    local valores : table[count] of double;
    local atributos : table[count] of double;

    local Nss : double;
    local Nsp : double;
    local Nsv : double;
    local Nsa : double;

    host = evaluarHostPath(uriParsed$host,pVector[0],epsilon);
    path = evaluarHostPath(uriParsed$path,pVector[1],epsilon);
    valores = evaluarValores(uriParsed$query,pVector[2],epsilon);
    atributos = evaluarAtributos(uriParsed$query,pVector[3],epsilon);

    print "INDICE DE ANORMALIDAD";
    Nss = calcularIndiceAnormalidad(host[1],|uriParsed$host|,host[2]);
    Nsp = calcularIndiceAnormalidad(path[1],|uriParsed$path|,path[2]);
    Nsv = calcularIndiceAnormalidad(valores[1],|uriParsed$query|,valores[2]);
    Nsa = calcularIndiceAnormalidad(atributos[1],|uriParsed$query|,atributos[2]);

    tablaIndiceAnormalidad[1] = Nss ;
    tablaIndiceAnormalidad[2] = Nsp ;
    tablaIndiceAnormalidad[3] = Nsv ;
    tablaIndiceAnormalidad[4] = Nsa ;

    return tablaIndiceAnormalidad;
}

#------------------------------------------------------------------------------#

function calcularProbabilidad(vectorB: table[count] of double) : double {

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    local resultVectorB : double;
    resultVectorB = 0.0;

    # Se calcula la sumatoria de las probabilidades que contiene el vectorB
    for (i in vectorB){

        resultVectorB = resultVectorB + Math::logaritmo(vectorB[i]);
    }

    return resultVectorB;

}

#------------------------------------------------------------------------------#

function verifiarAnomalia(theta: double, indiceAnormalidad: double){

    # Descripción de la función: Clase Lexer.
    #
    # Variables de entrada:
    #    * self : Corresponde a la instancia del objeto Lexer.
    #    * data : Corresponde al input del Lexer.
    #
    # Variables de salida:
    #    * Tokens : Lista de tokens correctos
    #    * Errores : Lista de tokens con los errores lexicograficos encontrados

    if (indiceAnormalidad >= theta){
        print "EMITIR ALARMA";
    }
    else {
        print "TODO ESTA NORMAL";
    }
}

#------------------------------------------------------------------------------#
