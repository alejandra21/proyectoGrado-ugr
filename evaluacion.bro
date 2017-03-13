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

    global evaluar: function(uriParsed: Segmentacion::uriSegmentado, pVector: vector of table[string] of Probability, epsilon: double): table[count] of double;
    global calcularProbabilidad: function(vectorB: table[count] of double) : double;
    global calcularIndiceAnormalidad: function(probabilidad: double) : double;
    global verifiarAnomalia: function(theta: double, indiceAnormalidad: double);

}

#------------------------------------------------------------------------------#
#                     FUNCIONES PARA EL MODULO DE EVALUACION                   #
#------------------------------------------------------------------------------#

function evaluarValores(wordList:table[string] of string, pVector: table[string] of Probability, epsilon : double): double{

    local results : double;

    results = 0.0;

    for ( i in wordList){

        #print wordList[i];

        if (wordList[i] in pVector){

            #print "LA PALABRA ESTA";

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[wordList[i]]$probability;

        }
        else{

            #print "NO ESTA LA PALABRA";
            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;

        }
    }

    return results;

}

#------------------------------------------------------------------------------#

function evaluarAtributos(wordList:table[string] of string, pVector: table[string] of Probability, epsilon : double): double{

    local results : double;

    results = 0.0;

    for ( [word] in wordList ){

        #print "WORD";
        #print word;

        if (word in pVector){

            #print "LA PALABRA ESTA";

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[word]$probability;

        }
        else{

            #print "NO ESTA LA PALABRA";

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;

        }
    }

    return results;

}

#------------------------------------------------------------------------------#

function evaluarHostPath(wordList:table [count] of string, pVector: table[string] of Probability, epsilon : double): double{

    local results : double;
    results = 0.0;

    for ( i in wordList){

        print wordList[i];

        if (wordList[i] in pVector){

            print "LA PALABRA ESTA";

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[wordList[i]]$probability;

        }
        else{

            print "NO ESTA LA PALABRA";

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;

        }

    }
    
    return results;
}

#------------------------------------------------------------------------------#

function evaluar(uriParsed: Segmentacion::uriSegmentado, pVector: vector of table[string] of Probability, epsilon: double): table[count] of double {

    local host : double;
    local path : double;
    local valores : double;
    local atributos : double;

    host = evaluarHostPath(uriParsed$host,pVector[0],epsilon);
    path = evaluarHostPath(uriParsed$path,pVector[1],epsilon);
    valores = evaluarValores(uriParsed$query,pVector[2],epsilon);
    atributos = evaluarAtributos(uriParsed$query,pVector[3],epsilon);

    local results : table[count] of double = { [1] = host , 
                                               [2] = path, 
                                               [3] = valores, 
                                               [4] = atributos };

    if (path == 0.0 && valores == 0.0 && atributos == 0.0){

        # results = { host };
        delete results[2];
        delete results[3];
        delete results[4];
    
    }
    else if (valores == 0.0 && atributos == 0.0){

        # results = { host , path };
        delete results[3];
        delete results[4];

    }
    else if (path == 0.0 ){

        # results  = { host , valores , atributos };
        delete results[2];

    }

    return results;

}

#------------------------------------------------------------------------------#

function calcularProbabilidad(vectorB: table[count] of double) : double {

    local resultVectorB : double;
    resultVectorB = 0.0;

    # Se calcula la sumatoria de las probabilidades que contiene el vectorB
    for (i in vectorB){

        resultVectorB = resultVectorB + Math::logaritmo(vectorB[i]);
    }

    return resultVectorB;

}

#------------------------------------------------------------------------------#

function calcularIndiceAnormalidad(probabilidad: double) : double {

    local indiceAnormalidad : double;
    indiceAnormalidad = - (probabilidad);

    return indiceAnormalidad;

}

#------------------------------------------------------------------------------#

function verifiarAnomalia(theta: double, indiceAnormalidad: double){

    if (indiceAnormalidad >= theta){
        print "EMITIR ALARMA";
    }
    else {
        print "TODO ESTA NORMAL";
    }
}

#------------------------------------------------------------------------------#
