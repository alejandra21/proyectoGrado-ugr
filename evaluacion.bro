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
            state: string;
            word: string;
    };

    type Probability: record {
            probability: double;
    };

    #--------------------------------------------------------------------------#
    #                         REGISTRO PARA LA MATRIZ A
    #--------------------------------------------------------------------------#

    type Valor: record {

            valor: double;
    };

    #--------------------------------------------------------------------------#

    global evaluar: function(uriParsed: Segmentacion::uriSegmentado, 
                            Bvector: table[string,string] of Probability,
                            vectorPoov: table[string] of Valor): table[count] of double;

    global calcularProbabilidad: function(vectorB: table[count] of double) : double;

    global calcularIndiceAnormalidad: function(epsilon0: double, N: double, 
                                                sumaLogaritmos: double) : double;

    global verifiarAnomalia: function(theta: double,
                                      indicesAnormalidad: table[count] of double);

}

global infinito: double = 100000000;
redef enum Notice::Type += { Umbral_Anomalia };
global alarmaEmitida: bool = F;

#------------------------------------------------------------------------------#
#                     FUNCIONES PARA EL MODULO DE EVALUACION                   #
#------------------------------------------------------------------------------#

function evaluarValores(wordList:table[string] of string, 
                        pVector: table[string,string] of Probability, 
                        epsilon : double, estado:string): table[count] of double{

    # Descripción de la función: Se itera sobre las palabras contenidas en la 
    #                           tabla wordList para calcular tanto la suma de sus
    #                           probabilidades de aparicion como la suma del los
    #                           logaritmos de la probabilidad de aparicion.
    #
    # Variables de entrada:
    #    * wordList : Tabla que contiene una lista de palabras. 
    #    * pVector  : Tabla que contiene una lista de palabras y sus probabilidades
    #                 de aparicion.
    #    * epsilon  : Valor correspondiente al Poov.
    #    * estado   : Estado del automata que se esta evaluando
    #
    # Variables de salida:
    #    *  tablaEvaluacion: Tabla que contiene el resultado de la suma de las 
    #                        probabilidades de aparicion de las palabras como la 
    #                        suma del los logaritmos de la probabilidad de aparicion.
 

    local results : double;
    results = 0.0;

    local sumLogaritmos : double;
    sumLogaritmos = 0.0;

    local tablaEvaluacion: table[count] of double = table();

    for ( i in wordList){

        if ([estado,wordList[i]] in pVector){

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[estado,wordList[i]]$probability;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(pVector[estado,wordList[i]]$probability);

        }
        else{

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(epsilon);

        }
    }


    if (|wordList|!= 0){

        results = results /|wordList|;
    }

    tablaEvaluacion[1] = results;
    tablaEvaluacion[2] = sumLogaritmos;

    # Se retorna el valor de epsilon sub cero.
    return tablaEvaluacion;

}

#------------------------------------------------------------------------------#

function evaluarAtributos(wordList:table[string] of string,
                          pVector: table[string,string] of Probability, 
                          epsilon : double, estado:string): table[count] of double{

    # Descripción de la función: Se itera sobre las palabras contenidas en la 
    #                           tabla wordList para calcular tanto la suma de sus
    #                           probabilidades de aparicion como la suma del los
    #                           logaritmos de la probabilidad de aparicion.
    #
    # Variables de entrada:
    #    * wordList : Tabla que contiene una lista de palabras. 
    #    * pVector  : Tabla que contiene una lista de palabras y sus probabilidades
    #                 de aparicion.
    #    * epsilon  : Valor correspondiente al Poov.
    #    * estado   : Estado del automata que se esta evaluando
    #
    # Variables de salida:
    #    *  tablaEvaluacion: Tabla que contiene el resultado de la suma de las 
    #                        probabilidades de aparicion de las palabras como la 
    #                        suma del los logaritmos de la probabilidad de aparicion.

    local results : double;
    results = 0.0;

    local sumLogaritmos : double;
    sumLogaritmos = 0.0;

    local tablaEvaluacion: table[count] of double = table();


    for ( [word] in wordList ){

        if ([estado,word] in pVector){

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[estado,word]$probability;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(pVector[estado,word]$probability);

        }
        else{

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(epsilon);

        }
    }

    if (|wordList|!= 0){

        results = results /|wordList|;
    }

    tablaEvaluacion[1] = results;
    tablaEvaluacion[2] = sumLogaritmos;

    # Se retorna el valor de epsilon sub cero.
    return tablaEvaluacion;

}

#------------------------------------------------------------------------------#

function evaluarHostPath(wordList:table [count] of string, 
                        pVector: table[string,string] of Probability, 
                        epsilon : double, estado:string): table[count] of double{

    # Descripción de la función: Se itera sobre las palabras contenidas en la 
    #                           tabla wordList para calcular tanto la suma de sus
    #                           probabilidades de aparicion como la suma del los
    #                           logaritmos de la probabilidad de aparicion.
    #
    # Variables de entrada:
    #    * wordList : Tabla que contiene una lista de palabras. 
    #    * pVector  : Tabla que contiene una lista de palabras y sus probabilidades
    #                 de aparicion.
    #    * epsilon  : Valor correspondiente al Poov.
    #    * estado   : Estado del automata que se esta evaluando
    #
    # Variables de salida:
    #    *  tablaEvaluacion: Tabla que contiene el resultado de la suma de las 
    #                        probabilidades de aparicion de las palabras como la 
    #                        suma del los logaritmos de la probabilidad de aparicion.

    local results : double;
    results = 0.0;

    local sumLogaritmos : double;
    sumLogaritmos = 0.0;

    local tablaEvaluacion: table[count] of double = table();

    for ( i in wordList){

        if ([estado,wordList[i]] in pVector){

            # Se suma la probabilidad de la palabra que se encuentra en el
            # diccionario.
            results =  results + pVector[estado,wordList[i]]$probability;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(pVector[estado,wordList[i]]$probability);

        }
        else{

            # Se entra en este caso si la palabra no estaba en el vocabulario.
            results = results + epsilon;
            sumLogaritmos = sumLogaritmos + Math::logaritmo(epsilon);
            
        }

    }
    
    if (|wordList|!= 0){

        results = results /|wordList|;
    }

    tablaEvaluacion[1] = results;
    tablaEvaluacion[2] = sumLogaritmos;

    # Se retorna el valor de epsilon sub cero.
    return tablaEvaluacion;
}

#------------------------------------------------------------------------------#

function calcularIndiceAnormalidad(epsilon0: double, N: double, 
                                    sumaLogaritmos: double) : double {

    # Descripción de la función: Funcion que calcula el indice de anormalidad
    #                            del URI.
    #
    # Variables de entrada:
    #   * epsilon0 :.
    #   * N : .
    #   * sumaLogaritmos:
    #
    # Variables de salida:
    #   * indiceAnormalidad: Indice de anormalidad del URI.

    local indiceAnormalidad : double;
    indiceAnormalidad = - (N * Math::logaritmo(epsilon0)) - sumaLogaritmos;

    return indiceAnormalidad;

}

#------------------------------------------------------------------------------#

function evaluar(uriParsed: Segmentacion::uriSegmentado, 
                Bvector: table[string,string] of Probability, 
                vectorPoov: table[string] of Valor): table[count] of double{

    # Descripción de la función: Se llaman todas las funciones necesarias
    #                            para evaluar el indice de anormalidad de un
    #                            URI.
    #
    # Variables de entrada:
    #    * uriParsed  : Estructura que almacena el URI segmentado.
    #    * Bvector    : Vector B (vector que almacena el modelo).
    #    * vectorPoov : Vector que almacena los diferentes Poov.
    #
    # Variables de salida:
    #    * tablaIndiceAnormalidad: Tabla que almacena los indices de anormalidad
    #                              de cada uno de los estados del automata. 


    local tablaIndiceAnormalidad : table[count] of double;

    local host : table[count] of double;
    local path : table[count] of double;
    local valores : table[count] of double;
    local atributos : table[count] of double;

    local Nss : double = 0.0;
    local Nsp : double = 0.0;
    local Nsv : double = 0.0;
    local Nsa : double = 0.0;

    local Bss = "Bss";
    local Bsp = "Bsp";
    local Bsa = "Bsa";
    local Bsv = "Bsv";

    # Como se evaluara un nuevo URI el flag de alarmas emitida se inicializara
    # en False.
    alarmaEmitida = F;

    # Si el URI posee una sintaxis correcta se procede a calcular los indices
    # de anormalidad.
    if (uriParsed$uriCorrecto){

        host = evaluarHostPath(uriParsed$host,Bvector,vectorPoov["Poov1"]$valor,Bss);
        path = evaluarHostPath(uriParsed$path,Bvector,vectorPoov["Poov2"]$valor,Bsp);

        # Se calculan los indices de anormalidad del host y del path
        Nss = calcularIndiceAnormalidad(host[1],|uriParsed$host|,host[2]);
        Nsp = calcularIndiceAnormalidad(path[1],|uriParsed$path|,path[2]);


        # Si el URI posee query se calcula el indice de anormalidad tanto de
        # los valores como los atributos de los mismos.
        if (|uriParsed$query| != 0){

            valores = evaluarValores(uriParsed$query,Bvector,vectorPoov["Poov3"]$valor,Bsv);
            atributos = evaluarAtributos(uriParsed$query,Bvector,vectorPoov["Poov4"]$valor,Bsa);

            # Se calculan los indices de anormalidad del los valores y atributos
            # del query.
            Nsv = calcularIndiceAnormalidad(valores[1],|uriParsed$query|,valores[2]);
            Nsa = calcularIndiceAnormalidad(atributos[1],|uriParsed$query|,atributos[2]);

        }
            
        tablaIndiceAnormalidad[1] = Nss ;
        tablaIndiceAnormalidad[2] = Nsp ;
        tablaIndiceAnormalidad[3] = Nsv ;
        tablaIndiceAnormalidad[4] = Nsa ;

    }
    # Si el URI no posee una sintaxis correcta, entonces,  
    # se asignara como indice de anormalidad un valor muy alto.
    else{

        tablaIndiceAnormalidad[1] = infinito ;
        tablaIndiceAnormalidad[2] = infinito ;
        tablaIndiceAnormalidad[3] = infinito ;
        tablaIndiceAnormalidad[4] = infinito ;

    }


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

function verifiarAnomalia(theta: double,indicesAnormalidad: table[count] of double){

    # Descripción de la función: Funcion que verifica si el indice de anormalidad
    #                            de un URI es anomalo o no.
    #
    # Variables de entrada:
    #    * theta : Umbral de normalidad.
    #    * indicesAnormalidad : Tabla que contiene indices de anormalidad.
    #
    # Variables de salida:
    #    * Ninguna.

    for (i in indicesAnormalidad){

        # Si el indice de anormalidad es mayor o igual que theta, y no se han
        # emitido alarmas anteriores para el uri que se esta evaluando, entonces
        # se disparara una alerta.
        if (indicesAnormalidad[i] >= theta && alarmaEmitida == F){
            print "EMITIR ALARMA";
            NOTICE([$note=Umbral_Anomalia,
            $msg = "Se ha sobrepasado el umbral de anomalia",
            $sub = fmt("URI = %s", "www")]);
            alarmaEmitida = T;
        }
        else {
            print "NO HACER NADA";
        }
  
    }

}

#------------------------------------------------------------------------------#
