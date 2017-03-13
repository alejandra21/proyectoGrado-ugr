#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

module HTTP;
@load segmentacion
@load evaluacion
@load entrenamiento

#------------------------------------------------------------------------------#

global BSsx: table[string] of Evaluacion::Probability = table();
global BSpx: table[string] of Evaluacion::Probability = table();
global BSax: table[string] of Evaluacion::Probability = table();
global BSvx: table[string] of Evaluacion::Probability = table();
global A:      table[string] of Evaluacion::Rows = table();

global vectorProbabilidad: vector of table[string] of Evaluacion::Probability = { BSsx , BSpx, BSvx , BSax };

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio";
    # Se extraen de un archivo de texto los vectores de probabilidad B
    Input::add_table([$source="BssPrueba.log", $name="BssPrueba.log",
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, $destination=BSsx]);

    Input::add_table([$source="BspPrueba.log", $name="BspPrueba.log",
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, $destination=BSpx]);

    Input::add_table([$source="BsaPrueba.log", $name="BsaPrueba.log",
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, $destination=BSax]);

    Input::add_table([$source="BsvPrueba.log", $name="BsvPrueba.log",
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, $destination=BSvx]);

    Input::add_table([$source="A", $name="A",
                      $idx=Evaluacion::Column, $val=Evaluacion::Rows, $destination=A]);

    Segmentacion::parseHost("http://www.hola.com");
    Segmentacion::parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");
    Entrenamiento::entrenar(Segmentacion::parsedUri);
    print "---------------##------";
    print Entrenamiento::entrenamientoSs;
    print "---------------";
    print Entrenamiento::entrenamientoSp;
    print "---------------";
    print Entrenamiento::entrenamientoSa;
    print "---------------";
    print Entrenamiento::entrenamientoSv;
    print "---------------##------";

}

event Input::end_of_data(name: string, source: string) {

    #parseHost("http://www.hola.com");
    #parseUrl("/seniors/all_seniors/schs-paul/index.htm/?pepe=maria&juan=juana/#ref");
    #numeroPalabraSs = entrenamientoPathHost(Segmentacion::parsedUri$host, entrenamientoSs ,numeroPalabraSs);
    #numeroPalabraSp = entrenamientoPathHost(Segmentacion::parsedUri$path, entrenamientoSp ,numeroPalabraSp);
    #numeroPalabraSa = entrenamientoAtributos(Segmentacion::parsedUri$query, entrenamientoSa ,numeroPalabraSa);
    #numeroPalabraSv = entrenamientoValores(Segmentacion::parsedUri$query, entrenamientoSv ,numeroPalabraSv);


    #evaluarProbabilidad(entrenamientoSs ,numeroPalabraSs);
    #evaluarProbabilidad(entrenamientoSp ,numeroPalabraSp);
    #evaluarProbabilidad(entrenamientoSa ,numeroPalabraSa);
    #evaluarProbabilidad(entrenamientoSv ,numeroPalabraSv);

    #escribirArchivo(entrenamientoSs,"BssPrueba");
    #escribirArchivo(entrenamientoSp,"BspPrueba");
    #escribirArchivo(entrenamientoSa,"BsaPrueba");
    #escribirArchivo(entrenamientoSv,"BsvPrueba");



    #print BSsx;
    #print BSpx;
    #print BSax;
    #print BSvx;


    #print "---------------##------";
    #print numeroPalabraSs;
    #print entrenamientoSs;
    #print "---------------";
    #print numeroPalabraSp;
    #print entrenamientoSp;
    #print "---------------";
    #print numeroPalabraSa;
    #print entrenamientoSa;
    #print "---------------";
    #print numeroPalabraSv;
    #print entrenamientoSv;
    #print "---------------##------";


}

#event http_reply(c: connection, version: string, code: count, reason: string)
#    {

#    local vectorR: table[count] of double;
#    local probabilidad: double;
#    local Ns: double;

#    if ( c$http$method == "GET" && c$http$status_code == 200 ){
#            local uri = c$http$uri;
#            print "EL URI ES:";
#            print uri;
#            print "El host es:";
#            print c$http$host;
#            parseHost(c$http$host);
#            parseUrl(c$http$uri);
#            vectorR = evaluar(parsedUri,vectorProbabilidad);
#            print vectorR;
#            probabilidad = calcularProbabilidad(vectorR);
#            print "Probability";
#            print probabilidad;
#            Ns = calcularIndiceAnormalidad(probabilidad);
#            print "Ns";
#            print Ns;
#            verifiarAnomalia(theta, Ns);
#            inicializarRecord(parsedUri);
#        }
    
#    }

#event bro_done(){

#    print "ESTOY LISTO";
#    print Segmentacion::parsedUri;
#    Segmentacion::inicializarRecord(Segmentacion::parsedUri);
#    print Segmentacion::parsedUri;

#}