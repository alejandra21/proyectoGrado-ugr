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
global A:    table[string] of Evaluacion::Rows = table();

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

    Segmentacion::parseHost("https://localhost:8080");
    Segmentacion::parseUrl("/search?client=ùbuntu&channel=fs&q%42=hacer+arroz&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=LNrGWOjdK-eJ8QeOzoaQBA");
    #Entrenamiento::entrenar(Segmentacion::parsedUri);
    #Segmentacion::inicializarRecord(Segmentacion::parsedUri);

    #Segmentacion::parseHost("http://192.168.1.1:8080");
    #Segmentacion::parseUrl("/login?dst=http%3A%2F%2Fwww.testmysecurity.com%2Flogin%3Fdst%3Dhttp%253A%252F%252F192.168.1.1%252F");

    #local queryUri : URI;
    #queryUri = decompose_uri("?client=ubuntu&channel=fs&q=hacerarroz&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=LNrGWOjdK-eJ8QeOzoaQBA");
    #print queryUri$params;

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

event bro_done(){

    print "LISTO";
    print Evaluacion::evaluar(Segmentacion::parsedUri,vectorProbabilidad,0.001);
}