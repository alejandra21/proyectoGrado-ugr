#------------------------------------------------------------------------------#
#                                  IMPORTES                                    #
#------------------------------------------------------------------------------#

module HTTP;
@load segmentacion
@load evaluacion
@load entrenamiento

#------------------------------------------------------------------------------#
#                                 REGISTROS                                    #
#------------------------------------------------------------------------------#


type Clave: record {

        clave : string;
};

type Valor: record {

        valor : string &default = "";
};

#------------------------------------------------------------------------------#
#                             VARIABLES GLOBALES                               #
#------------------------------------------------------------------------------#

global modelo: table[string] of Valor;
global BSsTable: table[string] of Evaluacion::Probability = table();
global BSpTable: table[string] of Evaluacion::Probability = table();
global BSaTable: table[string] of Evaluacion::Probability = table();
global BSvTable: table[string] of Evaluacion::Probability = table();
global A:    table[string] of Evaluacion::Rows = table();
global vectorProbabilidad: vector of table[string] of Evaluacion::Probability = { BSsTable , BSpTable, BSvTable , BSaTable };

# Claves del modelo.
global Bss: string   = "Bss";
global Bsp: string   = "Bsp";
global Bsv: string   = "Bsv";
global Bsa: string   = "Bsas";
global Poov: string  = "Poov";
global Theta: string = "Theta";

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio";
    # Se leen los datos del modelo.
    Input::add_table([$source="modelo", $name="modelo",
                          $idx=Clave, $val=Valor, $destination=modelo]);

    # Se extraen de un archivo de texto los vectores de probabilidad B
    Input::add_table([$source=modelo[Bss]$valor, $name=modelo[Bss]$valor,
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=BSsTable]);

    Input::add_table([$source=modelo[Bsp]$valor, $name=modelo[Bsp]$valor,
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=BSpTable]);

    Input::add_table([$source=modelo[Bsa]$valor, $name=modelo[Bsa]$valor,
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=BSaTable]);

    Input::add_table([$source=modelo[Bsv]$valor, $name=modelo[Bsv]$valor,
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=BSvTable]);

    Input::add_table([$source="A", $name="A",
                      $idx=Evaluacion::Column, $val=Evaluacion::Rows, $destination=A]);

    Segmentacion::parseHost("https://localhost:8080");
    Segmentacion::parseUrl("/search?client=ùbuntu&channel=fs&q%42=hacer+arroz&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=LNrGWOjdK-eJ8QeOzoaQBA");
    Entrenamiento::entrenar(Segmentacion::parsedUri);
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);

    Segmentacion::parseHost("http://192.168.1.1:8080");
    Segmentacion::parseUrl("/login?dst=http%3A%2F%2Fwww.testmysecurity.com%2Flogin%3Fdst%3Dhttp%253A%252F%252F192.168.1.1%252F");
    Entrenamiento::entrenar(Segmentacion::parsedUri);


    #local queryUri : URI;
    #queryUri = decompose_uri("?client=ubuntu&channel=fs&q=hacerarroz&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=LNrGWOjdK-eJ8QeOzoaQBA");
    #print queryUri$params;

}

event Input::end_of_data(name: string, source: string) {

    event bro_done();
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



    #print BSsTable;
    #print BSpTable;
    #print BSaTable;
    #print BSvTable;


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
    print Evaluacion::evaluar(Segmentacion::parsedUri,vectorProbabilidad,
                              to_double(modelo[Poov]$valor));
}