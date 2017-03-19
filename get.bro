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

type Model: record {

        clave : string;
};


type Valor: record {

        valor : string;
};

#------------------------------------------------------------------------------#
#                             VARIABLES GLOBALES                               #
#------------------------------------------------------------------------------#

global modelo : table[string] of Valor;
global modelTable: table[string] of string;
global BSsTable: table[string] of Evaluacion::Probability = table();
global BSpTable: table[string] of Evaluacion::Probability = table();
global BSaTable: table[string] of Evaluacion::Probability = table();
global BSvTable: table[string] of Evaluacion::Probability = table();
global A:    table[string] of Evaluacion::Rows = table();
global vectorProbabilidad: vector of table[string] of Evaluacion::Probability = { BSsTable , BSpTable, BSvTable , BSaTable };

# Claves del modelo.
global Bss: string   = "BssPrueba.log";
global Bsp: string   = "BspPrueba.log";
global Bsv: string   = "BsvPrueba.log";
global Bsa: string   = "BsaPrueba.log";
global Poov: string  = "Poov";
global Theta: string = "Theta";

#------------------------------------------------------------------------------#
#                             EVENTO PRINCIPAL                                 #
#------------------------------------------------------------------------------#

event bro_init(){

    print "Inicio";
    # Se leen los datos del modelo.
    Input::add_table([$source="modelo", $name="modelo",$idx=Model, 
                        $val=Valor, $destination=modelo]);

    # Se extraen de un archivo de texto los vectores de probabilidad B
    Input::add_table([$source=Bss, $name=Bss,
                          $idx=Evaluacion::Word, $val=Evaluacion::Probability, 
                          $destination=BSsTable]);

    Input::add_table([$source=Bsp, $name=Bsp,
                          $idx=Evaluacion::Word, 
                          $val=Evaluacion::Probability,
                          $destination=BSpTable]);

    Input::add_table([$source=Bsa, $name=Bsa,
                          $idx=Evaluacion::Word, 
                          $val=Evaluacion::Probability, 
                          $destination=BSaTable]);

    Input::add_table([$source=Bsv, $name=Bsv,
                        $idx=Evaluacion::Word, 
                        $val=Evaluacion::Probability, 
                        $destination=BSvTable]);


    Segmentacion::parseHost("https://localhost:8080");
    Segmentacion::parseUrl("/search?client=ùbuntu&channel=fs&q%42=hacer+arroz&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=LNrGWOjdK-eJ8QeOzoaQBA");
    #Entrenamiento::entrenar(Segmentacion::parsedUri);
    Segmentacion::inicializarRecord(Segmentacion::parsedUri);

    Segmentacion::parseHost("http://192.168.1.1:8080");
    Segmentacion::parseUrl("/login?dst=http%3A%2F%2Fwww.testmysecurity.com%2Flogin%3Fdst%3Dhttp%253A%252F%252F192.168.1.1%252F");
    #Entrenamiento::entrenar(Segmentacion::parsedUri);

}

#------------------------------------------------------------------------------#

event Input::end_of_data(name: string, source: string) {

}

event http_reply(c: connection, version: string, code: count, reason: string)
    {

    local indicesDeAnormalidad: table[count] of double;
    local probabilidad: double;
    local Ns: double;

    if ( c$http$method == "GET" && c$http$status_code == 200 ){

            print "Estoy en GET";
            print modelo;
            Segmentacion::parseHost(c$http$host);
            Segmentacion::parseUrl(c$http$uri);
            indicesDeAnormalidad = Evaluacion::evaluar(Segmentacion::parsedUri,
                                                    vectorProbabilidad,
                                                    to_double(modelo[Poov]$valor));

            Evaluacion::verifiarAnomalia(to_double(modelo[Theta]$valor),indicesDeAnormalidad);
            Segmentacion::inicializarRecord(Segmentacion::parsedUri);
        }
    
    }

#------------------------------------------------------------------------------#

event bro_done(){

    print "LISTO";
    print modelo;
    print to_double(modelo[Poov]$valor);
    #print Evaluacion::evaluar(Segmentacion::parsedUri,vectorProbabilidad,to_double(modelo[Poov]$valor));
}

#------------------------------------------------------------------------------#
