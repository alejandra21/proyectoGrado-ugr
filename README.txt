Universidad de Granada
Departamento de Teoría de la Señal, Telemática y Comunicaciones.
Autor:
       Alejandra Cordero 
  


DESCRIPCIÓN DEL PROGRAMA:

	El conjunto de programas presentados representan la implentación de la 
	técnica de detección de intrusiones SSM sobre URIs de los mensajes 
	tipo GET del protocolo HTTP.

	La implentación de dichos programas se realizó haciendo uso de lenguaje de
	scripting de la herramienta llamada Bro.

ARCHIVOS DE LA ENTREGA:

    -mainEvaluacion.bro: 

        Programa principal que recibe los paquetes de tipo HTML y ejecuta todas 
        las llamadas a función necesarias para evaluar si los URIs de los mismos 
        son anómalos o no.

    -mainEntrenamientoOnline.bro:

        Programa principal que recibe los paquetes de tipo HTML y ejecuta todas 
        las llamadas a función necesarias para realizar un entrenamiento de modo 
        ONLINE.

    -mainEntrenamientoOffline.bro: 

        Programa principal que recibe los paquetes de tipo HTML y ejecuta todas 
        las llamadas a función necesarias para realizar un entrenamiento de modo 
        OFFLINE.

    -segmentacion.bro: 

        Módulo que tiene implementadas todas las funciones y las estructuras de 
        datos requeridas para realizar y almacenar la segmentación de un URI.

    -evaluacion.bro:

        Módulo que tiene implementadas todas las funciones y las estructuras de 
        datos requeridas para evaluar si un URI es anómalo o no.

    -entrenamiento.bro:

        Módulo que tiene implementadas todas las funciones y las estructuras de 
        datos requeridas para realizar el entrenamiento, bien sea ONLINE u OFFLINE.

    -detectorAtaque:

        Bash scripting utilizado para ejecutar los programas.

INSTRUCCIONES DE EJECUCION:
	
	Para ejecutar las diversas modalidades del programa se hará uso del bash 
	scripting "detectorAtaque". 
	Su uso se describirá a continuación.

	- $./detectorAtaque --evl paquetesCapturados.pcap : 

		Nota: "paquetesCapturados.pcap" es un archivo de captura de paquetes que 
		puede tener cualquier nombre.

	 	Funciona para evaluar los URIs contenido en paquetesCapturados.pcap 
	 	sobre un modelo ya construido (en este caso el modelo siembre llevará
	 	el nombre de modeloBro.log) y verificar si los mismo son anómalos o no.

	 	Los URIs anómalos seras escritos en un LOG llamado alertas.log.

	 	Es importante recalcar que para poder realizar la evaluación
	 	debe existir un archivo llamado "config" con los parámetros de 
	 	configuración Poo1, Poo2, Poo3, Poo4 y Theta.

	 	El archivo "config" debe poseer la siguiente estructura:

	 	#fields	clave	valor
	 	Poov1	0.0001
	 	Poov2	0.0001
	 	Poov3	0.0001
	 	Poov4	0.0001
	 	Theta	12.0

	 	Nota importante sobre el archivo config: Los separadores entre palabras 
	 	deben ser obligatoriamente TABS.

	 - $./detectorAtaque --trainingOffline paquetesCapturados.pcap : 

	 	Nota: "paquetesCapturados.pcap" es un archivo de captura de paquetes que 
	 	puede tener cualquier nombre.

	 	Funciona para realizar un entrenamiento de modo OFFLINE.
	 	El modelo construido será escrito en un archivo llamado "modeloBro.log"

	 - $./detectorAtaque --trainingOnline paquetesCapturados.pcap : 

	 	Nota: "paquetesCapturados.pcap" es un archivo de captura de paquetes que 
	 	puede tener cualquier nombre.

	 	Funciona para realizar un entrenamiento de modo ONLINE.

	 	Si existe un modelo ya construido este debe llevar como nombre 
	 	"modeloBro.log" para que sea considerado por el programa.

	 	El nuevo modelo construido será escrito en un archivo 
	 	llamado "modeloBro.log"

 
CIERTAS CONDICIONES:

	- El sistema filtra únicamente paquetes de tipo HEAD. Para modificar este 
	  hecho solo sería necesario cambiar la palabra "HEAD" de los condicionales
	  que se encuentran en la línea 175 del archivo mainEvaluacion.bro, en la
	  línea 105 del archivo mainEntrenamientoOnline.bro y la línea 68 del archivo
	  mainEntrenamientoOffline por la palabra "GET".

	- En el sistema un URI del tipo: 
	  "192.168.137.211/cgi-bin/windmail.exe? -n desired.file attacker_email_address"
	  es considerado un URI incorrecto sintácticamente ya que no existe una 
	  tupla valor=atributo. 

	- En los archivos adjuntos hay un modelo ya construido. 
	  La forma en la que el sistema guarda el modelo es el siguiente:

	  #fields	state	word	probability
	  #types	string	string	double
	  Bss	192.168.1.13	1.0
	  Bsp	idr	0.16759
	  Bsa	idpd	0.000006
	  Bsv	nombre	0.000175
	  numeroPalabraSs	numTotal	205069.0
	  numeroPalabraSp	numTotal	423870.0
	  numeroPalabraSa	numTotal	319727.0
	  numeroPalabraSv	numTotal	319727.0

	  La primera columna corresponde al estado al que corresponde la palabra
	  (Bss, Bsp, Bsv o Bsa), la segunda columna es la palabra y la tercera
	  columna es la probilidad de aparición de la misma.

	  En el modelo se almacena el número total de palabras observadas en cada
	  estado. 
	  
	  La forma de guardar dichas cantidades es la siguiente:

	  	* En la primera columna se almacena las palabras claves numeroPalabraSs,
	  	  numeroPalabraSp, numeroPalabraSa o numeroPalabraSv para identificar
	  	  a que estado corresponde el numero de palabras totales.

	  	* En la segunda columna se almacena la palabra clave "numTotal".

	  	* En la tercera columna se almacena el número total de palabras vista.