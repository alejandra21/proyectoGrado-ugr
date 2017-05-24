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