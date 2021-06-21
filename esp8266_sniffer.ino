#include <ESP8266WiFi.h> //incluimos la libreira esp8266 que se instala desde preferecnia de placas del arduino IDE
#include <Arduino.h> //dincluimos la libreria de arduino 
#include <TimeLib.h>//importamos la libreria Time lib la cual nosa ayudara a tener un registro exacto del tiempo en el que se embio el pauqete 
#include <SPI.h>//llamamos a la libreria spi el cual nosa ayudara a guardar los archivos para leerlos con el wiresahrk 
#include <SdFat.h>//el sdFAt nos aydara a tener identificara nuestra sd como un formateado tipo FAT
#include <PCAP.h> //el Pcap en si es nuestro sniffer la llamamos como libreria  y nos ayuda a guardarlos en la sd 


File esp8266_;
extern "C" { //indicamos el external c para que el esp reconsoca el el sd 
  #include "user_interface.h" //importamos la libreria user_interface
}


#define CHANNEL 1 //inidcamos el canal en el que sniffearemos los paquetes en este caso 1 se puede otro canal pero en este caso usaremos el 1 
#define FILENAME "esp8266"//definimos nuestro tipo de placa que usamos 
#define SAVE_INTERVAL 30 //indicamos cuanto tiempo le daremos para que vaya guardando los paquetes en el sd
#define CHANNEL_HOPPING false //indicamos si buscaremos en mas canales en este caso le pondremos en false para ahorro de memoria sd
#define MAX_CHANNEL 11 //en el cso que ayamos puesto true anteriormente ponemos el maximo de canales 
#define HOP_INTERVAL 214 //ponemos el interbalo de de sniffing en este caso 214


SdFat SD;//declaramos nuestra sd con la ayuda de la libreria sdfat 
unsigned long lastTime = 0;//en caso de que tengamos asignado un espacio en nuestra sd le damos un tiempo el sin guaradar en la sd es una variable la cual la inicializamos en 0
unsigned long lastChannelChange = 0;//en caso en que guardemos nuestro canal en el que estamos esniffeando es una bariable que incializamos en 0
int counter = 0; //creamos una variabel llamada counter en 0
int ch = CHANNEL; //creamos una variable llamada ch y le asignamos la variable CHANNEL
bool fileOpen = false; //creamos una baraible tipo boleana llamada file open la inicializamos en false


PCAP pcap = PCAP();//usamos la herramienta Pacap de la libreria pcap 


void sniffer(uint8_t *buf, uint16_t len) { //creamos la libreria sniffer con las variables 
  if(fileOpen){//abrimos un if preguntando si se abre el archivo en el que se guardara 
    uint32_t timestamp = now(); //current timestamp //declaramos que nuestra variable sea de 32 bits 
    uint32_t microseconds = (unsigned int)(micros() - millis() * 1000); //micro segundos de offset de (0 - 999)
    pcap.newPacketSD(timestamp, microseconds, len, buf); //escribimos el paquete en el archivo
  }
}

void openFile(){//creamos una nueva clase la cual se llamara open file 

  //searches for the next non-existent file name
  int c = 0; //declaramos una variable entera llamada c inicializamos en 0 
  String filename = (String)FILENAME + ".pcap";//declaramos la variable tipo string llamada filename en la cual usaremos lo pacaps
  while(SD.exists(filename.c_str())){//inicializamos un while en el que si existe usamos la libreria sd fat idicandole si existe un sd que guarde en la variable filename 
    filename = (String)FILENAME + "_" + (String)c + ".pcap";//guardamos los archivos sd en el file name para guardarlos en el sd
    c++;//saumamos mas uno a nuestra bariable c 
  }

  pcap.filename = filename;//guardamos y le asignmamos la herramienta .pcap a filename 
  fileOpen = pcap.openFile(SD);//usamos de la libreria pcap el abrir archivo en la sd 

  Serial.println("abierto: "+filename);//imprimos por consola abierto mas la variable filename 

  counter = 0; //iniciamos un contador en 0 
}



void setup() { //creamos un nueva clase 
  
  Serial.begin(9600);//indicamos la velocidad de nuestra comunicacion serial
  pinMode(LED_BUILTIN, OUTPUT); //definimos nuestro pin 9 como salida
  
  Serial.begin(115200); //indicamos la velocidad del serial en este caso 115200
  delay(2000); //esperamos un tiempo de 2 segundos 
  Serial.println();//asemos un salto de impresion 
  Serial.println("empezando..."); //imprimimos en un salto de linea empezando 
  
  if(!SD.begin()) { //inicializamos un if indicando que si no se puede acceder al sd
    Serial.println("iniciacion fallida");//imprimimos en un salto de consola que fallo la conexion cojn el sd
    return;//retorno
  }
  Serial.println("iniciacicion exitosa");//indicamos que ubo exito con la conexion con el sds

  openFile();//llamamos a la clase openfile
  
  wifi_set_opmode(STATION_MODE); //inicializando el esp como una estacion wifi
  wifi_promiscuous_enable(0); //inabilitamos el modo promiscuo 
  WiFi.disconnect(); //desconectando la red de toda linea wifi
  wifi_set_promiscuous_rx_cb(sniffer); //asemos un llamado a la libreria sniffer
  wifi_set_channel(ch); //switch para seleccionar otro canal 
  wifi_promiscuous_enable(1); //abilitamos el modo promiscuo
  
  Serial.println("Sniffer iniciado!");//imprimimos que el sniffer inicio

  Serial.begin(9600);//baudios de comunicacion serial con el micro sd
  Serial.print(F("Iniciando SD"));//mensaje de inicio sd en consola
  if (!SD.begin(4))//abriendo un if para el pin de comunicacion de guardado de los pcap
  {
    Serial.println(F("Error al iniciar"));//mensaje de error en caso de no poder abrir escribir en el sd
    return;//retorno
  }
  Serial.println(F("Iniciado correctamente"));//mensaje correcto de abrir el sd

  if (esp8266_) {//abrimos un if 
    Serial.print("leyendo el archivo esp8266.pcap....");//mensaje de lectura en los test de pcaps
    esp8266_.println("testing 1, 2, 3.");//mensaje de consola de testeo de pcaps
    
    esp8266_.close();//clase de cierre de la consola
    Serial.println("abierto.");//imprimimos que archivo pacap 1 se abrira 
    
  } else {//condicion else en caso de imprimirse error 

    Serial.println("error al abrir esp8266.pcap");//error de lectura en archivo del pacap 
  }

  esp8266_ = SD.open("esp8266.pcap");//tratamos de abrir el archivo con sd.open de la libreria sd.h
  if (esp8266_) {//abrimos una condicion de if 
    Serial.println("esp8266.pcap:");//mensaje con salto de linea en cosola 

 
    while (esp8266_.available()) {//condicion de while indicamos mientras se pueda abrir el archivo esp8266
      Serial.write(esp8266_.read());//indicamos que podamos leer el archivo 
    }
    esp8266_.close();//cerramos el archivo .pcap
  } else {//condicion de else 
    
    Serial.println("error en el archibo esp8266.pcap");//imprimimos mensaje
  }
}




void loop() { //entarmos a nuestra clase loop 
  unsigned long currentTime = millis();//usamos la libreria Timelib en milisegundos 

  digitalWrite(LED_BUILTIN, LOW);//indicamos que nuestro led este apagado 
  if(CHANNEL_HOPPING){//indicamos el salto de canal encaso que indiquemos en la parte superior si queremos tener varios canales al escucha 
    if(currentTime - lastChannelChange >= HOP_INTERVAL){//indicamos que si nuestra resta entre el tiempo recorrido con la ultimo canal guardado es mayor o igual hop intervalo 
      lastChannelChange = currentTime;//indicamos que nuestro ultimo canal guardado sera igual anuestro tiempo recorrido  
      ch++; //incremento de la variable ch
      if(ch > MAX_CHANNEL) ch = 1;//acreamos un if en el cual indicamos que si ch es mayor a nuestro max channel permitidos el cual pusimos 11 y luego lo ch lo igualmos a 1 
      wifi_set_channel(ch); //switch del nuevo canal
      Serial.println( "conmutado del canal " + (String)ch );//imprimos con un salto de linea en consola que  el conmutado del canal con tipo cadena con la variable ch
    }
  }
  
  
  if(fileOpen && currentTime - lastTime >= 1000){//abrimos un if preguntado si nuestra open file y nuestro tiempo transcurrido restado con nuestro lasttime es mayor o igual a 1000
    pcap.flushFile(); //guardamos el archivo 
    lastTime = millis(); //actualizamos el tiempo
    counter++; //sumamos 1 al contador
    
  }

  /* when counter > 30s interval */
  if(fileOpen && counter >= SAVE_INTERVAL){//abrimos un if en el cual preguntamos si nuestro fileopen y nuestro contador en mayor o igual en nuestro save_interval
    pcap.closeFile(); //guardamos y cerramos el archivo
    fileOpen = false; //actualizamos nuestro flag
    Serial.println("==================");//imprimos un espacio con lineas
    Serial.println(pcap.filename + " guardado!");//imprimimos con un salto de linea nuestro filename con la herramienta pcap indicando que se guardo 
    Serial.println("==================");//imprimos un espacio con lineas
    openFile(); //abrimos un nuevo file
    delay(1000);                      // esperamos un segundo
    digitalWrite(LED_BUILTIN, HIGH);  // encendemos el led 
    delay(2000);  //esperamos 2 segundos
  }
}
