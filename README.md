# DroneFS

## Compilar e instalar

En primer lugar tenemos que preparar el entorno para poder utilizar el sistema de compilación de GNU. Esto lo hacemos con los siguientes comandos, en el mismo orden en el que aparecen:

```
autoreconf --install
aclocal
automake --add-missing
autoconf
```

El último comando (autoconf) generará automáticamente el famoso script configure encargado de generar los Makefiles que compilarán el código.

Para que los comandos anteriores funcionen hay que tener instalados los siguientes paquetes:

 - autoconf
 - autogen
 - automake
 - autopoint
 - libtool
 - libtool-bin

Para compilar el código fuente simplemente hay que ejecutar la tupla `./configure` y `make install`.

```
./configure --with-openssl --with-libxml2
sudo make install
```

Por defecto el programa se instalará en `/usr/local`. Como es una ruta privilegiada, hay que ejecutar `make install` como root.

También le podemos decir que lo instale en una ruta alternativa. Por ejemplo, si creamos una carpeta local e instalamos todo allí, no es necesario ser root. Para ello, le pasamos el argumento `--prefix` a `configure`, que sirve para indicarle dónde queremos que `make install` instale el software.

```
mkdir out  # este es el directorio donde instalaremos el software
./configure --prefix=$(pwd)/out --with-openssl --with-libxml2
make install   # no es necesario ser root
```

Si los tests unitarios han sido habilitados (esto sucede si “check” está instalado, ver sección “Dependencias”) éstos pueden ejecutarse con make check.

### Dependencias

Las siguientes dependencias son obligatorias, y deben estar instaladas. De lo contrario configure fallará.

| Nombre dependencia | Instalación en Debian (o derivado) |
|--------------------|:----------------------------------:|
| libgcrypt, para el cifrado | apt-get install libgcrypt20-dev |
| liblua, para leer el fichero de configuración. Versión mínima *5.1.5*. | `apt-get install liblua5.1-0-dev` |
| libsqlite, para la base de datos embebida. Versión mínima *3.11*. | `apt-get install libsqlite3-dev` |

Las siguientes dependencias son opcionales. Si no están instaladas, el software se podrá compilar igualmente, aunque ciertas características no estarán disponibles.

| Nombre dependencia | Instalación en Debian (o derivado) |
|--------------------|:----------------------------------:|
| check, un framework para tests unitarios. Si no se instala, no se podrán ejecutar los tests con make check. Versión mínima *0.9.6*. | `apt-get install check` |
| doxygen, un generador de documentación. Se utiliza para generar documentación en HTML de la librería asociada, fsroot. Si no está instalado no se generará la documentación. | `apt-get install doxygen` |

## Ejecutar

Al ejecutar `make install`, deberíamos tener un nuevo comando llamado `fuse-main`. Si le hemos pasado la opción `--prefix` a `configure`, este programa se encuentra en la carpeta que le hemos indicado, a su vez dentro de otra subcarpeta llamada `bin`.

Por ejemplo, si le hemos pasado la carpeta llamada "out" (como en el ejemplo anterior) a `--prefix`, el programa se encontrará en `out/bin/fuse-main`.

Si lo ejecutamos sin más, nos mostrará la ayuda. Vemos que toma las siguientes opciones:

```
Usage: out/bin/fuse-main [options] <mount point> <root dir>

Available options:

-h, --help       Show this help text
--db-file        Set the path to the database file.
                 If the file does not exist, it will be created.
                 --config-file Set the path to the configuration file.
```

Le tenemos que especificar el fichero donde se almacenará la base de datos embebida con la información del sistema de ficheros, y el fichero de configuración donde se especifican qué challenges se van a cargar. Por otro lado, le tenemos que decir la ruta donde se montará el sistema de ficheros ("mount point") y la ruta en la que se almacenarán los ficheros cifrados en disco ("root dir").
Para la base de datos utilizaremos el fichero `fsroot.db`. Este fichero no tiene por qué existir; si no existe lo creará automáticamente. Nosotros simplemente le tenemos que dar la ruta donde queremos que se almacene. Para el fichero de configuración utilizaremos el fichero `config.xml`, que tampoco existe, pero este lo tenemos que crear nosotros. Le damos el siguiente contenido:

```xml
<DroneFSConfig>
<CipherData>AES-128-CTR</CipherData>
  <Challenges>
    <count>2</count>
    <Challenge name="libdch"></Challenge>
    <Challenge name="libdch2"></Challenge>
  </Challenges>
</DroneFSConfig>
```

Con ello le estamos indicando que cargue dos challenges que se encuentran en las librerías "libdch.so" y "libdch2.so". Estos son challenges muy simples que deben usarse únicamente con propósitos de prueba o depuración.

El filesystem lo vamos a montar en la subcarpeta `fuse-mount/`, y la carpeta donde se almacenarán los ficheros cifrados será `fuse-root/`.

Con las opciones indicadas ponemos en marcha el filesystem.

```
out/bin/fuse-main -s -d \
--db-file=$(pwd)/fsroot.db \
--config-file=$(pwd)/config.lua \
$(pwd)/fuse-mount $(pwd)/fuse-root
```

Las opciones `-s` y `-d` indican, respectivamente, que FUSE se debe ejecutar con un sólo hilo, y que debe mostrar mensajes de depuración.

Para parar el sistema de ficheros, simplemente lo desmontamos con el siguiente comando (como root):

```
sudo umount fuse-mount/
```

