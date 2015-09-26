# pokemon
Pokemon is a library to link to your C++ program to debug Lua code using 
[QtCreator](http://www.qt.io/ide/).


## Usage


### Configure your environment

Set the environment variable `QTC_QMLDEBUGGER_FILEEXTENSIONS` to the file
extensions for QML/JS and Lua:

```
bash>export QTC_QMLDEBUGGER_FILEEXTENSIONS=".qml;.js;.lua"
```

Restart QtCreator from the updated environment.


### Configure your project in QtCreator

Setup your project to use be 'QML enabled' and uncheck the 'Run in terminal' box. 

> Projects -> 'your project name' -> Build & Run -> 'your kit' -> Run -> Enable QML

If you must run your program in a terminal, you need to connect the QML
debugger manually:

> Debug -> Start Debugging -> Attach to QML port ...


### Setup pokemon in your source code
To see an example how to integrate the debugger with your C++ code take a 
look at `src/example.cpp`.

Start your program in the debugger and place a breakpoint in any of your
Lua files.


#### Disable debugging

You can disable Lua debugging by defining `POKEMON_NDEBUG` in your project.
If defined you no longer need to link to the pokemon static/shared library. 


## Compatibility

* You need QtCreator 3.5.1 or build it yourself using the current master branch.
* The debugger has been tested with Lua 5.1 and 5.2 on Linux (x86_64).
* The Windows implementation is a stub and doesn't work right now.


## Caveats
- QtCreator will always force evaluation of the 'this' expression which has no counterpart in Lua 
