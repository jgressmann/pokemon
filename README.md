# pokemon
Pokemon is a library to link to your C/C++ program to debug Lua code using 
[QtCreator](http://www.qt.io/ide/).

## Usage
To see an example how to integrate the debugger with your C/C++ code take a 
look at `src/example.cpp`.

Connect QtCreator to you Lua code by simply marking your project as 'QML
enabled' and uncheck the 'Run in terminal' box. 

> Projects -> 'your project name' -> Build & Run -> 'your kit' -> Run -> Enable QML

Start your program in the debugger and place a breakpoint in any of your
Lua files.

If you must run your program in a terminal, you need to connect the QML
debugger manually:

> Debug -> Start Debugging -> Attach to QML port ...

### Disable debugging

You can disable Lua debugging by defining `POKEMON_NDEBUG` in your project.
If defined you no longer need to link to the pokemon static/shared library. 

## Caveats
- Lua files need to be loaded using the full path to the file on disk for QtCreator to find them
- You need to patch QtCreator to
    - take full advantage of debug expressions
    - permit breakpoints in .lua files else files need to end in .js or .qml
- QtCreator will always force evaluation of the 'this' expression which has no counterpart in Lua 
