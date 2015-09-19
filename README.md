# pokemon
Pokemon Lua debugger for QtCreator

## Usage
To see an example how to integrate the debugger with your C/C++ code take a look at 

>src/example.cpp 

To connect QtCreator with to you Lua code, start your executable, set breakpoints 
in your Lua code, and then attach the QML debugger via

> Debug -> Start Debugging -> Attach to QML port ...

The debugger should stop on any of your Lua breakpoints.

## Caveats
- Lua files need to be loaded using the full path the the file on disk for QtCreator to find them
- You need to patch QtCreator to
    - take full advantage of debug expressions
    - permit breakpoints in .lua files else files need to end in .js or .qml
- QtCreator will always force evaluation of the 'this' expression which has no counterpart in Lua 