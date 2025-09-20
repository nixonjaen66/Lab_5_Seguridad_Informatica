// server.js
var validation = require('./libs/unalib');
var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var port = process.env.PORT || 3000;

app.get('/', function(req, res){
  res.sendFile(__dirname + '/index.html');
});

io.on('connection', function(socket){
  socket.on('Evento-Mensaje-Server', function(msg){
    const safe = validation.validateMessage(msg);
    io.emit('Evento-Mensaje-Server', safe);
  });
});

http.listen(port, function(){
  console.log('listening on *:' + port);
});
