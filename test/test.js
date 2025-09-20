var val = require('../libs/unalib');
var assert = require('assert');


describe('unalib', function(){

  describe('funcion is_valid_phone', function(){

    it('deberia devolver true para 8297-8547', function(){
      assert.equal(val.is_valid_phone('8297-8547'), true);
    });

    it('deberia devolver false para 8297p-8547', function(){
      assert.equal(val.is_valid_phone('8297p-8547'), false);
    });

  });   

  describe('funcion is_valid_url_image', function(){

    it('deberia devolver true para http://image.com/image.jpg', function(){
      assert.equal(val.is_valid_url_image('http://image.com/image.jpg'), true);
    });

    it('deberia devolver true para http://image.com/image.gif', function(){
      assert.equal(val.is_valid_url_image('http://image.com/image.gif'), true);
    });
    
  });

  describe('funcion is_valid_yt_video', function(){

    it('deberia devolver true para un enlace válido de YouTube', function(){
      assert.equal(val.is_valid_yt_video('https://www.youtube.com/watch?v=qYwlqx-JLok'), true);
    });

  });


  describe('funcion is_valid_url_video', function(){

    it('deberia devolver true para un .mp4 válido', function(){
      assert.equal(val.is_valid_url_video('https://videos.com/clip.mp4'), true);
    });

    it('deberia devolver false para un archivo .txt', function(){
      assert.equal(val.is_valid_url_video('https://videos.com/file.txt'), false);
    });

  });

describe('validateMessage - bloqueo estricto XSS', function() {
  it('debe devolver kind=blocked para <script>', function() {
    const input = JSON.stringify({ nombre:'X', color:'#000', mensaje: "<script>alert('x')</script>" });
    const out = JSON.parse(val.validateMessage(input));
    assert.equal(out.kind, 'blocked');
  });

  it('debe devolver kind=blocked para <img onerror=...>', function() {
    const input = JSON.stringify({ nombre:'X', color:'#000', mensaje: "<img src=x onerror=alert(1)>" });
    const out = JSON.parse(val.validateMessage(input));
    assert.equal(out.kind, 'blocked');
  });

  it('debe devolver kind=blocked para esquema javascript:', function() {
    const input = JSON.stringify({ nombre:'X', color:'#000', mensaje: "javascript:alert(1)" });
    const out = JSON.parse(val.validateMessage(input));
    assert.equal(out.kind, 'blocked');
  });

  it('no debe bloquear texto normal', function() {
    const input = JSON.stringify({ nombre:'A', color:'#123', mensaje: "hola esto es texto" });
    const out = JSON.parse(val.validateMessage(input));
    assert.equal(out.kind, 'text');
    assert.ok(out.text.includes('hola'));
    });

  });

});





