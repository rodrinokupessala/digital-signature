var express = require('express');
var router = express.Router();
let crypto=require('crypto')
/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/create-key-pair', function(req, res, next) {
 const {publicKey,privateKey}=crypto.generateKeyPairSync('rsa',{
   modulusLength:2048,
   publicKeyEncoding:{
     type:'spki',
     format:'der'
   },
   privateKeyEncoding:{
    type:'pkcs8',
    format:'der'
   }
 })
 res.send({publicKey:publicKey.toString('base64'),privateKey:privateKey.toString('base64')})
});


router.post('/sign', function(req, res, next) {
   let data=req.body.data
   let privateKey=req.body.privateKey


   const _privateKey=crypto.createPrivateKey({
    key:Buffer.from(privateKey,'base64'),
 
      type:'pkcs8',
      format:'der'
  
  })
const sign=crypto.createSign('sha1')//sha256
sign.update(data)
sign.end()
const signature=sign.sign(_privateKey).toString('base64')
  res.send({signature:signature})


 });


 router.post('/verify', function(req, res, next) {
  let {data,publicKey,signature}=req.body
  


  const _publicKey=crypto.createPublicKey({
   key:Buffer.from(publicKey,'base64'),

   type:'spki',
   format:'der'
 
 })
const verify=crypto.createVerify('sha1')//sha256
verify.update(data)
verify.end()
const result=verify.verify(_publicKey,Buffer.from(signature,'base64'))
 res.send({result:result})


});

 

module.exports = router;
