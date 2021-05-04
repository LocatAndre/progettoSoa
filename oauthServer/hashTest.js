const bcrypt = require('bcrypt');
const saltRounds = 10;
const yourPassword = "pass";

bcrypt.hash(yourPassword, saltRounds, (err, hash) => {
  console.log('l\'hash è: '+hash)
  myhash = hash
});


  bcrypt.compare(yourPassword, myhash, function(err, res) {
   if (res == true){
   	console.log('password corretta')
   }
   else{
   	console.log('password non riconosciuta')
   }
});
