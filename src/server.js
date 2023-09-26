'use strict'
const express = require('express');
const esession = require('express-session');
const crypto = require('node:crypto');
const multer  = require('multer')

/* not work with mysql
 * ER_NOT_SUPPORTED_AUTH_MODE:
 * Client does not support authentication protocol requested by server;
 * consider upgrading MySQL client
 */
const mysql = require('mysql2');
const db = mysql.createPool({
  host     : process.env.DB_HOST,
  user     : process.env.DB_USER,
  password : process.env.DB_PASSWORD,
  database : process.env.DB_NAME,
  connectionLimit: 10
});

const staffTbl = 'CREATE TABLE IF NOT EXISTS stafftbl (staffid INT AUTO_INCREMENT PRIMARY KEY, username TEXT, password TEXT, onboard DATETIME, message TEXT)';
const supplyTbl = 'CREATE TABLE IF NOT EXISTS supplytbl (staffid INT AUTO_INCREMENT PRIMARY KEY, username TEXT, supplyname TEXT)';

const HOST = '::';
const PORT = process.env.PORT;

const app = express();
app.set('views', './views');
app.set('view engine', 'pug');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/static', express.static('public'));
const topsecret = crypto.randomUUID() + '|' + crypto.randomUUID();
console.log(topsecret);
app.use(esession({
  name: 'buero.id',
  secret: topsecret,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

/* handle users already authenticated */
const redirect_to_staff = (req, res, next) => {
  var user = req.session.user;
  if (user == undefined) {
    next();
  } else {
    console.log('Redirect to /staff');
    res.redirect('/staff');
  }
}

app.get('/register', redirect_to_staff, (req, res) => {
  console.log('Get register');
  res.status(200).render('register');
});

app.post('/register', (req, res) => {
  const user = req.body.user;
  const pass = req.body.pass;
  const pass2 = req.body.pass2;
  var ts = (new Date()).toISOString().substring(0, 19).replace('T', ' ');

  if (user == undefined || pass == undefined || pass2 == undefined || user === '' || pass === '') {
    console.log('Post register failed: empty username or password');
    return res.status(400).send({'status': 'empty username or password'});
  }

  if (pass !== pass2) {
    console.log('Post register failed: password not match');
    return res.status(400).send({'status': 'password not match'});
  }

  if (user.match(/[^A-Za-z0-9/+_]/)) {
    console.log('Post register failed: forbidden characters');
    return res.status(400).send({'status': 'forbidden characters'});
  }

  var sql = `select * from stafftbl where username = ?`;
  db.query(sql, [user], (err, result) => {
    if (err) {
      console.log('Post register failed: ' + err.message);
      return res.status(500).send({'status': 'null'});
    }

    if (result.length != 0) {
      console.log('Post register failed: exists')
      return res.status(400).send({'status': 'user already exists'});
    }

    sql = `insert into stafftbl (username, password, onboard) values (?, ?, ?)`;
    db.query(sql, [user, pass, ts], (err, result) => {
      if(err) {
        console.log('Post register failed: ' + err.message);
        return res.status(500).send({'status': 'null'});
      }
      console.log('Post register succeeded: ' + user);
      res.status(201).send({'status': 'registration successful'});
    });
  });
});

app.get('/', redirect_to_staff, (req, res) => {
  console.log('Get /');
  res.status(200).render('index');
});

app.get('/health', (req, res) => {
  console.log('Get health');
  res.status(200).send({'status': 'ok'});
});

app.get('/login', redirect_to_staff, (req, res) => {
  console.log('Get login');
  res.status(200).render('login');
});

app.post('/login', (req, res, next) => {
  const user = req.body.user;
  const pass = req.body.pass;

  if (user == undefined || pass == undefined) {
    console.log('Login failed: empty')
    return res.status(400).send({'status': 'empty username or password'})
  }

  var sql = `select username, password from stafftbl where username = ?`;
  db.query(sql, [user], (err, result) => {
    if (err) {
      console.log('Post login failed: ' + err.message)
      return res.status(500).send({'status': 'null'});
    }

    if (result.length != 1) {
      console.log('Post login failed: none or multi user')
      return res.status(401).send({'status': 'Login failed'});
    }

    if (user == result[0].username && pass == result[0].password) {
      req.session.regenerate((err) => {
        if (err) next(err);
        req.session.user = user;
        console.log('Post login session: ' + JSON.stringify(req.session));
        req.session.save((err) => {
          if (err)
            return next(err)
          console.log('Post login succeeded: ' + user);
          res.redirect('/staff');
        });
      });
    } else if (user == result.username && pass != result.password) {
      console.log('Post login failed: wrong password')
      return res.status(401).send({'status': 'null'});
    } else {
      console.log('Post login failed: TODO')
      return res.status(401).send({'status': 'null'});
    }
  });
});

app.get('/logout', (req, res, next) => {
  req.session.user = null;
  req.session.save((err) => {
    if (err) return next(err);
    res.redirect('/');
  });
});

const auth = (req, res, next) => {
  // console.log('Authn: ' + JSON.stringify(req.session));
  var user = req.session.user;
  if (user == undefined) {
    console.log('Authn: not authenticated');
    res.status(401).send({'status': 'unauthenticated'});
  } else {
    console.log('Authn successful: ' + user);
    next();
  }
};

app.use('/staff', auth);

app.get('/staff/', (req, res) => {
  var user = req.session.user;
  if (user == undefined) {
    console.log('Get staff: no user given');
    res.status(400).send({'status': 'empty user'});
  }
  var sql = `select username, onboard, message from stafftbl where username = ?`;
  db.query(sql, [user], (err, result) => {
    if (err) {
      console.log('Get staff: ' + err.message);
      res.status(500).send({'status': 'null'});
    } else if (result.length == 0) {
      console.log('Get staff: user not found');
      res.status(404).send({'status': 'user not found'});
    } else {
      console.log('Get staff: user found');
      var message = result[0].message;
      if (message !== null && message.length > 60) {
        message = message.substring(0, 60);
      }
      sql = `select supplyname from supplytbl where username = ?`
      db.query(sql, [user], (err, result1) => {
        if (err) {
          console.log('Get staff: supply ' + err.message);
          res.status(500).send({'status': 'null'});
        } else if (result1.length != 0) {
          res.status(200).render('staff', {user: result[0].username,
            onboard: result[0].onboard, msg: message,
            supply: result1[0].supplyname});
        } else {
          res.status(200).render('staff', {user: result[0].username,
            onboard: result[0].onboard, msg: message, supply: ''});
        }
      });
    }
  });
});

function blockencrypt(msg, key, len) {
  var encmsg = [];
  for (var i = 0; i < len; i++) {
    encmsg.push(msg[i] ^ key[i]);
  }
  return Buffer.from(encmsg);
}

app.post('/staff/message', (req, res) => {
  var user = req.session.user;
  var sql = `select password from stafftbl where username = ?`
  db.query(sql, [user], (err, result) => {
    if (err) {
      console.log('Post staff message: ' + err.message);
      res.status(500).send({'status': 'null'});
    } else if (result.length == 0) {
      console.log('Post staff message: user not found');
      res.status(404).send({'status': 'user not found'});
    } else {
      var len = req.body.message.length;
      if (len <= 0) {
        console.log('Post staff message: message empty');
        res.status(413).send({'status': 'message empty'});
      } else if (len > 64) {
        console.log('Post staff message: message too long');
        res.status(413).send({'status': 'message too long'});
      } else {
        var keyBuffer = crypto.pbkdf2Sync(result[0].password, 'salt', 10, len, 'sha256');
        var msg_id = crypto.randomBytes(len);
        var msg = (new TextEncoder()).encode(req.body.message);
        var encmsgid = blockencrypt(keyBuffer, msg_id, len);
        var encmsg = blockencrypt(keyBuffer, msg, len);
        msg = encmsg.toString('hex') + msg_id.toString('hex') + encmsgid.toString('hex');
        sql = `update stafftbl set message = ? where username = ?`;
        db.query(sql, [msg, user], (req, result) => {
          if(err) {
            console.log('Post staff message: ' + err.message);
            res.status(500).send({'status': 'null'});
          }
          console.log('Post staff message: message inserted');
          res.status(200).send({'status': 'ok'});
        });
      }
    }
  });
});

app.get('/staff/message/:staff', (req, res) => {
  var staff = req.params.staff;
  var sql = `select message from stafftbl where username = ?`
  db.query(sql, [staff], (err, result) => {
    if (err) {
      console.log('Get staff message: ' + err.message);
      res.status(500).send({'status': 'null'});
    } else if (result.length != 1) {
      console.log('Get staff message: message not found');
      res.status(404).send({'status': 'message not found'});
    } else {
      var message = result[0].message;
      console.log('Get staff message: ' + message);
      res.status(200).send({'status': 'ok', 'message': message});
    }
  });
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads');
  },
  filename: (req, file, cb) => {
    var  newname = crypto.createHash('sha1').update(req.session.user + file.originalname).digest('hex');
    cb(null, newname);
  }
});

const limits = {
  fields: 64,
  fileSize: 64,
  files: 64,
  parts: 64
}

const uploader = multer({storage: storage, limits: limits});

app.post('/staff/supply',
  (req, res, next) => {
    var user = req.session.user;
    var sql = `select supplyname from supplytbl where username = ?`;
    db.query(sql, [user], (err, result) => {
      if(err) {
        console.log('Post staff supply: select supplyname');
        res.status(500).send({'status': 'null'});
      }
      if (result.length != 0) {
        console.log('Post staff supply: supply available');
        res.status(400).send({'status': 'supply already exists'});
      } else {
        next()
      }
    });
  },
  uploader.single('supply'),
  (req, res) => {
    var file = req.file;
    var user = req.session.user;
    var origname = file.originalname;
    if (file == undefined) {
      console.log('Post staff supply: no file');
      res.status(400).send({'status': 'no file uploaded'});
    } else {
      console.log('Post staff supply: ' + origname);
      console.log('Post staff supply: ' + file.path);
      var sql = `insert into supplytbl (username, supplyname) values (?, ?)`;
      db.query(sql, [user, origname], (err, result) => {
        if(err) {
          console.log('Post staff supply: insert supplyname ' + err.message);
          res.status(500).send({'status': 'null'});
        }
        res.status(201).send({'status': 'supply created'});
      });

    }
  }
);

app.get('/staff/supply/:fn', (req, res) => {
  var fn = '/app/uploads/' + req.params.fn;
  var user = req.session.user;
  console.log('Get staff supply: ' + fn);
  var sql = `select supplyname from supplytbl where username = ?`;
  db.query(sql, [user], (err, result) => {
    if(err) {
      console.log('Get staff supply: ' + err.message);
      res.status(500).send({'status': 'null'});
    } else if (result.length == 0) {
      console.log('Get staff supply: supply empty');
      res.status(404).send({'status': 'supply not found'});
    } else {
      res.setHeader('Content-Type', 'text/plain');
      res.status(200).sendFile(fn);
    }
  });
});

app.listen(PORT, HOST, () => {
  db.query(staffTbl, (err) => {if (err) console.log(err)});
  db.query(supplyTbl, (err) => {if (err) console.log(err)});
  console.log(`===================================`)
  console.log(`Bürographie listening on port ${PORT}`)
});
