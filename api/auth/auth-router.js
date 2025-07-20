// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

const router = require('express').Router(); 
const bcrypt = require('bcryptjs')
const { restricted, checkUsernameFree, checkUsernameExists, checkPasswordLength, checkCurrentPassword } = require('./auth-middleware.js');
const User = require('../users/users-model')




/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {

    const { username, password } = req.body;
    
    const hash = bcrypt.hashSync(password, 8); // Hash the password with a salt rounds of 8
    
    User.add({ username, password: hash })
        .then(user => {
        res.status(201).json({
            user_id: user.user_id,
            username: user.username
        });
        })
        .catch(next);

})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post('/login', checkUsernameExists, checkPasswordLength, (req, res, next) => {
    const { password } = req.body;
    const { user } = req;
    if (bcrypt.compareSync(password, user.password)) {
        // Password matches
        req.session.user = user; // Save user to session
        res.status(200).json({ message: `Welcome ${user.username}!` });
    } else {
        // Password does not match
        next({ status: 401, message: 'Invalid credentials' });
    }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */


router.get('/logout', (req, res) => {
    if (req.session.user) {
        req.session.destroy(err => {
            if (err) {
                res.status(500).json({ message: 'Could not log out' });
            } else {
                res.status(200).json({ message: 'logged out' });
            }
        });
    } else {
        res.status(200).json({ message: 'no session' });
    }
});

/**
  4 [PUT] /api/auth/change-password { "currentPw": "1234", "password": "12345" }
 
  response for logged-in users:
  status 200
  {
    "message": "password Updated!"
  }
 
  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
*/

router.put('/change-password', restricted, checkCurrentPassword, checkPasswordLength, async (req, res, next) => {

  const { password } = req.body;
  const { user_id } = req.session.user;
  const hash = await bcrypt.hashSync(password, 8); // Hash the new password
  User.updatePassword(user_id, hash)
    .then(() => {
      res.status(200).json({ message: "password Updated!" });
    })
    .catch(next);

})


 
// Don't forget to add the router to the `exports` object so it can be required in other modules


module.exports = router;