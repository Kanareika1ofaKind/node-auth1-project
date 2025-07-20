const db = require('../../data/db-config.js')
const bcrypt = require('bcryptjs')
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/



function restricted(req, res, next) {
    if (req.session.user) {
        next()
    } else {
        next({ status: 401, message: 'you shall not pass!' })
    }

}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {

    const { username } = req.body;
    if (!username) {
        return next({ status: 422, message: 'Username required' });
    }
    const existingUser = await db('users').where({ username }).first();
    if (existingUser) {
        return next({ status: 422, message: 'Username taken' });
    }
    next();

}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {

    const { username } = req.body;
    if (!username) {
        return next({ status: 401, message: 'Invalid credentials' });
    }
    const existingUser = await db('users').where({ username }).first();
    if (!existingUser) {
        return next({ status: 401, message: 'Invalid credentials' });
    }
    req.user = existingUser; // Store the user in the request object for later use
    next();

}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {

    const { password } = req.body;
    if (!password || password.length < 4) {
        return next({ status: 422, message: 'Password must be longer than 3 chars' });
    }
    next();
}
async function checkCurrentPassword(req, res, next) {
  const { currentPw, password } = req.body;
  const { user_id } = req.session.user;

  if (!password) {
    return next({ status: 422, message: 'New password required' });
  }
  if (!currentPw) {
    return next({ status: 422, message: 'Current password required' });
  }
  if (currentPw === password) {
    return next({ status: 422, message: 'New password must be different from current password' });
  }
  const user = await db('users').where({ user_id }).first();
  if (!user || !bcrypt.compareSync(currentPw, user.password)) {
    return next({ status: 401, message: 'Invalid credentials' });
  }
  next();

}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
    restricted,
    checkUsernameFree,
    checkUsernameExists,
    checkPasswordLength,
    checkCurrentPassword

};
