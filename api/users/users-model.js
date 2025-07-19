/**
  resolves to an ARRAY with all users, each user having { user_id, username }
 */

const db = require('../../data/db-config.js');
function find() {
    return db('users').select('user_id', 'username');
}

/**
  resolves to an ARRAY with all users that match the filter condition
 */
function findBy(filter) {
    return db('users').where(filter).select('user_id', 'username');

}

/**
  resolves to the user { user_id, username } with the given user_id
 */
function findById(user_id) {
    return db('users').where({ user_id }).first().select('user_id', 'username');
}

/**
  resolves to the newly inserted user { user_id, username }
 */
async function add(user) {
    const [id] = await db('users').insert(user)
    return findById(id);
}

async function update(user_id, changes) {
    await db('users').where({ user_id }).update(changes);
    return findById(user_id);
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
    find,
    findBy,
    findById,
    add,
    update
};
