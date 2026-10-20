// Fixtures for the js-mass-assignment-privileged-field rule.
//
// Annotations follow the semgrep test convention: the "ruleid" comment marks a
// line the rule MUST flag, the "ok" comment marks a line it MUST NOT flag.
//
// The indirection cases are the point. Taint mode exists here because the
// obvious `Model.create(req.body)` is the version that gets caught in review,
// and `const body = req.body` fifty lines earlier is the version that ships.

var db = require('../models')

// --- whole body handed to the ORM ------------------------------------------

module.exports.registerDirect = function (req, res) {
  // ruleid: js-mass-assignment-privileged-field
  db.User.create(req.body).then(u => res.json(u))
}

module.exports.registerLaundered = function (req, res) {
  const body = req.body
  const payload = body
  // ruleid: js-mass-assignment-privileged-field
  db.User.create(payload).then(u => res.json(u))
}

module.exports.registerConstructor = function (req, res) {
  // ruleid: js-mass-assignment-privileged-field
  const u = new db.User(req.body)
  u.save()
}

module.exports.updateBlind = function (req, res) {
  // ruleid: js-mass-assignment-privileged-field
  db.User.update(req.body, { where: { id: req.user.id } }).then(() => res.sendStatus(204))
}

module.exports.mongoUpdateBlind = function (req, res) {
  // ruleid: js-mass-assignment-privileged-field
  User.findByIdAndUpdate(req.user.id, req.body).then(() => res.sendStatus(204))
}

module.exports.objectAssign = function (req, res) {
  db.User.findByPk(req.user.id).then(user => {
    // ruleid: js-mass-assignment-privileged-field
    Object.assign(user, req.body)
    user.save()
  })
}

// --- privileged property written from the request -------------------------

module.exports.setRole = function (req, res) {
  db.User.findByPk(req.user.id).then(user => {
    // ruleid: js-mass-assignment-privileged-field
    user.role = req.body.role
    user.save()
  })
}

module.exports.setAdminFlagLaundered = function (req, res) {
  const body = req.body
  db.User.findByPk(req.user.id).then(user => {
    // ruleid: js-mass-assignment-privileged-field
    user.isAdmin = body.isAdmin
    user.save()
  })
}

module.exports.setBalance = function (req, res) {
  db.Account.findByPk(req.user.id).then(account => {
    // ruleid: js-mass-assignment-privileged-field
    account.balance = req.body.balance
    account.save()
  })
}

module.exports.setPriceFromQuery = function (req, res) {
  db.Product.findByPk(req.body.id).then(product => {
    // ruleid: js-mass-assignment-privileged-field
    product.price = req.query.price
    product.save()
  })
}

// --- safe: fields chosen explicitly ---------------------------------------

module.exports.registerAllowlisted = function (req, res) {
  // ok: js-mass-assignment-privileged-field
  db.User.create({ name: req.body.name, email: req.body.email, login: req.body.login })
    .then(u => res.json(u))
}

module.exports.updateAllowlisted = function (req, res) {
  db.User.findByPk(req.user.id).then(user => {
    // ok: js-mass-assignment-privileged-field
    user.email = req.body.email
    user.name = req.body.name
    user.save()
  })
}

module.exports.roleFromServerPolicy = function (req, res) {
  db.User.findByPk(req.user.id).then(user => {
    // ok: js-mass-assignment-privileged-field
    user.role = defaultRoleFor(user)
    user.save()
  })
}

module.exports.serverSetFlag = function (req, res) {
  db.User.findByPk(req.user.id).then(user => {
    // ok: js-mass-assignment-privileged-field
    user.verified = true
    user.save()
  })
}

module.exports.nonPrivilegedField = function (req, res) {
  db.User.findByPk(req.user.id).then(user => {
    // ok: js-mass-assignment-privileged-field
    user.bio = req.body.bio
    user.save()
  })
}

function defaultRoleFor (user) {
  return 'user'
}

// --- known false negative: spread of the whole body -----------------------
//
// `{ ...req.body }` is an object literal, and the sinks exclude object
// literals so that an explicit allowlist does not get flagged. The two shapes
// are syntactically the same kind of node, so excluding one excludes the
// other. This spread is as dangerous as create(req.body) and is missed.
// Recorded as real behaviour, not as a desirable outcome. See the README.

module.exports.spreadWholeBody = function (req, res) {
  // ok: js-mass-assignment-privileged-field
  db.User.create({ ...req.body }).then(u => res.json(u))
}
