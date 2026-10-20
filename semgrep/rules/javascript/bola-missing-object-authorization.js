// Fixtures for the js-bola-missing-object-authorization rule.
//
// Annotations follow the semgrep test convention: the "ruleid" comment marks a
// line the rule MUST flag, the "ok" comment marks a line it MUST NOT flag.
//
// The first pair is reduced from appsecco/dvna core/appHandler.js, where
// userEdit (GET) correctly reads req.user.id and userEditSubmit (POST) reads
// req.body.id twenty lines later. Changing one identifier in the posted form
// rewrites another account's password.

var db = require('../models')

// --- object addressed by request input, no session scope --------------------

module.exports.userEditSubmit = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  db.User.find({ where: { id: req.body.id } }).then(user => {
    user.email = req.body.email
    user.save()
  })
}

module.exports.getProduct = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  db.Product.findOne({ where: { id: req.query.id } }).then(p => res.json(p))
}

module.exports.deleteOrder = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  db.Order.destroy({ where: { id: req.params.orderId } }).then(() => res.sendStatus(204))
}

module.exports.getByPk = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  db.Invoice.findByPk(req.params.id).then(i => res.json(i))
}

module.exports.bracketAccess = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  db.User.findOne({ where: { id: req.body['id'] } }).then(u => res.json(u))
}

// Mongoose
module.exports.mongoGet = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  Document.findById(req.params.id).then(d => res.json(d))
}

module.exports.mongoUpdate = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  Document.findByIdAndUpdate(req.params.id, { title: req.body.title }).then(d => res.json(d))
}

module.exports.mongoDelete = function (req, res) {
  // ruleid: js-bola-missing-object-authorization
  Document.findByIdAndDelete(req.params.id).then(() => res.sendStatus(204))
}

// --- safe: identity comes from the session ---------------------------------

module.exports.userEdit = function (req, res) {
  // ok: js-bola-missing-object-authorization
  db.User.find({ where: { id: req.user.id } }).then(user => res.json(user))
}

module.exports.getOwnProduct = function (req, res) {
  // ok: js-bola-missing-object-authorization
  db.Product.findOne({ where: { id: req.query.id, userId: req.user.id } }).then(p => res.json(p))
}

module.exports.deleteOwnOrder = function (req, res) {
  // ok: js-bola-missing-object-authorization
  db.Order.destroy({ where: { id: req.params.orderId, userId: req.user.id } }).then(() => res.sendStatus(204))
}

module.exports.mongoGetOwn = function (req, res) {
  // ok: js-bola-missing-object-authorization
  Document.findOne({ _id: req.params.id, owner: req.user._id }).then(d => res.json(d))
}

module.exports.mongoGetSelf = function (req, res) {
  // ok: js-bola-missing-object-authorization
  Document.findById(req.user.id).then(d => res.json(d))
}

module.exports.sessionScoped = function (req, res) {
  // ok: js-bola-missing-object-authorization
  db.Cart.findOne({ where: { id: req.params.id, sessionId: req.session.id } }).then(c => res.json(c))
}

// --- safe: no request-controlled identifier at all -------------------------

module.exports.listAllPublic = function (req, res) {
  // ok: js-bola-missing-object-authorization
  db.Product.findAll({ where: { published: true } }).then(ps => res.json(ps))
}

// --- known false negative: the where clause built in a variable ------------
//
// The rule requires the request reference to appear inside the call it
// matches. Build the clause one line earlier and the rule goes quiet, even
// though this handler is exactly as exploitable as userEditSubmit above.
//
// A safely-scoped variable (`{ userId: req.user.id, id: req.params.id }`) is
// also skipped, which is the correct outcome, so the indirection costs recall
// rather than precision. The `ok` annotation records real behaviour; it is a
// miss, not a desirable non-finding. See the README.

module.exports.whereClauseInVariable = function (req, res) {
  const where = { id: req.body.id }
  // ok: js-bola-missing-object-authorization
  db.Order.findOne({ where }).then(o => res.json(o))
}
