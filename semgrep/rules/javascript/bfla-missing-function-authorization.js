// Fixtures for the js-bfla-missing-function-authorization rule.
//
// Annotations follow the semgrep test convention: the "ruleid" comment marks a
// line the rule MUST flag, the "ok" comment marks a line it MUST NOT flag.
//
// listUsersAPI is reduced from appsecco/dvna core/appHandler.js. Its route is
// /admin/usersapi, mounted with isAuthenticated and nothing else, while the
// /admin page it serves renders conditionally on req.user.role == 'admin'.
// The page checks the role. The API behind it does not.

var db = require('../models')

// --- unbounded read, no authorization in the handler -----------------------

module.exports.listUsersAPI = function (req, res) {
  // ruleid: js-bfla-missing-function-authorization
  db.User.findAll({}).then(users => res.status(200).json({ success: true, users: users }))
}

module.exports.listUsersArrow = (req, res) => {
  // ruleid: js-bfla-missing-function-authorization
  db.User.findAll().then(users => res.json(users))
}

module.exports.dumpAllDocs = function (req, res) {
  // ruleid: js-bfla-missing-function-authorization
  Document.find({}).then(docs => res.json(docs))
}

module.exports.truncateTable = function (req, res) {
  // ruleid: js-bfla-missing-function-authorization
  db.AuditLog.destroy({ truncate: true }).then(() => res.sendStatus(204))
}

module.exports.wipeDocs = function (req, res) {
  // ruleid: js-bfla-missing-function-authorization
  Document.deleteMany({}).then(() => res.sendStatus(204))
}

// --- authorization present: inline role guard ------------------------------

module.exports.listUsersRoleGuarded = function (req, res) {
  if (req.user.role !== 'admin') return res.sendStatus(403)
  // ok: js-bfla-missing-function-authorization
  db.User.findAll({}).then(users => res.json(users))
}

module.exports.listUsersFlagGuarded = (req, res) => {
  if (!req.user.isAdmin) return res.sendStatus(403)
  // ok: js-bfla-missing-function-authorization
  db.User.findAll({}).then(users => res.json(users))
}

module.exports.listUsersNegatedGuard = function (req, res) {
  if (req.user.role === 'admin') {
    // ok: js-bfla-missing-function-authorization
    db.User.findAll({}).then(users => res.json(users))
  } else {
    res.sendStatus(403)
  }
}

// --- authorization present: helper -----------------------------------------

module.exports.listUsersHelper = function (req, res) {
  requireRole(req, 'admin')
  // ok: js-bfla-missing-function-authorization
  db.User.findAll({}).then(users => res.json(users))
}

module.exports.listUsersPermission = function (req, res) {
  checkPermission(req, 'users:read')
  // ok: js-bfla-missing-function-authorization
  db.User.findAll({}).then(users => res.json(users))
}

// --- not an unbounded read, so out of scope --------------------------------

module.exports.listOwnOrders = function (req, res) {
  // ok: js-bfla-missing-function-authorization
  db.Order.findAll({ where: { userId: req.user.id } }).then(os => res.json(os))
}

module.exports.listPublished = function (req, res) {
  // ok: js-bfla-missing-function-authorization
  db.Product.findAll({ where: { published: true } }).then(ps => res.json(ps))
}
