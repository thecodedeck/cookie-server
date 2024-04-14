// Authentication middleware in CommonJS syntax
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    return next();
  } else {
    res.status(401).send({ message: "You must be logged in to access this" });
  }
};

module.exports = isAuthenticated;
