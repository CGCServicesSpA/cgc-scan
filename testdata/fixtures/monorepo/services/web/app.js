function handler(req) {
  return eval(req.body.code);
}
module.exports = handler;
