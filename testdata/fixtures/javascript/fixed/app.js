function handler(req) {
  const code = String(req.body.code);
  const pattern = String(req.query.pattern);
  return code.includes(pattern);
}

module.exports = handler;
