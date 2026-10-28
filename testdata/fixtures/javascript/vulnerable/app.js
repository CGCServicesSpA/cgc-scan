const cp = require('child_process');

function handler(req) {
  eval(req.body.code);
  cp.exec('ls ' + req.query.dir);
  const re = new RegExp(req.query.pattern);
  return re.test(req.query.value);
}

module.exports = handler;
