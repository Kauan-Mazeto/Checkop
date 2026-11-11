// Resposta falsa do Express: guarda status/corpo para as asserções.
export const fakeRes = () => {
  const res = { statusCode: 200, body: undefined, cookies: {} };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body) => {
    res.body = body;
    return res;
  };
  res.cookie = (name, value) => {
    res.cookies[name] = value;
    return res;
  };
  res.clearCookie = (name) => {
    delete res.cookies[name];
    return res;
  };
  return res;
};

export const fakeReq = (overrides = {}) => ({
  body: {},
  params: {},
  headers: { 'user-agent': 'node-test' },
  ip: '203.0.113.10',
  ...overrides,
});

// dns.lookup({ all: true }) devolve [{ address, family }]
export const dnsAnswer = (...addresses) =>
  addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
