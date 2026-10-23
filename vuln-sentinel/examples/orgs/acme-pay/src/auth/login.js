const axios = require('axios')

async function verifyToken(token) {
  return axios.get('https://idp.example.invalid/verify', { headers: { Authorization: token } })
}

module.exports = { verifyToken }
