import axios from 'axios'

export async function chargeCard(order) {
  return axios.post('https://psp.example.invalid/charge', order)
}

export async function refundCard(chargeId) {
  return axios.post('https://psp.example.invalid/refund', { chargeId })
}
