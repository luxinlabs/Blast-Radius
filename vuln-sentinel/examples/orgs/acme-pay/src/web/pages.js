import next from 'next'

export function renderHome(req, res) {
  return next({ dev: false }).render(req, res, '/')
}
