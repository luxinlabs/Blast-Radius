import chalk from 'chalk'
import debug from 'debug'

const trace = debug('build')

export function logStep(name) {
  trace(name)
  console.log(chalk.green(name))
}
