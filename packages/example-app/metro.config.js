const path = require('path')
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config')

/**
 * This app lives inside the react-native-matrix-crypto yarn workspace and
 * depends on a hoisted sibling package (react-native-matrix-crypto itself,
 * plus its own dependencies like @ubjs/core). Yarn hoists those to the
 * workspace root's node_modules, not this app's own -- but Metro's default
 * config only crawls this project's own root, so it never indexes the
 * hoisted root node_modules and fails to resolve anything that lives there
 * ("Unable to resolve module @babel/runtime/helpers/interopRequireDefault",
 * confirmed empirically even though the file is present on disk). Adding
 * the workspace root as a watched folder, and its node_modules as a second
 * resolution path, is the standard Metro monorepo configuration for this.
 *
 * https://reactnative.dev/docs/metro#adding-support-for-monorepos
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const projectRoot = __dirname
const workspaceRoot = path.resolve(projectRoot, '../..')

const config = {
  watchFolders: [workspaceRoot],
  resolver: {
    nodeModulesPaths: [
      path.resolve(projectRoot, 'node_modules'),
      path.resolve(workspaceRoot, 'node_modules'),
    ],
  },
}

module.exports = mergeConfig(getDefaultConfig(projectRoot), config)
