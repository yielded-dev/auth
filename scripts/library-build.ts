import { getBabelOutputPlugin } from "@rollup/plugin-babel";

/** Match Effect's published output while keeping purity annotations out of source. */
export const pureAnnotations = () =>
  getBabelOutputPlugin({
    excludeChunks: [/\.d$/],
    babelrc: false,
    configFile: false,
    plugins: ["babel-plugin-annotate-pure-calls"],
  });
