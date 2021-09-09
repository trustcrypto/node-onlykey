const path = require('path');
// const webpack = require('webpack');
const TerserPlugin = require("terser-webpack-plugin");


const minify = process.env.MINIFY == 1 ? true : false

module.exports = {
    mode: process.env.NODE_ENV,
    entry: ['./src/onlykey-api.js'],
    resolve: {
        alias: {
            forge: path.resolve(__dirname, 'libs/forge.min.js'),
            nacl: path.resolve(__dirname, 'libs/nacl.js'),
            crypto: path.resolve(__dirname, 'libs/webcrypto-shim.js'),
            // events: path.resolve(__dirname, 'src/libs/events.js'),
        },
    },

    output: {
        path: path.resolve(__dirname, (process.env.OUT_DIR) ? process.env.OUT_DIR : './'),
        filename: './dist/onlykey3rd-party'+(minify ? ".min" : "")+'.js',
        library: {
          name: 'ONLYKEY',
          type: 'umd',
        },
    },
    optimization: {
        minimize: minify,
        // minimizer: [new TerserPlugin({
        //     extractComments: false,
        // })]
    },
    stats: { errorDetails: true }
};
