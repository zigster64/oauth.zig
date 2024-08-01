/** @type {import('tailwindcss').Config} */

colors = require('tailwindcss/colors');
const plugin = require('tailwindcss/plugin')


module.exports = {
    mode: 'jit',
    content: ["./src/html/**/*.html", "./src/**/*.zig"],
    plugins: [
        require("@tailwindcss/typography"),
        require("daisyui"),
    ],
    daisyui: {
        themes: ["light", "dark", "cupcake"],
    }
}
