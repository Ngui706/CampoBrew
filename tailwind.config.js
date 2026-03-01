/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './public/**/*.html',
    './src/**/*.js',
    './server.js'
  ],
  theme: {
    extend: {
      colors: {
        coffee: {
          light: '#F5EBE0',
          DEFAULT: '#D5BDAF',
          medium: '#C38E70',
          dark: '#3A2618',
        },
      },
      fontFamily: {
        sans: ['Poppins'],
        serif: ['Playfair Display'],
      },
    },
  },
  plugins: [],
};
