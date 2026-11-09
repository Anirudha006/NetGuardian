/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#070b14',
          900: '#0d1527',
          800: '#1e2e4f',
          700: '#334155',
        }
      }
    },
  },
  plugins: [],
}
