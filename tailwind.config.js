/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/authmcp_gateway/templates/**/*.html",
    "./src/authmcp_gateway/admin/login.py",
    "./src/authmcp_gateway/setup_wizard.py",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
