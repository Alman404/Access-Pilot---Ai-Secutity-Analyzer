/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // AccessPilot theme: dark charcoal + deep green accent
        base: {
          bg: "#0d1210",
          panel: "#121916",
          panel2: "#161d1a",
          border: "#243029",
          border2: "#2e3d35",
        },
        accent: {
          DEFAULT: "#16a34a",
          bright: "#22c55e",
          dim: "#15803d",
        },
        text: {
          DEFAULT: "#e5e7e6",
          muted: "#8a958f",
          faint: "#5f6a64",
        },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 rgba(255,255,255,0.02), 0 8px 24px rgba(0,0,0,0.35)",
      },
    },
  },
  plugins: [],
};
