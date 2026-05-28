import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        primary: "#58a6ff",
        surface: "#0d1117",
        border: "#21262d",
        muted: "#8b949e",
        danger: "#f85149",
        success: "#3fb950",
        warning: "#d29922",
      },
    },
  },
  plugins: [],
};

export default config;
