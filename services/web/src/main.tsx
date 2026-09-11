import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import "./styles.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("the console needs a #root element; index.html is out of step");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
