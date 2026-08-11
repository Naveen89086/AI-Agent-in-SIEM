import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./auth/AuthContext";
import "./styles/theme.css";
import "./styles/soc.css";
import "./styles/fim.css";
import "./styles/threat.css";
import "./styles/endpoint.css";

const root = createRoot(document.getElementById("root")!);
root.render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>
);
