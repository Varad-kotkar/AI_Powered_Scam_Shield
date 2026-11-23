import React, { useState } from "react";
import { Routes, Route } from "react-router-dom";
import NavBar from "./components/NavBar";
import PremiumHero from "./components/PremiumHero";
import PremiumSearchBar from "./components/PremiumSearchBar";
import InferencePanel from "./components/InferencePanel";
import FaqSection from "./components/FaqSection";
import SiteFooter from "./components/SiteFooter";
import { textCheck, urlCheck, imageCheckFile, chatMultipart } from "./api";
import BatchScanPage from "./pages/BatchScanPage";
import DocsPage from "./pages/DocsPage";
import NotFoundPage from "./pages/NotFoundPage";

// Text, SMS, email, and script use the same text endpoint; URLs and images have dedicated endpoints.
function submitDetection(mode, query, file) {
  if (mode === "urls") return urlCheck(query);
  if (mode === "images") return imageCheckFile(file);
  if (mode === "chat") return chatMultipart(query, file);
  return textCheck(query);
}

function HomePage() {
  const [mode, setMode] = useState("text");
  const [query, setQuery] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  async function run() {
    setIsLoading(true);
    setResult(null);

    try {
      if (mode === "images" && !file) {
        alert("Upload image first!");
        return;
      }

      const response = await submitDetection(mode, query, file);
      console.log("API Response:", response);
      console.log("Response Data:", response.data);
      setResult(response.data);
    } catch (err) {
      console.error("API Error:", err);
      console.error("Error Response:", err?.response?.data);
      setResult({ error: err?.response?.data || err.message });
    } finally {
      setIsLoading(false);
    }
  }

  // Clear the visible result and the parent input state; the search bar mirrors this reset.
  const clearResults = () => {
    setResult(null);
    setQuery("");
    setFile(null);
  };

  return (
    <div className="min-h-screen bg-white text-slate-900">
      <div className="relative z-10 flex min-h-screen flex-col">
        <NavBar />

        <main className="flex-1">
          <div className="mx-auto flex w-full max-w-3xl flex-col px-4 pb-16 pt-8 md:pb-20">
            <PremiumHero />

            <section id="modes" className="mt-6">
              <PremiumSearchBar
                baseQuery={query}
                setBaseQuery={setQuery}
                mode={mode}
                setMode={setMode}
                baseFile={file}
                setBaseFile={setFile}
                run={run}
                loading={isLoading}
                onClearResults={clearResults}
              />
            </section>

            <section className="mt-10">
              <InferencePanel data={result} loading={isLoading} mode={mode} onClear={clearResults} />
            </section>

            <FaqSection />
          </div>
        </main>

        <SiteFooter />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/batch-scan" element={<BatchScanPage />} />
      <Route path="/docs" element={<DocsPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
