/**
 * /examples/nextjs/src/app/page.tsx
 * -------------------------------------------------
 * Double Ratchet Protocol Implementation
 *
 * Authors (Université Libre de Bruxelles ULB):
 * @suyeonORG, @ChaosArnhug, @KTBASECURITY, @Draimy
 *
 * - Signal Protocol Specifications by Trevor Perrin & Moxie Marlinspike
 *   https://signal.org/docs/specifications/doubleratchet/
 *   https://signal.org/docs/specifications/x3dh/
 *
 * - Original 2key-ratchet implementation by Peculiar Ventures, Inc. Under MIT license
 *   https://github.com/PeculiarVentures/2key-ratchet
 *
 * @license MIT
 */
"use client";

import { useState, useEffect } from "react";
import DoubleRatchetDemo from "./components/DoubleRatchetDemo";
import Footer from "./components/Footer";

const tabs = [
  {
    id: "demo",
    label: "Double Ratchet Protocol",
    component: DoubleRatchetDemo,
  }
];

export default function Home() {
  const [activeTab, setActiveTab] = useState("demo");

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace(/^#/, "");
      const foundTab = tabs.find((tab) => tab.id === hash);
      if (foundTab) {
        setActiveTab(foundTab.id);
      } else if (hash === "" || hash === "Double Ratchet Protocol") {
        setActiveTab("demo");
        window.location.hash = "demo";
      }
    };

    if (window.location.hash) {
      handleHashChange();
    } else {
      setActiveTab("demo");
      window.location.hash = "demo";
    }

    window.addEventListener("hashchange", handleHashChange);

    return () => {
      window.removeEventListener("hashchange", handleHashChange);
    };
  }, []);

  const handleTabClick = (id: string) => {
    setActiveTab(id);
    window.location.hash = id;
  };

  const ActiveComponent =
    tabs.find((tab) => tab.id === activeTab)?.component || DoubleRatchetDemo;

  return (
    <div className="app">
      <header className="header">
        <h1>Double Ratchet Cryptographic Protocol</h1>
        <p>
          Signal protocol implementation with modern cryptography using
          X25519/Ed25519 and SHA-512
        </p>
      </header>

      <nav className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => handleTabClick(tab.id)}
            className={`tab ${activeTab === tab.id ? "active" : ""}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="content">
        <ActiveComponent />
      </main>
      
      <Footer />
    </div>
  );
}
