import { useMemo, useRef, useState } from "react";
import "./App.css";

const initialFiles = [
  { id: 1, name: "Research_Paper.pdf", type: "PDF", size: "2.4 MB", date: "Today, 10:42 AM", status: "Encrypted", color: "violet" },
  { id: 2, name: "Project_Architecture.png", type: "PNG", size: "846 KB", date: "Yesterday", status: "Encrypted", color: "blue" },
  { id: 3, name: "Team_Notes.docx", type: "DOCX", size: "128 KB", date: "Oct 15, 2026", status: "Encrypted", color: "orange" },
  { id: 4, name: "Demo_Video.mp4", type: "MP4", size: "18.7 MB", date: "Oct 12, 2026", status: "Encrypted", color: "pink" },
];

const navItems = [
  { label: "Dashboard", icon: "⌂" },
  { label: "My Files", icon: "▤" },
  { label: "Shared with me", icon: "⇄" },
  { label: "Security", icon: "⬡" },
];

function Icon({ children, className = "" }) {
  return <span aria-hidden="true" className={`icon ${className}`}>{children}</span>;
}

function FileGlyph({ type, color }) {
  return <span className={`file-glyph ${color}`}><span>{type === "DOCX" ? "W" : type === "PDF" ? "P" : type === "PNG" ? "▧" : "▶"}</span></span>;
}

export default function App() {
  const [activeNav, setActiveNav] = useState("Dashboard");
  const [files, setFiles] = useState(initialFiles);
  const [search, setSearch] = useState("");
  const [notice, setNotice] = useState("");
  const inputRef = useRef(null);

  const visibleFiles = useMemo(
    () => files.filter((file) => file.name.toLowerCase().includes(search.toLowerCase())),
    [files, search]
  );

  function handleFiles(selected) {
    const picked = Array.from(selected || []);
    if (!picked.length) return;
    const added = picked.map((file, index) => ({
      id: Date.now() + index,
      name: file.name,
      type: file.name.split(".").pop()?.slice(0, 4).toUpperCase() || "FILE",
      size: file.size < 1024 * 1024 ? `${Math.max(1, Math.round(file.size / 1024))} KB` : `${(file.size / (1024 * 1024)).toFixed(1)} MB`,
      date: "Just now",
      status: "Ready to encrypt",
      color: ["blue", "violet", "orange", "pink"][index % 4],
    }));
    setFiles((current) => [...added, ...current]);
    setNotice(`${picked.length} file${picked.length > 1 ? "s" : ""} added to the demo list. No encryption or upload has occurred yet.`);
    if (inputRef.current) inputRef.current.value = "";
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#dashboard" onClick={() => setActiveNav("Dashboard")}>
          <span className="brand-mark"><Icon>◈</Icon></span>
          <span className="brand-name">qshare<span>.</span><small>SECURE FILE SPACE</small></span>
        </a>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          {navItems.map((item) => (
            <button key={item.label} className={`nav-item ${activeNav === item.label ? "active" : ""}`} onClick={() => setActiveNav(item.label)}>
              <Icon>{item.icon}</Icon><span>{item.label}</span>
              {item.label === "Shared with me" && <span className="nav-count">3</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="storage-card">
            <div className="storage-top"><span>Storage used</span><strong>21.4 / 50 GB</strong></div>
            <div className="storage-track"><span /></div>
            <p>42.8% of your secure space</p>
          </div>
          <button className={`nav-item ${activeNav === "Settings" ? "active" : ""}`} onClick={() => setActiveNav("Settings")}><Icon>⚙</Icon><span>Settings</span></button>
          <div className="profile">
            <div className="avatar">MK</div>
            <div className="profile-text"><strong>My workspace</strong><span>Free plan · Demo</span></div>
            <span className="profile-more">•••</span>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{activeNav}</strong></div>
          <div className="topbar-actions">
            <span className="secure-pill"><span className="pulse-dot" /> Secure session</span>
            <button className="icon-button" aria-label="Notifications" onClick={() => setNotice("No new notifications in this demo.")}>♧<i /></button>
            <div className="top-avatar">MK</div>
          </div>
        </header>

        <div className="page-content">
          <section className="welcome-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> YOUR PRIVATE CLOUD</div>
              <h1>{activeNav === "Dashboard" ? "Your files, under your control." : activeNav}</h1>
              <p className="page-subtitle">{activeNav === "Dashboard" ? "A safer place for the files that matter." : `Manage your ${activeNav.toLowerCase()} in one secure workspace.`}</p>
            </div>
            <button className="primary-button" onClick={() => inputRef.current?.click()}><Icon>＋</Icon> Upload files</button>
            <input ref={inputRef} className="hidden-input" type="file" multiple onChange={(event) => handleFiles(event.target.files)} />
          </section>

          <section className="hero-card">
            <div className="hero-content">
              <div className="hero-badge"><Icon>✦</Icon> BUILT FOR THE NEXT ERA</div>
              <h2>Privacy that’s ready<br />for tomorrow.</h2>
              <p>QShare is being built around modern encryption standards, with a post-quantum key exchange roadmap.</p>
              <button className="hero-link" onClick={() => setActiveNav("Security")}>Explore security <span>↗</span></button>
            </div>
            <div className="hero-art" aria-hidden="true">
              <div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="orbit orbit-three" />
              <div className="glow" />
              <div className="shield"><div className="shield-inner"><span className="shield-lock">⌑</span><span className="shield-check">✓</span></div></div>
              <div className="floating-chip chip-top"><span className="mini-dot green" /> AES-256-GCM</div>
              <div className="floating-chip chip-bottom"><span className="mini-dot purple" /> ML-KEM-768 <small>PLANNED</small></div>
            </div>
            <div className="hero-grid" />
          </section>

          {notice && <div className="notice" role="status"><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss">×</button></div>}

          <section className="stats-grid">
            <article className="stat-card">
              <div className="stat-icon violet-bg"><Icon>▤</Icon></div><div className="stat-label">Total files</div>
              <div className="stat-value">{files.length.toString().padStart(2, "0")} <span className="stat-trend">↗ demo</span></div><div className="stat-foot">Across your workspace</div>
            </article>
            <article className="stat-card">
              <div className="stat-icon green-bg"><Icon>✓</Icon></div><div className="stat-label">Encrypted files</div>
              <div className="stat-value">{files.filter((f) => f.status === "Encrypted").length.toString().padStart(2, "0")} <span className="stat-muted">of {files.length}</span></div><div className="stat-foot">Demo status only</div>
            </article>
            <article className="stat-card">
              <div className="stat-icon blue-bg"><Icon>⇄</Icon></div><div className="stat-label">Shared with you</div>
              <div className="stat-value">03 <span className="stat-trend">+1 this week</span></div><div className="stat-foot">Shared file invitations</div>
            </article>
            <article className="stat-card">
              <div className="stat-icon orange-bg"><Icon>◷</Icon></div><div className="stat-label">Security score</div>
              <div className="stat-value">— <span className="stat-muted">not audited</span></div><div className="stat-foot">Available after security review</div>
            </article>
          </section>

          <section className="files-section">
            <div className="section-heading">
              <div><h2>Recent files</h2><p>Your latest files in one place.</p></div>
              <div className="file-actions">
                <label className="search-box"><Icon>⌕</Icon><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search files..." /></label>
                <button className="secondary-button" onClick={() => setActiveNav("My Files")}>View all <span>→</span></button>
              </div>
            </div>
            <div className="files-table-wrap">
              <table className="files-table">
                <thead><tr><th>FILE NAME</th><th>SIZE</th><th>LAST MODIFIED</th><th>STATUS</th><th aria-label="Actions" /></tr></thead>
                <tbody>
                  {visibleFiles.map((file) => (
                    <tr key={file.id}>
                      <td><div className="file-name-cell"><FileGlyph type={file.type} color={file.color} /><div><strong>{file.name}</strong><span>{file.type} document</span></div></div></td>
                      <td className="muted-cell">{file.size}</td><td className="muted-cell">{file.date}</td>
                      <td><span className={`status-pill ${file.status === "Encrypted" ? "status-encrypted" : "status-pending"}`}><span />{file.status}</span></td>
                      <td><button className="row-menu" aria-label={`Actions for ${file.name}`} onClick={() => setNotice(`${file.name}: actions will be available after backend integration.`)}>•••</button></td>
                    </tr>
                  ))}
                  {visibleFiles.length === 0 && <tr><td colSpan="5" className="empty-state">No files match “{search}”.</td></tr>}
                </tbody>
              </table>
              <div className="table-footer"><span>Showing <strong>{visibleFiles.length}</strong> of <strong>{files.length}</strong> files</span><span className="demo-tag">DEMO DATA</span></div>
            </div>
          </section>

          <footer className="page-footer"><span>© 2026 QShare · Secure file sharing research project</span><span><i className="footer-dot" /> Prototype interface · Not production-ready</span></footer>
        </div>
      </main>
    </div>
  );
}
