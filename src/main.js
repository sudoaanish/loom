// Safely extract Tauri IPC & Events libraries for Tauri v2/v1, or fallback to mock
const { invoke } = window.__TAURI__?.core || window.__TAURI__?.tauri || {
  invoke: async (cmd, args) => {
    console.warn(`[Tauri Mock] Invoke '${cmd}'`, args);
    if (cmd === 'has_identity') return false;
    if (cmd === 'generate_new_identity') return "LOOM-MOCKTOKENBASE32DUMMYVALUE";
    if (cmd === 'get_my_token') return "LOOM-MOCKTOKENBASE32DUMMYVALUE";
    if (cmd === 'get_contacts') return [];
    if (cmd === 'get_messages') return [];
    return null;
  }
};

const { listen } = window.__TAURI__?.event || {
  listen: async (event, callback) => {
    console.warn(`[Tauri Mock] Subscribed to event: '${event}'`);
    return () => console.log(`[Tauri Mock] Unsubscribed from: '${event}'`);
  }
};

// Hex translation utility for safe mapping keys
function arrayToHex(arr) {
  if (!arr) return '';
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// App-wide State
const State = {
  myToken: null,
  contacts: new Map(),        // Key: hex(public_key) -> Value: ContactInfo
  discoveredPeers: new Map(), // Key: hex(peer_identity) -> Value: { peer_identity, ip, port }
  sessions: new Set(),        // Set of hex(public_key) for established sessions
  unreadCounts: new Map(),    // Key: hex(public_key) -> Count
  activeContactPubKey: null,  // Vec<u8> representation
  activeContactHex: null      // Hex string representation
};

// Minimal self-contained QR-drawing utility to render base32 token as a QR pattern on canvas
function drawQRPattern(canvasId, token) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const size = 21; // 21x21 grid (QR Version 1)
  const pixelSize = Math.floor(canvas.width / size);
  
  // Clear canvas
  ctx.fillStyle = "#FFFFFF";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  
  // 21x21 grid representation (0: empty, 1: black, -1: white)
  const grid = Array(size).fill(null).map(() => Array(size).fill(0));
  
  // Helper to draw a finder pattern
  function drawFinder(x, y) {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const isBlack = (r === 0 || r === 6 || c === 0 || c === 6) ||
                        (r >= 2 && r <= 4 && c >= 2 && c <= 4);
        grid[y + r][x + c] = isBlack ? 1 : -1;
      }
    }
  }
  
  // Draw finder patterns
  drawFinder(0, 0);          // Top-Left
  drawFinder(14, 0);         // Top-Right
  drawFinder(0, 14);         // Bottom-Left
  
  // Hash token to seed a deterministic pseudo-random generator
  let hash = 0;
  for (let i = 0; i < token.length; i++) {
    hash = (hash << 5) - hash + token.charCodeAt(i);
    hash |= 0; // Convert to 32bit integer
  }
  
  // Simple LCG PRNG
  function nextRand() {
    hash = (hash * 1664525 + 1013904223) | 0;
    return (hash >>> 0) / 4294967296;
  }
  
  // Fill remaining cells
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (grid[r][c] === 0) {
        if (r === 6 || c === 6) {
          // Timing patterns
          grid[r][c] = (r === 6 ? c : r) % 2 === 0 ? 1 : -1;
        } else {
          grid[r][c] = nextRand() < 0.5 ? 1 : -1;
        }
      }
    }
  }
  
  // Draw grid to canvas
  const darkColor = "#08080C"; // Obsidian dark
  const offset = Math.floor((canvas.width - (size * pixelSize)) / 2);
  
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (grid[r][c] === 1) {
        ctx.fillStyle = darkColor;
        ctx.fillRect(offset + c * pixelSize, offset + r * pixelSize, pixelSize, pixelSize);
      }
    }
  }
}

// Screen Toggle Helper
function toggleScreen(screenId) {
  const onboarding = document.getElementById("onboarding-screen");
  const app = document.getElementById("app-screen");
  
  if (screenId === "onboarding-setup") {
    onboarding.classList.remove("hidden");
    document.getElementById("onboarding-setup-view").classList.remove("hidden");
    document.getElementById("onboarding-display-view").classList.add("hidden");
    app.classList.add("hidden");
  } else if (screenId === "onboarding-display") {
    onboarding.classList.remove("hidden");
    document.getElementById("onboarding-setup-view").classList.add("hidden");
    document.getElementById("onboarding-display-view").classList.remove("hidden");
    app.classList.add("hidden");
  } else if (screenId === "app") {
    onboarding.classList.add("hidden");
    app.classList.remove("hidden");
  }
}

// UI Notification Helper
function showError(message) {
  console.error(message);
  alert(message);
}

// Load and Refresh Contacts
async function refreshContacts() {
  try {
    const list = await invoke("get_contacts");
    State.contacts.clear();
    list.forEach(c => {
      const hex = arrayToHex(c.public_key);
      State.contacts.set(hex, c);
    });
    renderContactsList();
  } catch (err) {
    showError("Failed to fetch contacts: " + err);
  }
}

// Render list of saved contacts
function renderContactsList() {
  const container = document.getElementById("list-contacts");
  if (!container) return;
  container.innerHTML = "";
  
  State.contacts.forEach((contact, hex) => {
    const li = document.createElement("li");
    li.className = `contact-card ${hex === State.activeContactHex ? 'active' : ''}`;
    
    const isSessionActive = State.sessions.has(hex);
    const isPeerOnline = State.discoveredPeers.has(hex);
    
    let statusClass = "offline";
    let statusLabel = "Offline";
    
    if (isSessionActive) {
      statusClass = "secured";
      statusLabel = "Secured";
    } else if (isPeerOnline) {
      statusClass = "handshake-ready";
      statusLabel = "Online";
    }
    
    const unread = State.unreadCounts.get(hex) || 0;
    const unreadBadge = unread > 0 ? `<span class="unread-badge" style="background: var(--accent-rose); border-radius: 50%; width: 18px; height: 18px; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold; margin-left: 8px;">${unread}</span>` : '';
    
    li.innerHTML = `
      <div class="contact-card-info">
        <span class="contact-name">${contact.display_name} ${unreadBadge}</span>
        <span class="contact-pubkey">${hex.substring(0, 12)}...</span>
      </div>
      <div class="contact-status-badge ${statusClass}">${statusLabel}</div>
    `;
    
    li.addEventListener("click", () => selectContact(contact));
    container.appendChild(li);
  });
}

// Render list of discovered mDNS peers
function renderPeersList() {
  const container = document.getElementById("list-discovered-peers");
  if (!container) return;
  container.innerHTML = "";
  
  State.discoveredPeers.forEach((peer, hex) => {
    // If this peer is already a contact, we don't display them in raw peers list
    if (State.contacts.has(hex)) return;
    
    const li = document.createElement("li");
    li.className = "peer-card";
    li.innerHTML = `
      <div class="peer-card-info">
        <span class="peer-addr">${peer.ip}:${peer.port}</span>
        <span class="peer-hash">${hex.substring(0, 12)}...</span>
      </div>
      <button class="glass-button compact btn-add-peer-contact">Add</button>
    `;
    
    li.querySelector(".btn-add-peer-contact").addEventListener("click", (e) => {
      e.stopPropagation();
      openAddContactFromPeer(hex, peer);
    });
    
    container.appendChild(li);
  });
}

// Auto-fill form from discovered peer
function openAddContactFromPeer(hex, peer) {
  const nameInput = document.getElementById("input-contact-name");
  const tokenInput = document.getElementById("input-contact-token");
  
  nameInput.value = `Peer-${hex.substring(0, 6)}`;
  tokenInput.focus();
}

// Select contact to load chat
async function selectContact(contact) {
  const hex = arrayToHex(contact.public_key);
  State.activeContactPubKey = contact.public_key;
  State.activeContactHex = hex;
  State.unreadCounts.set(hex, 0); // Clear unread
  
  document.getElementById("chat-fallback").classList.add("hidden");
  document.getElementById("chat-active-container").classList.remove("hidden");
  document.getElementById("chat-contact-name").innerText = contact.display_name;
  
  const isSessionActive = State.sessions.has(hex);
  updateChatHeaderStatus(isSessionActive);
  toggleChatInputs(isSessionActive);
  
  renderContactsList();
  await loadMessageHistory(contact.public_key);
}

// Update UI headers based on session state
function updateChatHeaderStatus(isSessionActive) {
  const statusDot = document.getElementById("chat-status-dot");
  const statusText = document.getElementById("chat-status-text");
  
  if (isSessionActive) {
    statusDot.className = "status-dot secured";
    statusText.innerText = "Secured";
  } else {
    statusDot.className = "status-dot offline";
    statusText.innerText = "No Secure Session";
  }
}

// Toggle disable states of message input
function toggleChatInputs(enabled) {
  const input = document.getElementById("input-chat-message");
  const btn = document.getElementById("btn-chat-send");
  
  input.disabled = !enabled;
  btn.disabled = !enabled;
}

// Load message history from DB
async function loadMessageHistory(pubKey) {
  try {
    const messages = await invoke("get_messages", { contact_pub_key: pubKey });
    renderMessageFeed(messages);
  } catch (err) {
    showError("Failed to load message history: " + err);
  }
}

// Render messages in feed
function renderMessageFeed(messages) {
  const feed = document.getElementById("chat-message-feed");
  if (!feed) return;
  feed.innerHTML = "";
  
  messages.forEach(m => {
    appendMessageToFeed(m, false);
  });
  
  feed.scrollTop = feed.scrollHeight;
}

// Append single message to feed
function appendMessageToFeed(msg, scroll = true) {
  const feed = document.getElementById("chat-message-feed");
  if (!feed) return;
  
  const bubble = document.createElement("div");
  const isIncoming = arrayToHex(msg.sender) === State.activeContactHex;
  
  bubble.className = `message-bubble ${isIncoming ? 'incoming' : 'outgoing'}`;
  
  const date = new Date(msg.timestamp * 1000);
  const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  
  bubble.innerHTML = `
    <div class="message-content">${escapeHTML(msg.content)}</div>
    <div class="message-time">${timeStr}</div>
  `;
  
  feed.appendChild(bubble);
  if (scroll) {
    feed.scrollTop = feed.scrollHeight;
  }
}

// Escape HTML utility
function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

// Start Network and transition to App
async function startNetworkAndEnterApp() {
  try {
    toggleScreen("app");
    await invoke("start_network");
    await refreshContacts();

    try {
      const port = await invoke("get_network_port");
      const label = document.querySelector("#self-profile-badge .profile-label");
      if (label) {
        label.innerText = `My Device (Port: ${port})`;
      }
    } catch (e) {
      console.warn("Failed to get network port", e);
    }
  } catch (err) {
    showError("Failed to start network client: " + err);
  }
}

// Event Bindings
function setupDomEventListeners() {
  // Generate ID
  document.getElementById("btn-generate-id").addEventListener("click", async () => {
    try {
      const token = await invoke("generate_new_identity");
      State.myToken = token;
      
      drawQRPattern("canvas-my-qr", token);
      document.getElementById("input-my-token").value = token;
      
      toggleScreen("onboarding-display");
    } catch (err) {
      showError("Failed to generate identity: " + err);
    }
  });
  
  // Copy Token
  document.getElementById("btn-copy-token").addEventListener("click", () => {
    const input = document.getElementById("input-my-token");
    input.select();
    navigator.clipboard.writeText(input.value)
      .then(() => {
        const btn = document.getElementById("btn-copy-token");
        const originalText = btn.innerText;
        btn.innerText = "Copied!";
        setTimeout(() => btn.innerText = originalText, 2000);
      })
      .catch(err => showError("Failed to copy token: " + err));
  });
  
  // Enter Client
  document.getElementById("btn-enter-client").addEventListener("click", async () => {
    await startNetworkAndEnterApp();
  });
  
  // Add Contact
  document.getElementById("btn-add-contact").addEventListener("click", async () => {
    const nameInput = document.getElementById("input-contact-name");
    const tokenInput = document.getElementById("input-contact-token");
    const portInput = document.getElementById("input-contact-port");
    
    const name = nameInput.value.trim();
    const token = tokenInput.value.trim();
    const portVal = portInput ? portInput.value.trim() : "";
    
    if (!name || !token) {
      showError("Please fill in Name and Token");
      return;
    }
    
    try {
      await invoke("add_contact_token", { token_str: token, display_name: name });
      
      if (portVal) {
        const portNum = parseInt(portVal, 10);
        if (!isNaN(portNum)) {
          const pubKey = await invoke("parse_token", { token_str: token });
          await invoke("inject_peer_address", {
            peer_pub_key: pubKey,
            ip: "127.0.0.1",
            port: portNum
          });
          console.log(`Manually injected loopback address 127.0.0.1:${portNum} for contact ${name}`);
        }
      }
      
      nameInput.value = "";
      tokenInput.value = "";
      if (portInput) portInput.value = "";
      await refreshContacts();
    } catch (err) {
      showError("Failed to add contact: " + err);
    }
  });
  
  // Initiate Handshake
  document.getElementById("btn-chat-handshake").addEventListener("click", async () => {
    if (!State.activeContactPubKey) return;
    const statusText = document.getElementById("chat-status-text");
    statusText.innerText = "Initiating handshake...";
    try {
      await invoke("initiate_chat_handshake", { contact_pub_key: State.activeContactPubKey });
    } catch (err) {
      showError("Handshake failed: " + err);
      statusText.innerText = "Handshake failed";
    }
  });
  
  // Send Message
  const handleSend = async () => {
    const input = document.getElementById("input-chat-message");
    const text = input.value.trim();
    if (!text || !State.activeContactPubKey) return;
    
    try {
      const msgId = await invoke("send_message", {
        contact_pub_key: State.activeContactPubKey,
        content: text
      });
      input.value = "";
      
      // Render outgoing message immediately
      appendMessageToFeed({
        id: msgId,
        sender: [], // Outgoing empty sender
        recipient: State.activeContactPubKey,
        content: text,
        timestamp: Math.floor(Date.now() / 1000),
        is_read: true
      });
    } catch (err) {
      showError("Failed to send message: " + err);
    }
  };
  
  document.getElementById("btn-chat-send").addEventListener("click", handleSend);
  document.getElementById("input-chat-message").addEventListener("keypress", (e) => {
    if (e.key === "Enter") handleSend();
  });
  
  // Profile / Modal
  document.getElementById("btn-show-modal-qr").addEventListener("click", async () => {
    if (!State.myToken) {
      try {
        State.myToken = await invoke("get_my_token");
      } catch (err) {
        showError("Failed to retrieve token: " + err);
        return;
      }
    }
    
    document.getElementById("label-modal-token").innerText = State.myToken;
    drawQRPattern("canvas-modal-qr", State.myToken);
    document.getElementById("qr-modal").classList.remove("hidden");
  });
  
  document.getElementById("btn-close-modal").addEventListener("click", () => {
    document.getElementById("qr-modal").classList.add("hidden");
  });
}

// Tauri Realtime Event Handlers
async function setupTauriListeners() {
  // 1. Peer discovered via mDNS
  await listen("peer_discovered", (event) => {
    const { peer_identity, ip, port } = event.payload;
    const peerHex = arrayToHex(peer_identity);
    
    State.discoveredPeers.set(peerHex, { peer_identity, ip, port });
    
    renderContactsList();
    renderPeersList();
  });
  
  // 2. Incoming secure chat message received
  await listen("message_received", (event) => {
    const { sender_identity, message_id, content, timestamp } = event.payload;
    const senderHex = arrayToHex(sender_identity);
    
    if (senderHex === State.activeContactHex) {
      appendMessageToFeed({
        id: message_id,
        sender: sender_identity,
        recipient: [],
        content: content,
        timestamp: timestamp,
        is_read: true
      });
    } else {
      const count = State.unreadCounts.get(senderHex) || 0;
      State.unreadCounts.set(senderHex, count + 1);
      renderContactsList();
    }
  });

  // 3. Double Ratchet Session Established
  await listen("session_established", (event) => {
    const { peer_identity } = event.payload;
    const peerHex = arrayToHex(peer_identity);
    
    State.sessions.add(peerHex);
    
    if (peerHex === State.activeContactHex) {
      updateChatHeaderStatus(true);
      toggleChatInputs(true);
    }
    renderContactsList();
  });

  // 4. Log integration from engine core
  await listen("log", (event) => {
    const { level, message } = event.payload;
    console.log(`[Loom Core ${level.toUpperCase()}] ${message}`);
  });
}

// Initialize Application
async function initializeApp() {
  try {
    setupDomEventListeners();
    await setupTauriListeners();
    
    const hasIdentity = await invoke("has_identity");
    if (hasIdentity) {
      State.myToken = await invoke("get_my_token");
      await startNetworkAndEnterApp();
    } else {
      toggleScreen("onboarding-setup");
    }
  } catch (err) {
    // If not running inside Tauri (e.g. standard browser) or initialization fails, fallback
    console.error("Initialization failed, falling back to mock onboarding:", err);
    toggleScreen("onboarding-setup");
  }
}

// Run init on load
window.addEventListener("DOMContentLoaded", initializeApp);
