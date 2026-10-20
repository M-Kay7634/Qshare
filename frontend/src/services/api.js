
const API_BASE_URL = "http://127.0.0.1:8000";

export async function apiRequest(path, options = {}) {
  const token = localStorage.getItem("qshare_token");

  const headers = {
    ...(options.body instanceof FormData
      ? {}
      : { "Content-Type": "application/json" }),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const detail =
      typeof data === "object" && data !== null
        ? data.detail || data.message
        : data;

    const error = new Error(detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }

  return data;
}

export async function registerUser({ email, password }) {
  return apiRequest("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function loginUser({ email, password }) {
  const data = await apiRequest("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });

  if (data.access_token) {
    localStorage.setItem("qshare_token", data.access_token);
  }

  return data;
}

export async function getCurrentUser() {
  return apiRequest("/api/auth/me");
}

export function logoutUser() {
  localStorage.removeItem("qshare_token");
}



// Make sure the logged-in user has an ML-KEM key pair before encrypting.
export async function ensureKeyPair() {
  try {
    await apiRequest("/api/hybrid/keys/me");
    return; // key pair already exists
  } catch (error) {
    if (error.status !== 404) throw error;
  }

  try {
    await apiRequest("/api/hybrid/keys/me", { method: "POST" });
  } catch (error) {
    // 409 = a key pair was created a moment ago. That is fine.
    if (error.status !== 409) throw error;
  }
}

export async function uploadEncryptedFile(file) {
  await ensureKeyPair();

  const formData = new FormData();
  formData.append("file", file);

  return apiRequest("/api/files/encrypt", {
    method: "POST",
    body: formData,
  });
}

export async function getMyFiles() {
  return apiRequest("/api/files");
}

export async function downloadDecryptedFile(fileId, filename) {
  const token = localStorage.getItem("qshare_token");

  const response = await fetch(
    `${API_BASE_URL}/api/files/${encodeURIComponent(fileId)}/download`,
    {
      headers: token
        ? { Authorization: `Bearer ${token}` }
        : {},
    }
  );

  if (!response.ok) {
    let message = "Download failed.";

    try {
      const data = await response.json();
      message = data.detail || message;
    } catch {
      // Keep the default message if the response isn't JSON.
    }

    throw new Error(message);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename || "download.bin";
  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
