
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

    throw new Error(detail || `Request failed (${response.status})`);
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
