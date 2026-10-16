import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { api, getToken, setToken, setUnauthorizedHandler } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(Boolean(getToken()));

  const logout = useCallback(async () => {
    try {
      if (getToken()) await api.post("/auth/logout/");
    } catch {
      /* token may already be invalid */
    }
    setToken(null);
    setUser(null);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setToken(null);
      setUser(null);
    });
    if (!getToken()) return;
    api
      .get("/auth/me/")
      .then(setUser)
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (username, password) => {
    const data = await api.post("/auth/token/", { username, password });
    setToken(data.token);
    setUser(data.user);
    return data.user;
  }, []);

  const value = useMemo(() => {
    const groups = user?.groups || [];
    return {
      user,
      loading,
      login,
      logout,
      isStaff: Boolean(user?.is_staff),
      canRespond: Boolean(user?.is_staff || groups.includes("responders") || groups.includes("forensics")),
      canUseTerminal: Boolean(user?.is_staff || groups.includes("forensics")),
    };
  }, [user, loading, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
