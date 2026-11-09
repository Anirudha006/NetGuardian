import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check auth state on load via /api/auth/me using HttpOnly cookie ng_session
  useEffect(() => {
    // Clean up any legacy localStorage token
    localStorage.removeItem('ng_token');

    api.getCurrentUser()
      .then(userData => {
        setUser(userData);
      })
      .catch(() => {
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (username, password) => {
    const data = await api.login(username, password);
    const userInfo = { username: data.username, role: data.role };
    setUser(userInfo);
    return userInfo;
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch (_) {}
    setUser(null);
  };

  const isAdmin = user?.role === 'ADMIN';

  return (
    <AuthContext.Provider value={{
      token: !!user, // boolean flag for backwards compatibility with if (!token)
      isAuthenticated: !!user,
      user,
      login,
      logout,
      isAdmin,
      loading
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
