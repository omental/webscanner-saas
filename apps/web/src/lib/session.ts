import { User } from "@/lib/types";

export type SessionUser = Pick<User, "id" | "email" | "name" | "role" | "status"> & {
  user_id: number;
  organization_id: number | null;
  logged_in: true;
};

const sessionKey = "webscanner.session";

export function getSessionUser(): SessionUser | null {
  if (typeof window === "undefined") {
    return null;
  }

  const value = window.localStorage.getItem(sessionKey);
  if (!value) {
    return null;
  }

  try {
    const user = JSON.parse(value) as Partial<SessionUser>;
    if (
      !user.logged_in ||
      typeof user.id !== "number" ||
      typeof user.user_id !== "number" ||
      typeof user.email !== "string" ||
      typeof user.role !== "string"
    ) {
      window.localStorage.removeItem(sessionKey);
      return null;
    }

    return user as SessionUser;
  } catch {
    window.localStorage.removeItem(sessionKey);
    return null;
  }
}

export function setSessionUser(user: SessionUser) {
  window.localStorage.setItem(sessionKey, JSON.stringify(user));
}

export function clearSessionUser() {
  window.localStorage.removeItem(sessionKey);
}

export function isAdmin(user: SessionUser | null) {
  return user?.role === "admin" || user?.role === "super_admin";
}

export function isSuperAdmin(user: SessionUser | null) {
  return user?.role === "super_admin";
}

export function isTeamMember(user: SessionUser | null) {
  return user?.role === "team_member";
}
