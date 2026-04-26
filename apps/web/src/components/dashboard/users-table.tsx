"use client";

import { useEffect, useMemo, useState } from "react";

import { Organization, User } from "@/lib/types";
import { getSessionUser, isSuperAdmin, SessionUser } from "@/lib/session";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

type UsersTableProps = {
  users: User[];
  loading: boolean;
  error: string | null;
  onRefresh: () => void | Promise<void>;
  onUpdateUser: (
    userId: number,
    payload: {
      name?: string;
      email?: string;
      password?: string;
      role?: string;
      organization_id?: number | null;
      status?: string;
    }
  ) => void | Promise<void>;
  onDeleteUser: (userId: number) => void | Promise<void>;
  organizations: Organization[];
};

function statusTone(status: string) {
  return status.toLowerCase() === "active" ? "success" : "warning";
}

function formatRole(role: string) {
  if (role === "super_admin") return "Super Admin";
  if (role === "team_member") return "Team Member";
  return "Admin";
}

export function UsersTable({
  users,
  loading,
  error,
  onRefresh,
  onUpdateUser,
  onDeleteUser,
  organizations,
}: UsersTableProps) {
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [editingUserId, setEditingUserId] = useState<number | null>(null);

  const [drafts, setDrafts] = useState<
    Record<
      number,
      {
        name: string;
        email: string;
        role: string;
        status: string;
        password: string;
        organization_id: string;
      }
    >
  >({});

  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [rowError, setRowError] = useState<string | null>(null);

  useEffect(() => {
    setSessionUser(getSessionUser());
  }, []);

  const superAdmin = isSuperAdmin(sessionUser);

  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase();

    return users.filter((user) => {
      const matchesSearch =
        !query ||
        user.name.toLowerCase().includes(query) ||
        user.email.toLowerCase().includes(query) ||
        (user.organization_name || "").toLowerCase().includes(query);

      const matchesRole = roleFilter === "all" || user.role === roleFilter;
      const matchesStatus =
        statusFilter === "all" || user.status === statusFilter;

      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [users, search, roleFilter, statusFilter]);

  function draftFor(user: User) {
    return (
      drafts[user.id] ?? {
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
        password: "",
        organization_id: user.organization_id?.toString() ?? "",
      }
    );
  }

  function updateDraft(
    user: User,
    field: "name" | "email" | "role" | "status" | "password" | "organization_id",
    value: string
  ) {
    setDrafts((current) => ({
      ...current,
      [user.id]: {
        ...draftFor(user),
        [field]: value,
      },
    }));
  }

  function canEditUser(user: User) {
    if (superAdmin) return true;
    return user.role === "team_member";
  }

  function canDeleteUser(user: User) {
    const isSelf = sessionUser?.id === user.id;

    if (isSelf) return false;
    if (superAdmin) return true;

    return user.role === "team_member";
  }

  async function saveUser(user: User) {
    const draft = draftFor(user);

    try {
      setRowError(null);

      await onUpdateUser(user.id, {
        name: draft.name,
        email: draft.email,
        role: superAdmin ? draft.role : undefined,
        organization_id:
          superAdmin && draft.role !== "super_admin"
            ? draft.organization_id
              ? Number(draft.organization_id)
              : null
            : superAdmin && draft.role === "super_admin"
              ? null
              : undefined,
        status: draft.status,
        ...(draft.password ? { password: draft.password } : {}),
      });

      setEditingUserId(null);
      setDrafts((current) => {
        const next = { ...current };
        delete next[user.id];
        return next;
      });
    } catch {
      setRowError("Unable to update user.");
    }
  }

  async function removeUser(user: User) {
    if (!canDeleteUser(user)) return;

    const confirmed = window.confirm(
      `Delete ${user.name || user.email}? This action cannot be undone.`
    );

    if (!confirmed) return;

    try {
      setRowError(null);
      await onDeleteUser(user.id);
    } catch {
      setRowError("Unable to delete user. Remove related targets or scans first.");
    }
  }

  const inputClass =
    "rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100";

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 px-6 py-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-sm font-semibold text-slate-950">Users</p>
            <p className="mt-1 text-sm text-slate-500">
              Manage user roles, status, organizations, and password resets.
            </p>
          </div>

          <Button variant="secondary" onClick={() => void onRefresh()}>
            Refresh
          </Button>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-[1fr_180px_180px]">
          <input
            className={inputClass}
            placeholder="Search name, email, or organization..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          <select
            className={inputClass}
            value={roleFilter}
            onChange={(event) => setRoleFilter(event.target.value)}
          >
            <option value="all">All roles</option>
            <option value="super_admin">Super Admin</option>
            <option value="admin">Admin</option>
            <option value="team_member">Team Member</option>
          </select>

          <select
            className={inputClass}
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </div>
      </div>

      {loading ? (
        <p className="px-6 py-5 text-sm text-slate-500">Loading users...</p>
      ) : error ? (
        <p className="px-6 py-5 text-sm text-red-600">{error}</p>
      ) : filteredUsers.length === 0 ? (
        <div className="px-6 py-10 text-center">
          <p className="text-sm font-medium text-slate-900">No users found.</p>
          <p className="mt-1 text-sm text-slate-500">
            Try changing your search or filters.
          </p>
        </div>
      ) : (
        <>
          {rowError ? (
            <p className="border-b border-red-100 bg-red-50 px-6 py-3 text-sm text-red-700">
              {rowError}
            </p>
          ) : null}

          <div className="divide-y divide-slate-100">
            {filteredUsers.map((user) => {
              const editing = editingUserId === user.id;
              const draft = draftFor(user);
              const isSelf = sessionUser?.id === user.id;
              const canEdit = canEditUser(user);
              const canDelete = canDeleteUser(user);

              return (
                <div key={user.id} className="p-6 hover:bg-slate-50/60">
                  <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="font-semibold text-slate-950">
                          {user.name}
                        </p>

                        {isSelf ? (
                          <span className="rounded-full bg-blue-50 px-3 py-1 text-xs font-medium text-blue-700">
                            You
                          </span>
                        ) : null}

                        <Badge tone={statusTone(user.status)}>
                          {user.status}
                        </Badge>

                        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700">
                          {formatRole(user.role)}
                        </span>
                      </div>

                      <p className="mt-1 text-sm text-slate-500">
                        {user.email}
                      </p>

                      {superAdmin ? (
                        <p className="mt-1 text-xs text-slate-400">
                          Organization: {user.organization_name ?? "Platform"}
                        </p>
                      ) : null}
                    </div>

                    {!editing ? (
                      <div className="flex flex-wrap gap-2">
<button
  type="button"
  onClick={() => setEditingUserId(user.id)}
  disabled={!canEdit}
  className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 hover:text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
>
  Edit
</button>

<button
  type="button"
  onClick={() => void removeUser(user)}
  disabled={!canDelete}
  className="rounded-lg border border-red-200 bg-white px-3 py-2 text-sm font-medium text-red-600 shadow-sm transition hover:bg-red-50 hover:text-red-700 disabled:cursor-not-allowed disabled:opacity-40"
>
  Delete
</button>
                      </div>
                    ) : null}
                  </div>

                  {editing ? (
                    <div className="mt-5 rounded-xl border border-slate-200 bg-white p-4">
                      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                        <input
                          className={inputClass}
                          value={draft.name}
                          placeholder="Name"
                          onChange={(event) =>
                            updateDraft(user, "name", event.target.value)
                          }
                        />

                        <input
                          className={inputClass}
                          type="email"
                          value={draft.email}
                          placeholder="Email"
                          onChange={(event) =>
                            updateDraft(user, "email", event.target.value)
                          }
                        />

                        <input
                          className={inputClass}
                          type="password"
                          placeholder="New password"
                          value={draft.password}
                          onChange={(event) =>
                            updateDraft(user, "password", event.target.value)
                          }
                        />

                        <select
                          className={inputClass}
                          value={draft.role}
                          onChange={(event) =>
                            updateDraft(user, "role", event.target.value)
                          }
                          disabled={!superAdmin}
                        >
                          {superAdmin ? (
                            <option value="super_admin">Super Admin</option>
                          ) : null}
                          <option value="admin">Admin</option>
                          <option value="team_member">Team Member</option>
                        </select>

                        <select
                          className={inputClass}
                          value={draft.status}
                          onChange={(event) =>
                            updateDraft(user, "status", event.target.value)
                          }
                        >
                          <option value="active">Active</option>
                          <option value="inactive">Inactive</option>
                        </select>

                        {superAdmin && draft.role !== "super_admin" ? (
                          <select
                            className={inputClass}
                            value={draft.organization_id}
                            onChange={(event) =>
                              updateDraft(
                                user,
                                "organization_id",
                                event.target.value
                              )
                            }
                          >
                            <option value="">Choose organization</option>
                            {organizations.map((organization) => (
                              <option
                                key={organization.id}
                                value={organization.id}
                              >
                                {organization.name}
                              </option>
                            ))}
                          </select>
                        ) : null}
                      </div>

                      <div className="mt-4 flex flex-wrap gap-2">
                        <Button
                          className="px-3 py-2"
                          onClick={() => void saveUser(user)}
                        >
                          Save
                        </Button>

                        <Button
                          variant="secondary"
                          className="px-3 py-2"
                          onClick={() => {
                            setEditingUserId(null);
                            setDrafts((current) => {
                              const next = { ...current };
                              delete next[user.id];
                              return next;
                            });
                          }}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}