"use client";

import { useEffect, useState } from "react";

import { CreateUserModal } from "@/components/dashboard/create-user-modal";
import { UsersTable } from "@/components/dashboard/users-table";
import { apiClient } from "@/lib/api-client";
import { Organization, User } from "@/lib/types";
import { getSessionUser, isSuperAdmin } from "@/lib/session";

export function UsersManager() {
  const [users, setUsers] = useState<User[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadUsers() {
    try {
      setLoading(true);
      setError(null);

      const sessionUser = getSessionUser();

      const [data, nextOrganizations] = await Promise.all([
        apiClient.listUsers(),
        isSuperAdmin(sessionUser)
          ? apiClient.listOrganizations()
          : Promise.resolve([]),
      ]);

      setUsers(Array.isArray(data) ? data : []);
      setOrganizations(Array.isArray(nextOrganizations) ? nextOrganizations : []);
    } catch (err) {
      console.error("Failed to load users", err);
      setError("Unable to load users right now.");
    } finally {
      setLoading(false);
    }
  }

  async function handleUpdateUser(
    userId: number,
    payload: {
      name?: string;
      email?: string;
      password?: string;
      role?: string;
      organization_id?: number | null;
      status?: string;
    }
  ) {
    await apiClient.updateUser(userId, payload);
    await loadUsers();
  }

  async function handleDeleteUser(userId: number) {
    await apiClient.deleteUser(userId);
    await loadUsers();
  }

  useEffect(() => {
    void loadUsers();
  }, []);

  return (
    <section className="space-y-6">
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:flex-row sm:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Team Management
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            Users and access
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
            Create users, update roles and status, or remove accounts.
          </p>
        </div>

        <CreateUserModal onCreated={loadUsers} />
      </div>

      <UsersTable
        users={users}
        loading={loading}
        error={error}
        onRefresh={loadUsers}
        onUpdateUser={handleUpdateUser}
        onDeleteUser={handleDeleteUser}
        organizations={organizations}
      />
    </section>
  );
}