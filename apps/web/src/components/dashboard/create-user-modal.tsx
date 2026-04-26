"use client";

import { FormEvent, useEffect, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { getSessionUser, isSuperAdmin } from "@/lib/session";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Organization, UserRole } from "@/lib/types";

type CreateUserModalProps = {
  onCreated?: () => void | Promise<void>;
};

export function CreateUserModal({ onCreated }: CreateUserModalProps) {
  const [open, setOpen] = useState(false);
  const sessionUser = getSessionUser();
  const superAdmin = isSuperAdmin(sessionUser);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<UserRole>("team_member");
  const [organizationId, setOrganizationId] = useState("");
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [status, setStatus] = useState("active");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !superAdmin) {
      return;
    }
    void apiClient.listOrganizations().then(setOrganizations);
  }, [open, superAdmin]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError(null);
      await apiClient.createUser({
        name,
        email,
        password,
        role,
        organization_id:
          role === "super_admin"
            ? null
            : superAdmin
              ? Number(organizationId)
              : sessionUser?.organization_id ?? null,
        status
      });
      setName("");
      setEmail("");
      setPassword("");
      setRole("team_member");
      setOrganizationId("");
      setStatus("active");
      setOpen(false);
      await onCreated?.();
    } catch {
      setError("Unable to create user.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <Button onClick={() => setOpen(true)}>Create user</Button>

      {open ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 px-4 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-[1.75rem] border border-white/10 bg-slate-950 p-6 shadow-2xl shadow-cyan-950/20">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">
                  Team Access
                </p>
                <h3 className="mt-3 text-2xl font-semibold text-white">
                  Create user
                </h3>
                <p className="mt-3 text-sm leading-6 text-slate-300">
                  Create an account within the allowed organization scope.
                </p>
              </div>
              <Button variant="ghost" onClick={() => setOpen(false)}>
                Close
              </Button>
            </div>

            <form className="mt-6 space-y-5" onSubmit={handleSubmit}>
              <div className="grid gap-5 md:grid-cols-2">
                <Input
                  label="Full name"
                  placeholder="Avery Khan"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  required
                />
                <Input
                  label="Email address"
                  type="email"
                  placeholder="avery@webscanner.dev"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                />
                <Input
                  label="Password"
                  type="password"
                  placeholder="temporary-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />
              </div>
              <div className="grid gap-5 md:grid-cols-2">
                <Select
                  label="Role"
                  value={role}
                  onChange={(event) => setRole(event.target.value as UserRole)}
                >
                  {superAdmin ? <option value="admin">Admin</option> : null}
                  <option value="team_member">Team member</option>
                  {superAdmin ? (
                    <option value="super_admin">Super admin</option>
                  ) : null}
                </Select>
                <Select
                  label="Status"
                  value={status}
                  onChange={(event) => setStatus(event.target.value)}
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </Select>
              </div>
              {superAdmin && role !== "super_admin" ? (
                <Select
                  label="Organization"
                  value={organizationId}
                  onFocus={async () => {
                    if (organizations.length === 0) {
                      setOrganizations(await apiClient.listOrganizations());
                    }
                  }}
                  onChange={(event) => setOrganizationId(event.target.value)}
                  required
                >
                  <option value="">Choose organization</option>
                  {organizations.map((organization) => (
                    <option key={organization.id} value={organization.id}>
                      {organization.name}
                    </option>
                  ))}
                </Select>
              ) : null}
              {error ? <p className="text-sm text-rose-300">{error}</p> : null}
              <div className="flex flex-col gap-3 border-t border-white/10 pt-5 sm:flex-row sm:justify-end">
                <Button variant="secondary" onClick={() => setOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={submitting}>
                  {submitting ? "Creating..." : "Create user"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </>
  );
}
