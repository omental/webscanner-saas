import { AuthForm } from "@/components/auth/auth-form";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

export function ProfileForm() {
  return (
    <div className="rounded-[1.75rem] border border-white/10 bg-white/5 p-6">
      <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">
        Profile Settings
      </p>
      <h3 className="mt-4 text-2xl font-semibold text-white">
        Update profile
      </h3>
      <div className="mt-6 max-w-2xl">
        <AuthForm
          submitLabel="Save changes"
          helperText="This form is UI-only for now. Persisting profile updates will be added when authentication and backend APIs are connected."
        >
          <div className="grid gap-5 md:grid-cols-2">
            <Input label="Full name" placeholder="Muba Tasnim" readOnly />
            <Input
              label="Email address"
              type="email"
              placeholder="muba@webscanner.dev"
              readOnly
            />
          </div>
          <Input label="Job title" placeholder="Security Lead" readOnly />
          <Select label="Default role" defaultValue="admin" disabled>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </Select>
        </AuthForm>
      </div>
    </div>
  );
}

