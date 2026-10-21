import { createClient } from '@supabase/supabase-js';

// No "use client": in the Next.js app router this runs on the server.
export async function deleteAccount(id: string) {
  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL ?? '', process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');
  await admin.auth.admin.deleteUser(id);
}
