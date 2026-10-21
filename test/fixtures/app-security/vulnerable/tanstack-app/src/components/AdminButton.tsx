import { createClient } from '@supabase/supabase-js';

// Component code ships to the browser in TanStack Start, whatever the folder.
const admin = createClient(import.meta.env.VITE_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');

export function AdminButton() {
  return null;
}
