import { createClient } from '@supabase/supabase-js';

// An AI assistant "fixed" a permissions error by switching to the service role key.
export const admin = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);
