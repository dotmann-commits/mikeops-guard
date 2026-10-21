import { createClient } from '@supabase/supabase-js';

// Serverless function: runs on the server, never shipped to the browser.
export const admin = createClient(process.env.SUPABASE_URL ?? '', process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');
