import { createFileRoute } from '@tanstack/react-router';
import { createClient } from '@supabase/supabase-js';

// A server route: only the handlers run, and only on the server.
export const Route = createFileRoute('/hooks/webhook')({
  server: {
    handlers: {
      POST: async () => {
        const admin = createClient(process.env.SUPABASE_URL ?? '', process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');
        await admin.from('events').insert({ kind: 'webhook' });
        return new Response('ok');
      },
    },
  },
});
