import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const RETENTION_DAYS = 7;
const BATCH_SIZE = 100;
const MAX_BATCHES_PER_RUN = 20;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  if (!SERVICE_ROLE_KEY || req.headers.get("authorization") !== `Bearer ${SERVICE_ROLE_KEY}`) {
    return new Response("Not found", { status: 404 });
  }
  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();

    let deleted = 0;
    for (let batch = 0; batch < MAX_BATCHES_PER_RUN; batch++) {
      const { data: old, error: selErr } = await supabase
        .from("attachments")
        .select("id, storage_path")
        .lt("created_at", cutoff)
        .order("created_at", { ascending: true })
        .limit(BATCH_SIZE);
      if (selErr) throw selErr;
      if (!old?.length) break;

      const paths = old.map((a) => a.storage_path).filter(Boolean) as string[];
      if (paths.length) {
        const { error: rmErr } = await supabase.storage.from("attachments").remove(paths);
        if (rmErr) throw rmErr;
      }
      const { error: delErr } = await supabase.from("attachments").delete().in("id", old.map((a) => a.id));
      if (delErr) throw delErr;
      deleted += old.length;
      if (old.length < BATCH_SIZE) break;
    }
    return new Response(JSON.stringify({ deleted, batch_limit_reached: deleted === BATCH_SIZE * MAX_BATCHES_PER_RUN }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("cleanup-old-attachments: batch failed");
    return new Response(JSON.stringify({ error: "Cleanup failed; it can be safely retried." }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});
