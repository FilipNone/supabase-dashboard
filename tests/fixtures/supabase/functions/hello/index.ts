// Synthetic test function, so that Studio's Edge Functions page has
// something to list and the router has a function to run. It reads no
// input and returns a fixed body.

Deno.serve(() =>
  new Response(JSON.stringify({ fixture: 'hello' }), {
    headers: { 'Content-Type': 'application/json' },
  })
)
