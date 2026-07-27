// Minimal starting point — replace with your app. The GATEWAY_URL and
// CREDENTIAL_HANDLE come from your emseapea workspace (get_workspace).
export default {
  async fetch() {
    return new Response('Hello from a governed emseapea app');
  },
};
