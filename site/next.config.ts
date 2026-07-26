import type { NextConfig } from "next";

const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value: "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  },
  { key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=()" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
  // The hosted skill's content is inlined as a generated TS constant
  // (app/api/invoke/[skillId]/skill-content.ts), so it is bundled into the
  // serverless function and no outputFileTracingIncludes entry is needed.
  // If you switch the route to fs.readFileSync of skill.md instead, add:
  //   outputFileTracingIncludes: {
  //     '/api/invoke/[skillId]': ['./app/api/invoke/[skillId]/skill.md'],
  //   },
};

export default nextConfig;
