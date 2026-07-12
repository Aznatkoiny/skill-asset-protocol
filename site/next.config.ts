import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The hosted skill's content is inlined as a generated TS constant
  // (app/api/invoke/[skillId]/skill-content.ts), so it is bundled into the
  // serverless function and no outputFileTracingIncludes entry is needed.
  // If you switch the route to fs.readFileSync of skill.md instead, add:
  //   outputFileTracingIncludes: {
  //     '/api/invoke/[skillId]': ['./app/api/invoke/[skillId]/skill.md'],
  //   },
};

export default nextConfig;
