import { execSync } from "child_process";
import { defineConfig } from "astro/config";

/**
 * Read a canister ID from dfx's local state
 */
export const readCanisterId = (canisterName) => {
  const command = `dfx canister id ${canisterName}`;
  try {
    const stdout = execSync(command);
    return stdout.toString().trim();
  } catch (e) {
    throw Error(
      `Could not get canister ID for '${canisterName}' with command '${command}', was the canister deployed? ${e}`
    );
  }
};

// https://astro.build/config
export default defineConfig({
  vite: {
    optimizeDeps: {
      esbuildOptions: {
        define: {
          // Needed because the agent uses `global` to build the Actor
          global: "globalThis",
        },
      },
    },
    plugins: [
      {
        name: "Add canister id header",
        configureServer(server) {
          const canisterId = readCanisterId("early_adopter");
          server.middlewares.use((_req, res, next) => {
            res.setHeader("x-ic-canister-id", canisterId);
            // Ensure the browser accepts the response
            res.setHeader("access-control-allow-headers", "*");
            res.setHeader("access-control-allow-origin", "*");
            res.setHeader("access-control-expose-headers", "*");
            next();
          });
        }
      }
    ]
  },
});
