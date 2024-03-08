print_help() {
  cat <<-EOF
	Generates the actor needed to talk to the canister.
	EOF
}

# Generate the actor
dfx generate early_adopter
# We are not using the default `createActor` function because we want to control the fetchRootKey with an env var.
# We need to remove the code because it uses process.env which is not available in the browser.
# We use a custom `createActor` from "src/utils/actor" to create the actor.
# We still need to export the idlFactory from the generated file.
echo 'export { idlFactory } from "./early_adopter.did.js";' > "./src/declarations/early_adopter/index.js"
