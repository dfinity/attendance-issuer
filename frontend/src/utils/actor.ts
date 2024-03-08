import { Actor, HttpAgent, type ActorSubclass } from "@dfinity/agent";
import { idlFactory } from "../declarations/early_adopter";
import type { _SERVICE } from '../declarations/early_adopter/early_adopter.did';


export const createActor = async (
  { canisterId, agent, fetchRootKey }:
  { canisterId: string, agent: HttpAgent, fetchRootKey: boolean }
): Promise<ActorSubclass<_SERVICE>> => {
  // Fetch root key for certificate validation during development
  if (fetchRootKey) {
    try {
      await agent.fetchRootKey()
    } catch (err) {
      console.warn(
        "Unable to fetch root key. Check to ensure that your local replica is running"
      );
      console.error(err);
    }
  }

  // Creates an actor with using the candid interface and the HttpAgent
  return Actor.createActor<_SERVICE>(idlFactory, {
    agent,
    canisterId,
  });
};