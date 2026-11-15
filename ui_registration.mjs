// Reviewed flat UI registration adapter; never invokes a test callback.
export function createRegistry() {
  const entries = [];
  let sealed = false;
  function register(name, fn) {
    if (sealed || arguments.length !== 2 || typeof name !== 'string' || !name ||
        name.length > 1024 || typeof fn !== 'function' || fn.length > 1 ||
        entries.some(x => x.name === name)) throw new Error('UNSUPPORTED_UI_REGISTRATION');
    entries.push(Object.freeze({name, fn}));
    if (entries.length > 100000) throw new Error('UI_REGISTRATION_BOUND');
    return undefined;
  }
  function seal() {
    if (sealed) throw new Error('UI_REGISTRATION_ALREADY_SEALED');
    sealed = true;
    return Object.freeze(entries.slice());
  }
  return Object.freeze({register, seal});
}
const registry = createRegistry();
export default registry.register;
export const sealRegistration = registry.seal;
