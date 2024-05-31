const EVENT_NAME_PARAM_KEY = "e";
const EVENT_CODE_PARAM_KEY = "c";
export const getEventFromParams = () => {
  const url = new URL(window.location.href);
  const params = url.searchParams;
  const eventName = params.get(EVENT_NAME_PARAM_KEY);
  const code = params.get(EVENT_CODE_PARAM_KEY);
  if (!eventName || !code) {
    return undefined;
  }
  return {
    eventName,
    code
  }
};