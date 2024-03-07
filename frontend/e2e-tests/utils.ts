import { expect, type BrowserContext, type Page, type TestInfo } from "@playwright/test";

export const signInWithNewUser = async ({
  page,
  context,
  testInfo,
}: {
  page: Page;
  context: BrowserContext;
  testInfo: TestInfo;
}) => {
  const iiPagePromise = context.waitForEvent("page");

  await page.locator("[data-tid=login-button]").click();

  const iiPage = await iiPagePromise;
  await expect(iiPage).toHaveTitle("Internet Identity");

  await iiPage.locator("#registerButton").click();
  await iiPage.locator("[data-action=construct-identity]").click();

  await iiPage.waitForTimeout(10_000);
  await iiPage.locator("input#captchaInput").waitFor();
  const screenshot = await iiPage.screenshot();
  await testInfo.attach('screenshot', { body: screenshot, contentType: 'image/png' });
  await iiPage.locator("input#captchaInput").fill("a");
  await iiPage.locator("#confirmRegisterButton").click();

  await iiPage.locator("#displayUserContinue").click();

  await iiPage.waitForEvent("close");
  expect(iiPage.isClosed()).toBe(true);
};