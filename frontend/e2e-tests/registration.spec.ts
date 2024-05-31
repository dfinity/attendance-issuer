import { test, expect } from '@playwright/test';
import { signInWithNewUser } from './utils';

const eventName = "TEST";
const eventCode = "TESTCODE"

test("use registers with Internet Identity and is redirected to a success page", async ({ page, context }) => {
  await page.goto(`/?e=${eventName}&c=${eventCode}`);
  await expect(page).toHaveTitle(/Proof of Attendance Campaign/);

  await signInWithNewUser({ page, context });
  
  expect(await page.getByTestId("success-page-title").textContent()).toBe("Congratulations!");
});
