import { expect } from '@playwright/test';
import {testWithII} from '@dfinity/internet-identity-playwright';

// Needs to match the event created in the backend.
const eventName = "TEST";
const eventCode = "testcode"

testWithII("use registers with Internet Identity and is redirected to a success page", async ({ iiPage, page, context }) => {
  await page.goto(`/?e=${eventName}&c=${eventCode}`);
  await expect(page).toHaveTitle(/Proof of Attendance Campaign/);

  await iiPage.signInWithNewIdentity({ selector: "[data-tid=login-button]"});
  
  expect(await page.getByTestId("success-page-title").textContent()).toBe("Congratulations!");
});
