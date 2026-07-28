import { expect, test } from '@playwright/test';

test('complete synthetic dashboard flow without exposing control token', async ({ page }) => {
  test.setTimeout(240_000);

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await expect(page.getByTestId('guided-flow')).toBeVisible();

  await page.getByRole('button', { name: /Generate synthetic demo/i }).click();
  await expect(page.getByText(/Synthetic demo generated/i)).toBeVisible();

  await page.getByRole('button', { name: /Materialize features/i }).click();
  await expect(page.getByText(/Feature windows materialized/i)).toBeVisible();

  await page.getByRole('button', { name: /Create dataset/i }).click();
  await expect(page.getByText(/Dataset snapshot created/i)).toBeVisible();

  await page.getByRole('button', { name: /Train models/i }).click();
  await expect(page.getByText(/Training completed/i)).toBeVisible({ timeout: 180_000 });

  await page.getByRole('button', { name: /Promote champion/i }).click();
  await expect(page.getByRole('dialog')).toContainText(/Promote champion/i);
  await page.getByRole('dialog').getByRole('button', { name: /^Promote$/i }).click();
  await expect(page.getByText(/Champion promoted/i)).toBeVisible();

  await page.getByRole('button', { name: /Run detection/i }).click();
  await expect(page.getByText(/Detection completed/i)).toBeVisible({ timeout: 90_000 });

  await page.getByRole('button', { name: /Open findings/i }).click();
  await expect(page.getByRole('heading', { name: 'Findings', level: 1 })).toBeVisible();
  await page.locator('.findingsTable button').filter({ hasText: 'open' }).first().click();
  await expect(page.getByText(/Numeric evidence and decisions/i)).toBeVisible();

  await page.getByRole('button', { name: 'Acknowledge', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText(/acknowledge finding/i);
  await page.getByRole('dialog').getByRole('button', { name: /^acknowledge$/i }).click();
  await expect(page.getByText(/Finding status updated/i)).toBeVisible();

  await page.getByRole('button', { name: /Create suppression/i }).click();
  await page.getByRole('dialog').getByRole('button', { name: /Create suppression/i }).click();
  await expect(page.getByText(/Suppression created/i)).toBeVisible();

  await page
    .locator('section:has(h2:has-text("Suppressions")) button:not([disabled])')
    .filter({ hasText: 'Revoke' })
    .last()
    .click();
  await page.getByRole('dialog').getByRole('button', { name: /^Revoke$/i }).click();
  await expect(page.getByText(/Suppression revoked/i)).toBeVisible();

  await page.getByRole('button', { name: 'Runtime' }).click();
  await expect(page.getByRole('heading', { name: 'Runtime', level: 1 })).toBeVisible();
  await page.getByRole('button', { name: /Verify installation/i }).click();
  await expect(page.getByText(/Installation verified/i)).toBeVisible();

  const bodyText = await page.locator('body').innerText();
  expect(bodyText).not.toContain('X-SentinelUEBA-Control-Token');
  expect(bodyText).not.toContain('control.token');
});
