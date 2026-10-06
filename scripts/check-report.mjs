import {chromium,expect} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const browser=await chromium.launch();
mkdirSync('test-results/browser',{recursive:true});
try {
 for(const width of [1280,390]) {
  const p=await browser.newPage({viewport:{width,height:900}}),errors=[];
  p.on('pageerror',e=>errors.push(e.message));
  await p.goto(pathToFileURL(resolve('evidence/report.html')).href);
  await expect(p.locator('section')).toHaveCount(5);
  expect(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  for(const section of await p.locator('section').all()) {
   await section.locator('summary').focus();await p.keyboard.press('Enter');
   await expect(section.locator('details')).toHaveAttribute('open','');
   await expect(section.locator('pre')).toContainText('provider_rotations');
   await p.keyboard.press('Enter');
  }
  await p.screenshot({path:`test-results/browser/report-${width}.png`,fullPage:true});
  expect(errors).toEqual([]);await p.close();console.log('PASS report',width);
 }
} finally {await browser.close();}
