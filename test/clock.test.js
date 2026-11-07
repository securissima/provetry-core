import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reportingClock, humanDuration } from '../src/clock.js';
import { cvss3Score, ratingOf } from '../src/vuln/cvss.js';

test('Article 14 deadlines for an exploited vulnerability', () => {
  const c = reportingClock({ awareAt: new Date('2026-11-06T09:30:00Z'), now: new Date('2026-11-06T12:00:00Z') });
  assert.deepEqual(c.steps.map((s) => s.due?.toISOString() ?? null), ['2026-11-07T09:30:00.000Z', '2026-11-09T09:30:00.000Z', null]);
  const f = reportingClock({ awareAt: new Date('2026-11-06T09:30:00Z'), fixAt: new Date('2026-11-20T00:00:00Z') });
  assert.equal(f.steps[2].due.toISOString(), '2026-12-04T00:00:00.000Z');
});

test('Article 14 deadlines for a severe incident: final report one month after the notification', () => {
  const c = reportingClock({ kind: 'incident', awareAt: new Date('2027-01-28T10:00:00Z') });
  assert.equal(c.steps[1].due.toISOString(), '2027-01-31T10:00:00.000Z');
  assert.equal(c.steps[2].due.toISOString(), '2027-02-28T10:00:00.000Z', 'clamped to the end of a shorter month');
  assert.throws(() => reportingClock({ awareAt: new Date('nope') }));
});

test('durations', () => {
  assert.equal(humanDuration(26 * 3600e3 + 5 * 60e3), '1 d 2 h');
  assert.equal(humanDuration(-(3 * 3600e3)), 'overdue by 3 h 0 min');
  assert.equal(humanDuration(59 * 60e3), '59 min');
});

test('CVSS 3.x base scores match the FIRST calculator', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 5.5);
  assert.equal(cvss3Score('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('CVSS:4.0/AV:N/AC:L'), null);
  assert.equal(cvss3Score('CVSS:3.1/AV:N'), null);
  assert.equal(ratingOf(9), 'critical');
  assert.equal(ratingOf(null), 'unknown');
});
