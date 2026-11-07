// SPDX-License-Identifier: AGPL-3.0-only
// The reporting deadlines of Article 14 of the Cyber Resilience Act (Regulation (EU) 2024/2847), which apply to
// manufacturers from 11 September 2026 (Article 71(2)). Notifications go to the CSIRT designated as coordinator and to ENISA,
// through ENISA's single reporting platform.
//
//  - Actively exploited vulnerability in your product (Art. 14(2)): early warning within 24 hours of becoming
//    aware, notification within 72 hours, final report no later than 14 days after a corrective or mitigating
//    measure is available.
//  - Severe incident having an impact on the security of your product (Art. 14(4)): early warning within
//    24 hours, notification within 72 hours, final report within one month after the notification was submitted.
//
// This computes dates. It does not decide whether something must be reported: that is your assessment.

const H = 3600 * 1000;

function addMonths(date, n) {
  const d = new Date(date);
  const day = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() + n);
  const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, last));
  return d;
}

/**
 * @param {{ kind?: 'vulnerability'|'incident', awareAt: Date, fixAt?: Date|null, notifiedAt?: Date|null, now?: Date }} input
 * @returns {{ kind, awareAt, steps: Array<{ step, article, due: Date|null, note, remainingMs: number|null }> }}
 */
export function reportingClock({ kind = 'vulnerability', awareAt, fixAt = null, notifiedAt = null, now = new Date() }) {
  if (!(awareAt instanceof Date) || Number.isNaN(awareAt.getTime())) throw new Error('a valid start date is needed');
  const t = awareAt.getTime();
  const notif = new Date(t + 72 * H);
  const steps = [
    { step: 'Early warning', article: kind === 'incident' ? 'Art. 14(4)(a)' : 'Art. 14(2)(a)', due: new Date(t + 24 * H), note: '' },
    { step: 'Notification', article: kind === 'incident' ? 'Art. 14(4)(b)' : 'Art. 14(2)(b)', due: notif, note: '' },
  ];
  if (kind === 'incident') {
    // The month runs from the day the notification was actually submitted; without that date, from the latest
    // day it could have been, which gives the latest possible final-report date.
    const sent = notifiedAt instanceof Date && !Number.isNaN(notifiedAt.getTime()) ? notifiedAt : null;
    steps.push({ step: 'Final report', article: 'Art. 14(4)(c)', due: addMonths(sent ?? notif, 1), note: sent ? 'one month after the notification' : 'at the latest: one month after the notification is submitted' });
  } else if (fixAt instanceof Date && !Number.isNaN(fixAt.getTime())) {
    steps.push({ step: 'Final report', article: 'Art. 14(2)(c)', due: new Date(fixAt.getTime() + 14 * 24 * H), note: '14 days after the corrective measure became available' });
  } else {
    steps.push({ step: 'Final report', article: 'Art. 14(2)(c)', due: null, note: 'due 14 days after a corrective or mitigating measure is available' });
  }
  for (const s of steps) s.remainingMs = s.due ? s.due.getTime() - now.getTime() : null;
  return { kind, awareAt, steps };
}

/** "2 d 4 h", "5 h 10 min", "overdue by 3 h". */
export function humanDuration(ms) {
  const neg = ms < 0;
  let m = Math.round(Math.abs(ms) / 60000);
  const d = Math.floor(m / 1440);
  m -= d * 1440;
  const h = Math.floor(m / 60);
  m -= h * 60;
  const s = d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
  return neg ? `overdue by ${s}` : s;
}
