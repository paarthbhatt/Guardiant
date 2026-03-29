# 📊 Growth Monitoring Dashboard

**Track:** GitHub stars, npm downloads, traffic, conversions

---

## 🎯 Key Metrics to Track

### Product Metrics
1. **GitHub Stars** - Brand awareness
2. **NPM Downloads** - Actual usage
3. **CLI Scans** - Active engagement
4. **Findings per Scan** - Product value
5. **Error Rate** - Product quality

### Marketing Metrics
6. **Website Traffic** - Content reach
7. **Email Subscribers** - Lead generation
8. **Twitter Followers** - Community size
9. **Blog Post Views** - Content performance
10. **Conversion Rate** - Visitor → User

### Revenue Metrics (Future)
11. **Trial Signups** - Product interest
12. **Paying Customers** - Revenue
13. **MRR** - Monthly recurring revenue
14. **Churn Rate** - Customer retention

---

## 🛠️ Tools Setup

### 1. **PostHog** (Product Analytics) - FREE
**Tracks:** CLI usage, scan events, feature usage

Setup:
```bash
# Already integrated in packages/shared/src/analytics/

# Set environment variable:
export POSTHOG_API_KEY=phc_xxx
```

Dashboard Queries:
```sql
-- Total scans per day
SELECT date_trunc('day', timestamp) as date, count(*) 
FROM events 
WHERE event = 'scan_started' 
GROUP BY date 
ORDER BY date DESC;

-- Vulnerability severity distribution
SELECT properties->>'critical_count' as critical,
       properties->>'high_count' as high,
       count(*)
FROM events 
WHERE event = 'scan_completed'
GROUP BY critical, high;

-- Error rate
SELECT (
  SELECT count(*) FROM events WHERE event = 'scan_error'
) * 100.0 / (
  SELECT count(*) FROM events WHERE event = 'scan_started'
) as error_percentage;
```

### 2. **GitHub Stats** (Stars, Watchers, Forks) - FREE
**Tracks:** Repository engagement

API Endpoint:
```bash
curl https://api.github.com/repos/paarthbhatt/Guardiant
```

Dashboard Script:
```javascript
// .automation/scripts/github-stats.js
const fetch = require('node-fetch');

async function getGitHubStats() {
  const response = await fetch('https://api.github.com/repos/paarthbhatt/Guardiant');
  const data = await response.json();
  
  return {
    stars: data.stargazers_count,
    watchers: data.subscribers_count,
    forks: data.forks_count,
    openIssues: data.open_issues_count,
  };
}

// Run daily, log to CSV
```

### 3. **NPM Stats** (Downloads) - FREE
**Tracks:** Package installations

API Endpoint:
```bash
curl https://api.npmjs.org/downloads/point/last-month/@guardiant/cli
```

Dashboard Script:
```javascript
// .automation/scripts/npm-stats.js
const fetch = require('node-fetch');

async function getNpmDownloads() {
  const response = await fetch(
    'https://api.npmjs.org/downloads/point/last-month/@guardiant/cli'
  );
  const data = await response.json();
  
  return {
    downloads: data.downloads,
    start: data.start,
    end: data.end,
  };
}
```

### 4. **Google Analytics** (Website Traffic) - FREE
**Tracks:** guardiant.dev traffic, blog views, conversions

Setup:
```html
<!-- Add to website <head> -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX');
</script>
```

Track Events:
```javascript
// Download click
gtag('event', 'download', {
  'event_category': 'engagement',
  'event_label': 'cli_download'
});

// Docs visit
gtag('event', 'page_view', {
  'page_title': 'VCVF Documentation',
  'page_location': '/docs/vcvf'
});
```

### 5. **ConvertKit** (Email Stats) - FREE
**Tracks:** Subscribers, open rate, click rate

API:
```javascript
// Get subscriber count
const response = await fetch(
  'https://api.convertkit.com/v3/subscribers?api_secret=YOUR_SECRET'
);
```

### 6. **Twitter Analytics** (Built-in) - FREE
**Tracks:** Followers, impressions, engagement rate

Access: twitter.com/guardiant_sec/analytics

---

## 📈 Dashboard Layout

### Tool: **Notion** (FREE) or **Grafana** (self-hosted)

**Recommended:** Notion Database (simple, no setup)

### Notion Setup

**Database Schema:**
```
Date | GitHub Stars | NPM Downloads | CLI Scans | Email Subs | Twitter Followers | Notes
-----|--------------|---------------|-----------|------------|-------------------|------
```

**Update Frequency:** Daily (manual or automated)

**Automation Script:**
```javascript
// .automation/scripts/update-metrics.js
// Fetches all metrics and appends row to Notion database
// Run via cron: 0 9 * * * (daily at 9 AM)
```

---

## 📊 Sample Dashboard (Notion Template)

```
🎯 Guardiant Growth Dashboard
Last Updated: 2026-03-29

═══════════════════════════════════════════════════

📈 WEEKLY SNAPSHOT

GitHub Stars:         234 (+12 this week) ⬆️
NPM Downloads:        1,247 (+89 this week) ⬆️
Email Subscribers:    87 (+15 this week) ⬆️
Twitter Followers:    156 (+23 this week) ⬆️
CLI Scans (7d):       312 scans

═══════════════════════════════════════════════════

🎯 MONTHLY GOALS (March 2026)

[▓▓▓▓▓▓▓░░░] 300 / 500 GitHub Stars (60%)
[▓▓▓▓░░░░░░] 1,247 / 3,000 NPM Downloads (41%)
[▓▓▓▓▓▓▓▓░░] 87 / 100 Email Subs (87%)
[▓▓▓▓▓░░░░░] 156 / 300 Twitter Followers (52%)

═══════════════════════════════════════════════════

📊 TOP PERFORMING CONTENT

1. Blog: "What is VCVF?" - 2,347 views, 87 conversions
2. Tweet: "Symmetric CRUD thread" - 14.2K impressions
3. Reddit: r/netsec post - 234 upvotes, 45 comments

═══════════════════════════════════════════════════

🚀 THIS WEEK'S FOCUS

- [ ] Write Blog Post #2: "Supabase Security Guide"
- [ ] Schedule 6 Twitter posts
- [ ] Launch email welcome sequence
- [ ] Submit to Product Hunt
- [ ] Fix 3 GitHub issues

═══════════════════════════════════════════════════

📈 DETAILED METRICS

View full dashboard: [Link to Notion database]
PostHog Analytics: [Link to PostHog]
Google Analytics: [Link to GA]
```

---

## 🤖 Automation Scripts

### Daily Metrics Collection

**File:** `.automation/scripts/collect-metrics.js`

```javascript
#!/usr/bin/env node

const { Client } = require('@notionhq/client');
const fetch = require('node-fetch');

const notion = new Client({ auth: process.env.NOTION_API_KEY });
const databaseId = process.env.NOTION_DATABASE_ID;

async function collectMetrics() {
  // Fetch GitHub stats
  const ghResponse = await fetch('https://api.github.com/repos/paarthbhatt/Guardiant');
  const ghData = await ghResponse.json();
  
  // Fetch NPM stats
  const npmResponse = await fetch('https://api.npmjs.org/downloads/point/last-day/@guardiant/cli');
  const npmData = await npmResponse.json();
  
  // Add row to Notion
  await notion.pages.create({
    parent: { database_id: databaseId },
    properties: {
      Date: { date: { start: new Date().toISOString().split('T')[0] } },
      'GitHub Stars': { number: ghData.stargazers_count },
      'NPM Downloads': { number: npmData.downloads },
      // Add more metrics...
    },
  });
  
  console.log('✅ Metrics updated');
}

collectMetrics().catch(console.error);
```

**Run daily:**
```bash
# Add to crontab
0 9 * * * cd /path/to/guardiant && node .automation/scripts/collect-metrics.js
```

---

## 📊 KPI Targets (12 Months)

| Month | Stars | Downloads | Email Subs | Twitter | Scans/mo |
|-------|-------|-----------|------------|---------|----------|
| 1 | 500 | 3,000 | 100 | 300 | 1,000 |
| 3 | 1,000 | 10,000 | 300 | 800 | 3,000 |
| 6 | 2,500 | 30,000 | 1,000 | 2,000 | 10,000 |
| 12 | 5,000 | 100,000 | 3,000 | 5,000 | 30,000 |

---

## 🎯 Week 1 Setup Checklist

- [ ] Sign up for PostHog (posthog.com)
- [ ] Set POSTHOG_API_KEY in environment
- [ ] Create Notion database for metrics
- [ ] Write GitHub stats collection script
- [ ] Write NPM stats collection script
- [ ] Set up Google Analytics on website
- [ ] Create Twitter Analytics bookmark
- [ ] Setup ConvertKit API access
- [ ] Write daily metrics automation script
- [ ] Test end-to-end collection
- [ ] Schedule cron job for daily updates

---

**Dashboard Status:** Ready to implement  
**Time to Setup:** 2-3 hours  
**Update Frequency:** Daily (automated)  
**Review Frequency:** Weekly (manual analysis)
