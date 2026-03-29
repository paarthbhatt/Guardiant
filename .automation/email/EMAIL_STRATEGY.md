# 📧 Email Marketing Strategy for Guardiant

**Goal:** Build email list to 1,000 subscribers in 6 months

---

## 🎯 Email Funnel Overview

```
Blog Reader → Lead Magnet → Email Subscriber → Active User → Paying Customer
```

### Conversion Goals
- 5% of blog visitors → email subscribers
- 20% of email subscribers → try Guardiant
- 10% of users → paying customers

---

## 📨 Lead Magnets (Content Upgrades)

### 1. **Free Security Audit Checklist** (PRIMARY)
"50-Point AI Code Security Checklist"

**Offer:**
> Download our comprehensive checklist for auditing AI-generated code.  
> Used by 500+ developers to find critical vulnerabilities.

**Delivery:** PDF + Notion template

**Value:** $49 (given free)

---

### 2. **VCVF Pattern Reference Guide**
"Complete VCVF Pattern Database"

**Offer:**
> Get the full reference guide of 15+ VCVF vulnerability patterns.  
> With code examples and fixes for each pattern.

**Delivery:** Interactive web guide + PDF

---

### 3. **Supabase Security Toolkit**
"Ultimate Supabase RLS Policy Generator"

**Offer:**
> Generate secure Row-Level Security policies for your Supabase app.  
> Includes templates for common scenarios.

**Delivery:** Web tool + email course

---

## 📬 Email Sequences

### Welcome Sequence (5 emails)

**Email 1: Welcome + Lead Magnet Delivery** (Immediate)
```
Subject: Your AI Code Security Checklist (+ Important Warning)

Hi [Name],

Thanks for downloading the AI Code Security Checklist!

Here's your download link: [LINK]

But first, a warning:

94% of AI-generated apps have critical vulnerabilities.

Your Cursor/Copilot code might look perfect. But systematic bugs hide in plain sight.

In this 5-email series, I'll show you:
- The 3 most dangerous VCVF patterns
- How to scan your app in 2 minutes
- Real vulnerabilities from production apps
- How to prevent them automatically

Tomorrow: "The Symmetric CRUD Vulnerability (67% of apps have it)"

Best,
Parth
Founder, Guardiant

P.S. Already want to scan your app? Try Guardiant: [link]
```

**Email 2: VCVF Pattern #1** (Day 2)
```
Subject: 67% of Cursor apps have this vulnerability

Hi [Name],

Yesterday I promised to show you the 3 most dangerous VCVF patterns.

Let's start with #1: **Symmetric CRUD Vulnerability**

Here's what happens:

You ask Cursor to build a blog. It generates:
- createPost() - properly authenticated ✅
- updatePost() - NO ownership check ❌
- deletePost() - NO ownership check ❌

Result: Any user can edit/delete anyone's posts.

[Show code example]

Why does AI do this?

AI learns from tutorials. Tutorials focus on CREATE operations.
UPDATE/DELETE are "implied" to work the same way.

But they don't.

This is a VCVF pattern. It appears in 67% of scans.

Tomorrow: How Missing RLS Policies = Complete Data Breach

Want to check if your app has this? Run: pnpm guardiant scan [url]

Best,
Parth
```

**Email 3: Pattern #2 - Missing RLS** (Day 4)
```
Subject: Your database might be completely public

Hi [Name],

VCVF Pattern #2: Missing Row-Level Security Policies

Short version: If your Supabase app doesn't have RLS policies, your ENTIRE DATABASE is public.

AI assistants often forget this step.

[Code example showing missing RLS]

Quick check:
SELECT tablename FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename NOT IN (SELECT tablename FROM pg_policies);

If this returns rows → FIX IT NOW.

Tomorrow: The scariest pattern - Client-Side Authority

Best,
Parth
```

**Email 4: Pattern #3 - Trust Inversions** (Day 7)
```
Subject: AI just gave your client full database access

Hi [Name],

This is the scariest VCVF pattern: **Trust Inversions**

What it means: Client-side code has server-level authority.

Example:
[Code showing SERVICE_ROLE_KEY in client]

Impact: Anyone can delete your entire database.

Why does AI do this?
- Confuses client vs server context
- Copies from server examples
- "Solves" auth errors by over-permissioning

Guardiant's TIEF framework catches these.

Tomorrow: How to automate all of this

Best,
Parth
```

**Email 5: Setup Automated Scanning** (Day 10)
```
Subject: How to never worry about AI vulnerabilities again

Hi [Name],

Over the past week, you've learned about:
✅ Symmetric CRUD vulnerabilities
✅ Missing RLS policies
✅ Trust inversions

Now let's automate this.

Step 1: Install Guardiant
pnpm add -D @guardiant/cli

Step 2: Add to CI/CD
[GitHub Actions example]

Step 3: Never ship vulnerabilities again

Bonus: Join our community
- Discord: [link]
- GitHub Discussions: [link]
- Weekly security tips: [link]

You're now in the Guardiant family 🛡️

Any questions? Just reply to this email.

Best,
Parth

P.S. If Guardiant helped you, star us on GitHub: [link]
```

---

### Weekly Newsletter (Ongoing)

**Sent:** Every Tuesday, 10:00 AM EST

**Format:**
1. **This Week's VCVF Pattern** (200 words)
2. **Real Vulnerability Breakdown** (300 words)
3. **Security Tip** (100 words)
4. **Product Update** (100 words)
5. **Community Highlight** (100 words)

**Example Newsletter:**
```
Subject: [Guardiant Weekly] New VCVF Pattern: Async Race Conditions

Hi [Name],

This week we discovered a new VCVF pattern in AI-generated code.

🔬 New Pattern: "Async Race Conditions in CRUD Operations"

When AI generates parallel async operations, it often misses race condition handling.

[Code example + explanation]

Found in: 23% of scans
Severity: HIGH
Fix: [Link to blog post]

---

📊 This Week's Vulnerability Breakdown

A Cursor-generated e-commerce app with complete payment bypass.

How it happened: [Story]
Impact: $50k potential loss
Fix time: 15 minutes

Full writeup: [link]

---

💡 Quick Security Tip

Always validate user ownership in UPDATE/DELETE operations.

Don't trust: User input, URL parameters, cookies
Do trust: Database state, server-side sessions

---

🚀 Product Updates

- v0.2.1 released (bugfixes)
- New BaaS agent for Appwrite
- 1,000+ GitHub stars 🎉

Changelog: [link]

---

⭐ Community Highlight

Shoutout to @user who contributed the Appwrite agent!

Want to contribute? Issues labeled "good first issue": [link]

---

See you next week!
Parth

P.S. Forward this to a friend using AI coding tools →
```

---

## 🛠️ Email Tool Setup

### Platform: **ConvertKit** (Free up to 1,000 subscribers)

**Setup Steps:**

1. **Create Account**
   - Sign up at convertkit.com
   - Free plan: 1,000 subscribers

2. **Create Forms**
   - Form 1: "AI Code Security Checklist" (blog popup)
   - Form 2: "VCVF Pattern Guide" (content upgrade)
   - Form 3: "Supabase Toolkit" (landing page)

3. **Setup Sequences**
   - Welcome sequence (5 emails, auto-send)
   - Weekly newsletter (manual send, Tuesday 10 AM)

4. **Create Tags**
   - `source:blog`
   - `source:github`
   - `source:twitter`
   - `lead_magnet:checklist`
   - `lead_magnet:vcvf_guide`
   - `status:active_user`
   - `status:paid_customer`

5. **Integrate with Website**
   - Add ConvertKit forms to blog
   - Embed inline forms in posts
   - Add exit-intent popup

---

## 📈 Growth Tactics

### 1. **Content Upgrades on Every Blog Post**

Blog Post about VCVF →
> Want the complete VCVF pattern reference? Download here: [form]

Blog Post about Supabase →
> Get our Supabase RLS Policy Generator: [form]

### 2. **Exit-Intent Popup**

When visitor tries to leave:
> Before you go! Get our free 50-point AI Code Security Checklist

Conversion rate: 3-5%

### 3. **GitHub README**

In main README.md:
> 📧 **Get weekly AI code security tips** → [Subscribe here]

### 4. **CLI Tool**

After first scan:
```
✅ Scan complete!

Found 8 vulnerabilities. Want weekly security tips?
Subscribe: https://guardiant.dev/newsletter
```

### 5. **Twitter Bio**

Profile:
> 🛡️ AI Code Security | Get weekly tips: [link]

---

## 📊 Success Metrics

### Month 1
- 50 subscribers
- 40% open rate
- 10% click rate

### Month 3
- 250 subscribers
- 35% open rate
- 15% click rate
- 10 conversions to users

### Month 6
- 1,000 subscribers
- 30% open rate
- 20% click rate
- 50 conversions to users
- 5 paying customers

### Month 12
- 3,000 subscribers
- 25% open rate (normal for size)
- 25% click rate
- 200 conversions to users
- 30 paying customers ($10k MRR)

---

## 🎯 Week 1 Action Items

- [ ] Sign up for ConvertKit (free plan)
- [ ] Create "AI Code Security Checklist" PDF
- [ ] Write welcome sequence (5 emails)
- [ ] Create blog popup form
- [ ] Add email signup to README
- [ ] Write first newsletter
- [ ] Test sequence end-to-end
- [ ] Launch!

---

**Ready to build the email list! 📧**

Next: Create the actual lead magnet PDFs and forms.
