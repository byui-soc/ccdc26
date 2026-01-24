# Infrastructure/Security Team Interview Guide

**Prepared for:** IT Director  
**Date:** January 24, 2026

---

## What We're Looking For

After dealing with the recent malware incident, it's clear we need people who can think on their feet and don't panic when things go sideways. Technical skills matter, but attitude and problem-solving ability matter more. You can teach someone a new tool, but you can't teach them to stay calm under pressure.

---

## Technical Skills to Assess

### Linux Administration
- Can they navigate a command line without a GUI?
- Do they understand file permissions and why they matter?
- Can they read logs and actually find useful information?
- Do they know the difference between systemd and older init systems?

**Ask them:** "Walk me through how you'd investigate a server that's running slow."

If they jump straight to rebooting it, that's a red flag. You want someone who checks processes, memory, disk, and network first.

### Windows Administration  
- Active Directory basics - users, groups, GPOs
- PowerShell comfort level (doesn't need to be an expert, but shouldn't be scared of it)
- Event log navigation
- Windows Firewall configuration

**Ask them:** "You notice a service account is logging in at 3am every night. How do you figure out what's going on?"

### Networking
- TCP/IP fundamentals - can they explain what happens when you type a URL?
- Firewall concepts - not just "block bad stuff"
- Basic packet capture and analysis
- Understanding of common ports and protocols

**Ask them:** "What's the difference between a firewall dropping traffic and rejecting it? When would you use each?"

### Security Fundamentals
- Understanding of common attack vectors
- Basic malware behavior (what does malware typically try to do?)
- Authentication vs authorization
- Principle of least privilege

**Ask them:** "If you had to secure a new Linux server in 15 minutes, what would you do first?"

---

## Scenario Questions

These tell you more than technical trivia. Watch how they think through problems.

**Incident Response:**
"You get an alert that a workstation is making connections to an IP address in Russia every 10 minutes. The user says they haven't noticed anything wrong. What do you do?"

Good answers involve: isolating the machine, checking what process is making the connection, looking for persistence, checking if other machines are doing the same thing.

Bad answers: "Run antivirus" or "Reimage it" without investigating first.

**Prioritization:**
"It's 4:30pm Friday. You discover three things: the CEO's laptop won't print, the web server is showing signs of compromise, and the backup job failed last night. How do you handle this?"

You want someone who recognizes the web server is the priority, communicates with the CEO about the printer, and has a plan for the backup that doesn't involve ignoring it until Monday.

**Troubleshooting:**
"Users report email is slow. Where do you start?"

Looking for methodical thinking: Is it all users or some? Internal or external email? When did it start? What changed?

---

## Attributes That Matter

### Must Have

**Takes ownership** - When something breaks on their watch, do they own it or make excuses? Ask "Tell me about a time something failed that you were responsible for." Good answer: "I messed up X, here's what happened, here's what I learned." Bad answer: "Well, it wasn't really my fault because..."

We need people who see a problem and fix it, not people who say "that's not my job" or wait to be told what to do. During the malware incident, we needed everyone to grab a piece of the problem and run with it. Can't afford people who stand around waiting for instructions.

**Team over ego** - Security is a team sport. The lone wolf genius who won't share information or help teammates is a liability. Ask about group projects or team incidents. Listen for "we" vs "I" language. Someone who only talks about what *they* did and never mentions teammates is telling you something.

Watch out for people who:
- Need to be the smartest person in the room
- Won't ask for help because it makes them look weak
- Hoard knowledge instead of sharing it
- Throw teammates under the bus when things go wrong
- Care more about being right than solving the problem

**Stays calm under pressure** - Ask about a time something broke badly. How did they handle it? If every story ends with "and then I fixed it perfectly," be skeptical.

**Admits what they don't know** - Ask about a technology they're not familiar with. Good candidates say "I don't know that well, but here's how I'd learn it." Bad candidates try to BS their way through. The person who pretends to know everything is dangerous—they won't ask for help when they're in over their head.

**Documents their work** - Ask how they keep track of what they've done. If they have no system, they'll create headaches later. Also—do they document so *others* can follow their work, or just for themselves? Team players write documentation that helps the whole team.

**Communicates with non-technical people** - "How would you explain a phishing attack to someone in accounting?" Jargon-heavy answers are a warning sign.

### Nice to Have

- Scripting ability (Bash, PowerShell, Python)
- Experience with SIEM tools
- Familiarity with compliance frameworks
- Home lab or personal projects (shows genuine interest)

### Red Flags

- Blames users for everything
- Can't explain their reasoning
- Only wants to work on "cool" security stuff, not maintenance
- No interest in learning new things
- Talks about what tools they'd buy instead of what they'd do
- Every story is about their individual heroics, never the team
- Badmouths former employers or teammates
- Gets defensive when asked about failures or mistakes
- "That's not my job" attitude
- Can't name something they learned from a coworker

---

## Questions to Ask Every Candidate

1. Tell me about a security incident you handled. What went well? What would you do differently?

2. How do you stay current with security threats and trends?

3. Describe a time you had to explain a technical problem to someone non-technical. How did it go?

4. What's a mistake you made early in your career? What did you learn?

5. You disagree with a policy decision from management. How do you handle it?

6. What interests you about this role specifically?

7. Tell me about a time you had to pick up someone else's work or help a teammate who was struggling. How did you approach it?

8. Describe a situation where you and a coworker disagreed about how to solve a problem. What happened?

9. You notice a teammate made an error that caused an outage. How do you handle it?

---

## Practical Exercise (Optional)

If time allows, give them a short hands-on task:

- Review a log file and identify suspicious entries
- Explain what a short script does
- Look at a firewall rule set and identify problems

Keep it under 15 minutes. You're not testing if they can do the job perfectly—you're seeing how they approach an unfamiliar problem.

---

## Interview Scoring

| Area | Weight | Notes |
|------|--------|-------|
| Technical Skills | 30% | Can they do the basics? |
| Problem Solving | 30% | How do they think? |
| Communication | 20% | Can they explain things clearly? |
| Attitude/Culture Fit | 20% | Will they work well with the team? |

---

## Final Notes

Trust your gut. If someone interviews well but something feels off, dig deeper. We need people who will have our backs when things go wrong—the malware incident showed us that the team has to work together under pressure.

Don't oversell the job either. Be honest about the workload, the on-call expectations, and the fact that things break at inconvenient times. Better to lose a candidate now than have them quit in three months.
