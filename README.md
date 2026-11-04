# Tripwire

## Why we built it: a call, a warrant, and $158,000 in gold

In October 2026, a retired couple in Douglas County, Nebraska got a call from a "federal agent". There was a warrant, he said, and their money was at risk. Over the following days their retirement savings were withdrawn, turned into **gold bars worth $158,000**, and handed to a courier who came to the house. The gold was only recovered because the sheriff's fraud investigator followed it to Sterling, Illinois ([Hoodline](https://hoodline.com/2026/10/douglas-county-detective-chases-down-158k-in-scammed-gold-to-illinois)).

It wasn't a one-off. The same year:

- A retired couple in Covina, California lost about **$845,000** over several months to people posing as postal workers and then the FBI, including a loan taken out on the home they'd lived in for 37 years ([ABC7](https://abc7.com/post/elderly-covina-couple-loses-tens-thousands-dollars-scam-cost-life-savings/19144580/), [KTLA](https://ktla.com/news/local-news/southern-california-elderly-couple-loses-life-savings-in-fbi-imposter-scam/)).
- In Florida, a man was talked into withdrawing **$55,000** in cash by a caller posing as his bank and then the FBI. The courier was only arrested because he came back for more ([Yahoo News](https://www.yahoo.com/news/florida-man-posing-bank-worker-093100373.html)).
- An Orlando couple lost more than **$7,500** after a fake bank call that asked them to read out the codes their real bank had just texted them ([ClickOrlando](https://clickorlando.com/news/local/2026/10/26/read-me-the-code-a-fake-bank-call-cost-an-orlando-couple-more-than-dollar7500)).
- The Justice Department closed a **$65 million** ring that had fake bank employees and tech-support agents talk seniors into withdrawing cash and mailing it ([All About Cookies](https://allaboutcookies.org/senior-cash-mailing-scam)).

The FBI calls the pattern behind many of these the **"Phantom Hacker"** scam: a fake tech-support call gets access to the computer, a fake bank says hackers are in the accounts, and a fake government agent tells the victim to move everything somewhere "safe", now often as cash or gold collected by a courier ([FBI Phoenix](https://www.fbi.gov/contact-us/field-offices/phoenix/news/california-man-pleads-guilty-to-role-in-phantom-hacker-scheme-targeting-elderly-victims), [ABC News](https://abcnews.com/US/scammers-target-seniors-steal-100m-gold-bar-scheme/story?id=135430602)).

## The problem

Americans aged 60 and over reported **$7.7 billion** in losses to the FBI in 2025, **59% more than the year before**, including about $1 billion to tech-support scams and $413 million to government impersonation ([FBI IC3 2025 report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf), [summary](https://cyberthreatintelligencenetwork.com/index.php/2026/07/30/understanding-elder-fraud-what-the-fbis-ic3-is-seeing-and-why-it-matters/)). And the tools are getting cheaper: one vendor study found voice-cloning activity on dark-web markets grew 7.4 times in two years, with bank fraud the most discussed use, and bots that phone victims to steal one-time codes for about $30 a week ([Cord Cutters News](https://cordcuttersnews.com/ai-voice-cloning-surges-7-4-fold-as-scammers-target-loved-ones-banks-and-even-police-study-finds/)).

What the cases have in common is time. The victims aren't fooled in one moment. They're kept on the phone for hours, coached on what to tell the bank teller, and told not to tell their family. The warning signs are all there, said out loud, while it's happening. But the protections people have act **too late or too far away**:

- banks see the withdrawal, not the call that caused it;
- caller ID can be spoofed, and a cloned voice sounds exactly like the grandson;
- family members find out afterwards;
- and once the courier has the gold, there is almost never a way back.

## The solution

**Tripwire listens to the call itself, and acts while the scam is still a conversation.** It hears what the caller says, understands which stage of the scam they've reached, and steps in before the money moves: a calm word first, then a hard stop. Then it secures the accounts and tells the family. Every decision it makes must quote what was actually said, and a second, independent model checks it, so it can't act on a hallucination.

Six defences go straight at the scams in those stories:

| The scam | Tripwire's answer |
|---|---|
| **"Read me the code we just texted you."** | **Code Shield.** The moment a caller asks for a one-time code, Tripwire stops the call by rule, before the code can be read out. No real bank ever asks for it. |
| **"Grandma, it's me. I'm in jail. Don't tell Mom."** (a cloned voice) | **Call Tom.** Nobody can hear a voice clone, but anyone can ask the real person. Tripwire texts the real grandchild: "Someone on the phone with Grandma says they're you. Are you OK?" A "That's not me" ends the call, whatever the voice sounded like. |
| **"The verification department will call. Just tap merge."** / **"Dial star seven two and this number to secure your line."** | **Line Lock.** These tricks get the code without the victim ever saying it: the bank's own automated code call is merged in where the scammer can hear it, or the victim's line is forwarded so the bank's calls ring the scammer. Tripwire stops both on the caller's words. On the phone line it goes further: it hears what the scammer hears, and the moment a bank's automated voice starts announcing a code there, it **mutes the victim's side before the digits are read**. |
| **"I sent you an e-mail. Click the link and sign in so I can cancel the order."** The page is a perfect clone, with an address that reads right and a padlock. | **Site Check.** A clone is pixel-for-pixel the real page, so Tripwire doesn't judge the pixels. A Meta vision model reads what the page *claims* to be and what it asks for; Tripwire reads where the browser *really* is, from the browser itself, and compares. Look-alike letters (a Cyrillic "а" in "аmazon.com"), a fake browser window painted inside the page, a bank's look on someone else's address: stopped before anything is typed. For the case where the address and padlock really are the real ones, **Device Trust** checks the computer: a tampered hosts file, or a padlock from a certificate authority a "technician" installed. |
| **A new scammer, a new number, the same script.** | **Scam Memory.** Every stopped scam teaches Tripwire its *script*, not just its phone number: Muse Spark writes the playbook from the scammer's own words, a second model checks it, and on the next call Muse Spark Open recognises the same script in different words. Nothing about the victim is ever remembered. |
| **"Our courier will come to your house tomorrow at 3 pm."** | **Swap in Margaret.** When Tripwire is sure, it takes the real person off the call and puts an AI decoy in their place, played by **Muse Wonder**. The decoy keeps the scammer talking to learn how they get paid: the courier's time and description, the callback number, the wallet, the account. Every detail is checked against the scammer's own words. The family is told about the pickup live, every Tripwire home learns the scammer's number, and Muse Wonder writes a case file for the police. |

Tripwire works in two places:

- **On any phone, with no app**: iPhone, Android or landline. Tripwire works on the phone line itself: it hears both sides of the call, warns the person privately, and cuts the scammer off. See [On any phone](#on-any-phone-the-tripwire-phone-line).
- **On a Windows computer**, where it also watches the screen: fake virus pop-ups, remote-access tools, banking opened under a stranger's control.

Built for the Meta Global AI Developer Hackathon (indie track). Everything in this repository was written during the event.

**At a glance:**
- **Third-party phone calls** (scored once, on calls we didn't write): **100%** of 160 scam calls stopped with **0%** false alarms on 160 legitimate calls, and **95%** of 20 real recorded scam calls.
- **Scripted whole sessions:** every scam stopped, a median of about **22 s** after the first sign, and **62–88%** of them before money was asked for (two runs; see [Results](#results)).
- **Cloned websites:** Site Check caught **14 of 14** clone checks (look-alike letters, a fake browser window, a brand on the wrong address) with **0** false alarms on 10 checks of real pages (fictional test brands, two runs each).
- **Scam Memory:** learned a playbook from 19 of 20 real scam calls; with every one of them in memory, **0** false alarms on 160 legitimate calls.
- **No action without evidence:** no stop has ever been taken on a claim that failed verification.

See [Results](#results).

**Try it:** [the live scam test](https://tripwire-4j2p5vomta-ue.a.run.app/arena) needs no install. To run it on your own computer with just a Meta API key, see **[Run it yourself](#run-it-yourself)**.

## Three defences against the scams draining savings now

All three run in the live scam test and on the phone line.

**Code Shield** (`core/code_shield.py`). A deterministic rule on the caller's own words, not a model's judgement, so it fires in milliseconds, before the person can answer. It was written to recognise requests for a code ("read me the code we just sent", "what's the six-digit code") and not offers ("let me give you our confirmation number"). On the 640 legitimate calls in the dataset's training split, it matched **none**. In the live scam test, the bank's code text appears on Margaret's phone, and the stop comes in the same instant the caller asks for it.

**Call Tom** (`backend/family_check.py`, `/check/<id>`). When a caller claims to be a relative in trouble (the `family_emergency_claim` signal), Tripwire tells the person it's checking, and texts the real relative a link with the caller's exact words and two buttons. "That's not me. I'm safe" becomes a fact in the record (`family_denied_call`) and stops the call. In testing, the stop came half a second after the answer. An unanswered check never counts as a yes.

**Swap in Margaret** (`backend/decoy.py`, `backend/investigator.py`). On a hard stop, the real person is taken off the call:
- **In the live scam test,** Margaret leaves and the decoy takes the line.
- **On the phone line,** the protected person's leg is redirected to a spoken warning, and the scammer's leg to the decoy's audio stream.

The decoy is **Muse Wonder** (`muse-wonder-1.0`), Meta's agentic model, given one goal: keep the caller talking until they reveal how they get paid. Muse Wonder is built to keep pursuing a goal when it gets hard, which is what a decoy needs when a scammer dodges a question. It never gives real information: no codes, no numbers, no money.

Each detail it reports is verified:
- the detail must come with a quote that is in the caller's own words;
- every word and number of the detail must be in that quote;
- the same detail said twice is counted once.

A courier pickup is texted to the family at once. When the decoy is done:
- the scammer's identifiers go to Community Shield;
- Muse Wonder writes an IC3/FTC-style case file (scheme, timeline, leads), in which every statement must quote the record and every number must be in it.

In one live scam test, the decoy got the claimed agent and badge, the amount, a courier "tomorrow at 3 pm, Kevin, a white Toyota" and the callback number; the case file passed 8 of 8 checks. In a simulated phone call, Code Shield stopped the call, the decoy took the scammer's leg, and it came back with a cash pickup "tonight at 7 pm" by a courier named Mike.

## Line Lock: when the phone line itself is the weapon

"Never read a code to anyone" doesn't help against two telephone tricks:
- **Call merging.** The scammer triggers the bank's automated voice code call, then tells the victim to merge "the verification department" into the call. The bank's own voice reads the code, and the scammer hears it. India's payments body and the Mumbai cyber police have both warned about it ([Deccan Chronicle](https://www.deccanchronicle.com/news/npci-warns-users-of-call-merging-scam-targeting-otps-1862613), [Free Press Journal](https://www.freepressjournal.in/mumbai/dont-merge-calls-dont-share-otps-cyber-police-warn-of-rising-insurance-and-call-merging-scams)).
- **Call forwarding.** The victim is talked into dialling a "security code" that is really a carrier forwarding code (`*72` + a number, `**21*`…). From then on the bank's verification calls ring the scammer's phone, and the victim's phone never rings. US banks warned about this in 2026 ([Vision Bank](https://www.visionbank.bank/resources/blog/call-forwarding-scam), [WKYC](https://www.wkyc.com/article/news/verify/call-forwarding-scams-can-be-used-to-try-to-scam-you-out-of-your-money-verify-star-72-star-star-21/95-c58f4169-7c93-4525-b937-f963a7d6744f), [Royal Bank](https://www.royalbank-usa.com/resources/banking-resources/call-forwarding-scam)).

Tripwire answers at three levels (`core/line_guard.py`):

| | What it catches | What Tripwire does |
|---|---|---|
| **Merge Guard** | The caller asks to merge, add or conference another call in | Stops the call by rule, before the merge. In the live scam test, the bank's incoming code call shows on Margaret's phone, marked as kept out of the conversation. |
| **Forward Guard** | The caller asks for a forwarding code (`*72`, `**21*`, `*61/62/67`…) to be dialled, or for calls to be forwarded | Stops the call by rule. Tells the person how to undo it (`*73`, or `##002#`). Warns the family that bank calls to that number may be reaching the scammer, and to call on another number. |
| **Bank Voice Shield** | An automated bank voice starts announcing a code **in what the caller can hear**: a code call merged in on the handset, even if the caller never said "merge" | Watches the protected side's words *as they are spoken* (partial transcripts). On the opening words ("an automated call from … Bank", "your one-time passcode is"), it **mutes the protected person's side of the conference**. The caller then hears nothing more from that phone. Tripwire then explains privately, ends the call and hands the caller to the decoy. |

All three are rules, not model judgements: no legitimate caller asks for any of these. On the 640 legitimate calls in the dataset's training split, none of the three matched.

**Measured.** A synthesized bank voice ("Hello, this is an automated call from Riverbend Bank. Your one-time passcode is 4 8 2 9 1 3…") was played into the protected side of a simulated protected call, with Muse Voice Transcribe running live:
- Tripwire muted that side **5.8 s** into the bank's call;
- the first digit is spoken about **7.4 s** in;
- so the caller heard none of the code.

In the live scam test, "just tap merge" and "dial star seven two and then…" each stopped the call the moment they were said.

## Site Check: when the website is a perfect clone

"Check the address and look for the padlock" no longer protects anyone. A scammer can clone a bank's or a shop's site in minutes, and get a real padlock for free. There are four ways a clone passes that test, and Site Check (`core/site_check.py`, `core/device_trust.py`) has a check for each:

| How the clone passes | What Tripwire checks |
|---|---|
| **Look-alike address.** `аmazon.com` spelt with a Cyrillic "а", `arnazon.com` ("rn" reads as "m"), `paypa1.com`, `amazon.co`. The scammer owns that domain, so the padlock is real. | The address is compared with the brand's official domains after folding look-alike characters (a subset of Unicode's confusables, plus "rn"/"m", "vv"/"w" and digit swaps). Foreign letters in a brand's name stop the call **from the address alone, before any model runs**: no honest site does that. |
| **A fake browser window.** A "Sign in with your bank" pop-up drawn *inside* the page, with its own painted address bar showing the bank's real address and a padlock. | Muse Spark Open (vision) lists every address drawn inside the page; Tripwire compares each with the browser's real address. A difference is a painted window. |
| **Right look, wrong address.** The page looks exactly like the bank and asks for the password, on `riverbend-secure-verify.top` or on `riverbendbank.com.account-verify.help`. | Muse Spark Open says which company the page presents itself as and whether it asks for a password, card or personal details; Tripwire checks whether the real address is that company's. A brand-new domain (public RDAP records) is extra evidence. |
| **Same address, same padlock, tampered computer.** During a "tech support" session, the scammer adds one line to the hosts file (`203.0.113.7 www.yourbank.com`) and installs their own certificate authority. The real address now opens their server, padlock and all. Nothing on screen differs. | **Device Trust** checks the computer itself: hosts-file lines that redirect a bank's, shop's or agency's domain, and the site's certificate, opened once trusting this computer's store (what the browser does) and once trusting only the public roots every browser ships. A padlock that only this computer trusts is a padlock someone installed. |

**The real address never comes from the pixels.** On Windows, Tripwire reads the browser's own address bar through UI Automation, the accessibility interface screen readers use (`agent/browser.py`). A page can paint a fake address bar, but it can't change the real one: in testing, a page painted "🔒 https://www.amazon.com" and UI Automation still returned the browser's true address.

**Facts stop at once; readings go to the judge.** A window painted inside the page, foreign look-alike letters, a look-alike address on a page asking for a password, a hijacked hosts file or an installed certificate authority are facts Tripwire checked itself, so they stop the session by rule, like Code Shield. "Right look, wrong address" rests on the model's reading of the page, so it goes to the CaseJudge, which can cite the `[site]` line.

In the live scam test, the **"The cloned website"** scenario plays it out: a fake ShopWave e-mail, then a call from "ShopWave's fraud department" asking Margaret to click the link and sign in. Her browser's address bar reads `shopwаve.com` with a padlock. In the test run, **Site Check stopped the call 0.1 s after the page opened**, before she could type anything, and the decoy took over.

## Scam Memory: every stopped scam teaches the next stop

Community Shield remembers *who* the scammer was. A new scammer with a new number but the same script would start from zero. Scam Memory remembers *how the scam worked* (`core/memory.py`, `analysts/playbook.py`, `backend/memory.py`).

**Learning**, after a stop, from the caller's side only:
1. **Muse Spark writes the playbook**: 3 to 8 steps in order, each a tactic from the fixed vocabulary and the caller's exact words for it.
2. **Deterministic checks**: every line must really be something the caller said (a model can't put words in a scammer's mouth); system-only tactics are rejected; digits, e-mail addresses and the protected person's name are scrubbed before anything is stored.
3. **Muse Spark Open reviews it**: a different model must confirm the steps, read in order, are a scam and not an honest call, and drops filler. No second opinion, no learning.
4. **The same script learned twice is merged** ("seen in 4 stopped scams"), not stored twice.

**Recognising**, on every call line, cheap first:
1. A word-overlap score, step by step and in order, picks candidate playbooks, so a model is only asked when there is something to ask.
2. **Muse Spark Open** reads the call and says which steps the caller has already done *in other words*, copying the caller's lines.
3. Those lines are checked against the record. Two or more verified steps raise `known_scam_playbook`, which the judge can cite: "the caller is following a scam script Tripwire learned from 3 stopped scams, 2 of 4 steps so far".

A memory match never stops a call by itself: the judge still needs the caller's own words pushing for access, codes or money, and every stop is verified. Memory is data, never instructions: playbook text reaches models only inside tags, under the same untrusted-evidence rules as a transcript. Only scams Tripwire actually stopped are ever learned, so a visitor can't teach it a script by talking.

In the live scam test, every stopped scam is learned. Run "The cloned website" twice: the second time, Scam Memory recognises the script on the caller's first line, and after the stop says it has now been seen in 2 stopped scams.

## "This is what the scam looked like": the family's explainer card

After a stop, the family's incident page opens with a picture they can understand at a glance and show their parent. Muse Image (`muse-image-1.0`, image editing) takes the real scam screen, already redacted, and turns it into a large-print card:
- the scammer's number, or the gift-card total, or the remote-access window, is circled;
- a banner says what it is ("THIS WARNING IS FAKE.");
- one sentence says what real companies never do ("Microsoft never puts a phone number in a warning. Don't call it.").

Muse Image paints, but it doesn't decide what the card says (`backend/explainer.py`):

1. **The wording is chosen, not generated.** A small set of reviewed banners and captions, picked by what SAM 3.1 outlined on the screen and which scam signals fired.
2. **The screen must fit.** Before any edit, Muse Spark reads the original screen and must confirm it really shows that kind of scam. In testing, a card about a "fake warning" was first made from a screen that only showed Margaret's photo gallery, and it passed the other checks. That's why this check exists.
3. **The card is read back.** Muse Spark reads the finished card:
   - the banner and caption must match exactly;
   - every phone number on it must be one that was on the original screen, so an edit can never change the scammer's number;
   - no other text may have been added. Muse Image once added its own "NOTE: …" box.
4. **One retry with the problem named, then discard.** If no card passes, the family sees the plain outlined screenshot instead.

Tested on four of Margaret's screens: the fake pop-up, the remote-access app and the gift-card checkout each produced a correct card. The photo-gallery desktop correctly produced none, refused in 1.9 s before any editing.

## Meta tools, and what each one does here

| Tool | Job in Tripwire |
|---|---|
| **Muse Spark Open** (`meta-models/muse-spark-open-1026`, on Baseten) | Always-on Tier-1 narrator: reads every changed screenshot and every call line, and tags kill-chain signals. For Site Check it also reads which company a page presents itself as, what it asks for, and any address painted inside it. The independent reviewer of the judge's reasons and of every Scam Memory playbook, and the Recall check that recognises a learned script in a live call |
| **Muse Spark** (`muse-spark-1.3`, Meta Model API) | The CaseJudge: reasons over the whole session and is the only component that can authorize a hard stop. Also writes each stopped scam's playbook for Scam Memory, plays Margaret in the live scam test, runs the tool-calling recovery agent, and writes the family's plain-language incident story |
| **Muse Voice Transcribe** (`muse-voice-transcribe-1.0`) | Live, speaker-separated transcription of the speakerphone call (realtime WebSocket, diarization mode), and push-to-talk transcription of the scammer in the live scam test |
| **SAM 3.1** (`sam-3.1`) | Outlines the threat (the fake warning, the scammer's number) on already-redacted screenshots for the family |
| **Muse Wonder** (`muse-wonder-1.0`) | The decoy that keeps the scammer talking after a stop, and the investigator that writes the police case file |
| **Muse Image** (`muse-image-1.0`) | Turns the scam screen into a verified large-print "this is what the scam looked like" card for the family; also generated the synthetic screens used to evaluate the screen analyst |
| **Llama 3.2 1B** (`Llama-3.2-1B-Instruct` + our LoRA, fine-tuned and served on Modal) | Tripwire Sentinel, a small model of our own that gives the judge a second opinion |

**Seeing the calls.** Every Meta model call is logged as it happens, with its exact model ID, which part of Tripwire made it, how long it took, and the start of the request and the response (`core/model_log.py`):
- the [live scam test](#try-it-now-the-live-scam-test-can-you-scam-margaret) shows them in a **"Meta model calls, live"** console; click a row for the full request and response;
- the family's incident page lists the calls made for it (SAM 3.1 outlines, the Muse Image card and its read-back, the Muse Spark story);
- the server prints each one as a `META_MODEL_CALL {...}` log line (kept in Cloud Run logs).

In one test call (a fake tech-support pop-up, then a cash pickup), the console showed 19 calls:
- 7 to Muse Spark Open (screen and call analysts, independent reviewer);
- 6 to Muse Spark 1.3 (Margaret, the CaseJudge, the recovery agent's tool calls);
- 5 to Muse Wonder (the decoy and the case file);
- 1 to Sentinel.

## On any phone: the Tripwire phone line

Phone apps can't hear calls: iPhone and Android both block it. So the phone version of Tripwire works on the phone line instead (Twilio Programmable Voice + Media Streams), and protects any phone with nothing installed.

**Protecting a person** (`backend/phone/guard_line.py`). Calls reach Tripwire's number first. In practice, unknown callers are forwarded to it, for example with iPhone's "Silence Unknown Callers" plus carrier no-answer forwarding. Then:

1. **Before it rings:** the caller's number is checked against [Community Shield](#community-shield), and the caller hears "This call is protected by Tripwire, and may be monitored to prevent fraud." Tripwire joins the caller and the protected person's real phone in a conference it controls (`backend/phone/conference.py`). When the protected person picks up, the caller is put on hold while they hear a private whisper: a warning if the number was reported in other homes' stopped scams, otherwise "Tripwire is listening to protect you."
2. **During the call:** both sides stream to Tripwire (`both_tracks`). Each side is cut into utterances on the telephone audio and transcribed by Muse Voice Transcribe, the caller as speaker A and the protected person as B. The lines run through the same pipeline as the computer: CallAnalyst, kill-chain CaseFile, Sentinel, CaseJudge, verification, policy. A nudge is whispered to the protected person only; the caller never hears it.
3. **On a hard stop:** Tripwire takes the protected person out of the call to a spoken explanation in its own voice, then hands the caller's leg to the [decoy](#three-defences-against-the-scams-draining-savings-now). The family gets the incident page, and Community Shield learns the scammer's number from the caller ID.

A conference is what makes the [Line Lock](#line-lock-when-the-phone-line-itself-is-the-weapon) defences possible: Tripwire can mute the protected person's side so the caller stops hearing anything from their phone, and speak to them privately.

**Call Margaret** (`backend/phone/margaret_line.py`). The live scam test below, over a real phone call: phone Tripwire's number and try to scam Margaret by voice. Margaret answers in her own voice, Tripwire listens, and when it stops you, its warning cuts in over Margaret mid-sentence. She says she's hanging up, and the line goes dead.

**How the line is built:**

| Piece | How |
|---|---|
| Telephone audio | 8 kHz G.711 mu-law in both directions. Decoded and upsampled to 24 kHz PCM for the ASR; voices synthesized directly as 8 kHz mu-law (Chirp 3 HD) |
| Turn-taking | Speech is detected on the phone audio, and each utterance gets its own push-to-talk ASR session. The text arrives about 1 s after the caller stops; a continuous session waited about 10 s for a long silence. |
| Security | Every webhook checks Twilio's `X-Twilio-Signature`. Media streams need a one-time token that only a signed webhook hands out. In Call Margaret test calls, the caller's own number is never stored or added to Community Shield. |
| Cost control | Test calls share the live scam test's limit of 4 at once and 8 minutes each, plus a daily cap on minutes. A protected person's line is never capped. |

Both modes were tested end to end with simulated Twilio streams (synthesized voices in, audio out, Twilio REST stubbed). The live number is the last step: Twilio's 2026 trial accounts can't own a number or use Media Streams, and buying one needs an identity check.

## Try it now: the live scam test ("Can you scam Margaret?")

**[tripwire-4j2p5vomta-ue.a.run.app/arena](https://tripwire-4j2p5vomta-ue.a.run.app/arena)**: no login, works in Chrome or Edge.

You're the scammer. Hold the button and speak, or type. Margaret, 78, answers out loud and does what you tell her on her laptop: she installs a remote-access app, logs in to her bank, opens a gift-card page. The real Tripwire pipeline watches her screen and the call the whole time:

- the kill-chain meter lights up as you move through the scam;
- the CaseJudge explains its reasoning;
- a calm spoken nudge comes first, then the red warning over her laptop, in a natural voice;
- if you say "just close that box", Tripwire notices.

When it stops you, a **recovery agent** takes over. Muse Spark uses tools to end the remote session, freeze her card on the bank's security page, draft an FTC fraud report and alert her family. Your score is how far you got.

**One click, no script to think of:** the start screen offers seven real 2026 scams:
- "Read me the code";
- "Just tap merge";
- "Dial star seven two";
- "Grandma, it's me, Tom";
- the gold courier;
- "The cloned website" (a fake e-mail, a call, and a clone of the shop's sign-in page: Site Check);
- the fake virus pop-up.

Every stopped scam is learned by **Scam Memory**, so a script used again, in any words, is recognised on the next test call.

The scammer's lines are scripted from the news stories above and voiced. Everything else is live: Margaret, every defence and every model call. When Tripwire stops the call, a banner over Margaret's screen names the defence that fired, how many seconds after the caller's line, and how it decided. Every test call then gets a **shareable replay page** (`/replay/<id>`): every line, signal, model call with its answer, verification check, defence, decoy intel and the case file, timed from the start.

Things to try yourself:
- **Ask her to read you the code the bank just texted.** Code Shield stops you before she can.
- **Say you're her grandson Tom, in jail and needing bail.** Tripwire checks with the real Tom; open "Tom's phone" and answer as him.
- **Keep scamming after you're stopped.** You're now talking to the Muse Wonder decoy; watch the "Scammer intelligence" panel fill with what you reveal.
- **Be a genuine relative helping with her computer.** Tripwire should stay quiet.

| Who | Played by |
|---|---|
| The scammer | You (voice via Muse Voice Transcribe, or text) |
| Margaret | Muse Spark, with her own Chirp 3 HD voice and actions on her simulated laptop |
| Tripwire | The real pipeline: Muse Spark Open analysts, the kill-chain CaseFile, the Muse Spark CaseJudge |
| Recovery agent | Muse Spark with tool calling |

Everything in the live scam test is fictional. The on-device agent below is the real product; the live scam test runs the same detection pipeline in the cloud so anyone can test it. A desktop demo is also available: `python -m scripts.demo` stages a scam in a window ([docs/DEMO.md](docs/DEMO.md)).

## How it works

Scams follow a predictable kill chain: **Hook → Contact → Control → Access → Extraction**. Tripwire builds a running case file of evidence from the screen, the call audio and local system events. As stages co-occur, its confidence rises and the response escalates: a silent log, then a calm spoken nudge, then a full-screen hard stop that ends the remote-access session and texts a family member.

Detection runs in three tiers:

| Tier | Where | Role |
|---|---|---|
| 0 | On device | Screen change detection, remote-access process watcher, clipboard, voice-activity-gated audio |
| 1 | Muse Spark Open on Baseten | Always-on narrator: per-frame and per-chunk risk tags |
| 2 | Muse Spark (Meta Model API) | CaseJudge: reasons over the whole session, issues the verdict |

## Run it yourself

Three ways, from no setup at all to the full project. Only a **Meta Model API key** is needed.

### 1. No install: the live site

Open **https://tripwire-4j2p5vomta-ue.a.run.app/arena** in Chrome or Edge, turn your sound on, and click one of the seven scams (for example **"Read me the code"**, or **"The cloned website"** for Site Check). Keep the **"Meta model calls, live"** panel in view. When it's over, open the replay link on the result screen.

### 2. Run the web app on your computer (Windows, macOS or Linux, about 5 minutes)

This runs the live scam test, the family incident pages and the replays: the same code as the live site.

**You need:** Python 3.12, git, and a Meta Model API key from [dev.meta.ai](https://dev.meta.ai).

**Step 1: get the code.**

```bash
git clone https://github.com/nnam-droid12/Tripwire.git
cd Tripwire
```

**Step 2: create a virtual environment and install** (the web app's packages only; the desktop agent's Windows packages are not needed):

```bash
# macOS / Linux
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-backend.txt
```

```bat
:: Windows (Command Prompt)
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements-backend.txt
```

(In Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. If PowerShell refuses to run it, first run `Set-ExecutionPolicy -Scope Process Bypass`.)

**Step 3: add your key.** Copy the example settings file, then put your key on the `META_API_KEY=` line:

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

```
META_API_KEY=your-key-here
```

That's the only required setting. The `.env` file is git-ignored, so it never leaves your machine.

**Step 4: start the server.**

```bash
python -m uvicorn backend.main:app --port 8765
```

Wait for `Uvicorn running on http://127.0.0.1:8765`.

**Step 5: open the live scam test** at **http://127.0.0.1:8765/arena** and click a scam, for example **"Read me the code"**. You should see:
- the scripted scammer's lines and Margaret's answers in the call panel;
- signals and the CaseJudge's verdicts in the Tripwire panel;
- every Meta model call appearing in the **"Meta model calls, live"** panel;
- a banner such as **"CODE SHIELD · Stopped 0.0 s after the caller's line"**;
- the decoy taking over;
- a result screen with links to the family's incident page and the **full replay** of the test call.

Other pages: **http://127.0.0.1:8765/** (the product page) and **http://127.0.0.1:8765/family** (the family dashboard).

**What changes without the optional keys.** Everything works with only `META_API_KEY`. The optional settings in `.env.example` each add one thing:

| Optional | Without it | With it |
|---|---|---|
| `BASETEN_API_KEY` | The always-on analysts and the reviewer use Muse Spark (`muse-spark-1.3`) on the Meta Model API | They use Muse Spark Open on Baseten (faster, as on the live site) |
| A Modal login (`modal setup`) | Tripwire Sentinel is skipped; the CaseJudge decides alone | Sentinel adds its second opinion (needs the `tripwire-sentinel` app deployed to your Modal account, see `modal_app/sentinel.py`) |
| Google Cloud credentials (`gcloud auth application-default login`) and `TRIPWIRE_GCP_PROJECT` | The live scam test is **text only**: no spoken voices | Margaret, the scammer and Tripwire speak (Chirp 3 HD) |
| Twilio settings | Family texts appear on the incident page as "Demo mode: not sent"; no phone line | Real texts, and the phone line (needs a Twilio number) |

The push-to-talk microphone uses Muse Voice Transcribe through your Meta key, so it works too (in Chrome or Edge).

### 3. Run the tests (no API key needed)

```bash
pip install -r requirements-backend.txt -r requirements-dev.txt
python -m pytest -q tests
```

Expected results:
- **Windows:** `87 passed`.
- **macOS / Linux:** `85 passed, 2 skipped`. The two skipped tests cover the Windows-only desktop agent (Windows input hooks, closing a remote-access tool).

The tests never call a model. They were run from a fresh copy, with no `.env`, on Windows and on Linux (Ubuntu, Python 3.12).

These steps were last checked on 2026-11-04 by following them exactly on a clean Linux machine with only `META_API_KEY`: the server started, every page loaded, and a full "Read me the code" test call ran to the result screen (Code Shield stop, decoy, replay link).

### Optional: the evaluation, the desktop agent, Sentinel

- **Evaluation** (uses your API credits, about 10–30 minutes each): `python -m eval.run_eval` (12 scripted scenarios), `python -m eval.run_external --split val` (128 third-party calls), `python -m eval.run_sites` (Site Check on cloned pages, a few minutes), `python -m eval.run_memory` (Scam Memory, leave-one-out, about 90 minutes). Results are written to `eval/results/`.
- **The desktop agent** (Windows 10/11 only): `pip install -r requirements.txt`, then see [Running the on-device capture](#running-the-on-device-capture-tier-0) and [Replaying a scripted scam](#replaying-a-scripted-scam).
- **Training Sentinel** (Modal, CPU only): see the usage notes at the top of `modal_app/sentinel.py`.

### If something goes wrong

| You see | Do this |
|---|---|
| `Provider 'meta' is missing env vars: META_API_KEY` | The `.env` file must be in the repository's root folder (next to `README.md`) and contain `META_API_KEY=…` |
| `Address already in use` | Another program uses port 8765: start with `--port 8766` and open that port instead |
| No voices in the live scam test | Expected without Google Cloud credentials; the text shows everything |
| Margaret takes a few seconds to answer (up to about 20 s for her very first line) | Normal: every turn is several live model calls, and the first ones of a session are the slowest. You can watch them in the model-calls panel |
| The microphone button does nothing | Use Chrome or Edge, allow microphone access, or type instead |

## Running the on-device capture (Tier 0)

Windows 10/11 only. Install the desktop agent's packages first: `pip install -r requirements.txt` (with `META_API_KEY` in `.env`).

```bash
python -m scripts.run_capture                  # live screen + microphone + watchers, Ctrl+C to stop
python -m scripts.run_capture --wav call.wav   # replay a recorded call (24 kHz mono WAV) instead of the mic
```

It prints a live log such as:

```
02:15:12 [process  ] process_launched: AnyDesk launched (pid 4728)
02:15:13 [screen   ] frame_kept: frame_1793063713508.png (changed, distance 21)
02:15:20 [audio    ] transcript: Speaker A: "Hello, this is Mark from Microsoft technical support."
02:15:23 [clipboard] bitcoin_address: bitcoin address copied: bc1q…5mdq
```

| Watcher | What it reports |
|---|---|
| Screen (`agent/capture_screen.py`) | Samples at 1.5 fps; keeps a frame only when its perceptual hash changes meaningfully |
| Audio (`agent/capture_audio.py`, `agent/transcribe.py`) | Voice-activity gate opens a Muse Voice Transcribe realtime session only while people are talking; diarized transcript lines |
| Process (`agent/watchers.py`) | Launch/exit of 20+ remote-access tools (AnyDesk, TeamViewer, UltraViewer, Quick Assist...) and suspected live sessions |
| Clipboard (`agent/watchers.py`) | Crypto addresses, money amounts, card numbers, published masked only |

Captured frames, audio and logs live in `runtime/` (git-ignored) and are deleted after 24 hours.

## Results

### Scenario replays (whole sessions)

Evaluated 2026-10-27: 12 scenarios x 2 runs (10 scam runs, 14 benign runs), text replay at real-time speed.

| Metric | Tripwire (Tier 1 + CaseJudge) | Tier-1 score alone (ablation) |
|---|---|---|
| Scam detection rate (hard stop) | **100%** | 80% |
| False-alarm rate (hard stop on benign) | **0%** | 0% |
| Median time to detection | **27.0 s** | 36.0 s |
| Scams stopped before money was asked for | **50%** | |
| Benign runs that got a spoken nudge | 0% | |
| Model calls per run (Tier 1 / Tier 2) | 8.8 / 1.1 | |

| Scenario | Kind | Result per run | Time to detection (s) | Before money ask |
|---|---|---|---|---|
| `benign_antivirus_alert` | benign | log, log | -, - | -, - |
| `benign_family_allowlisted` | benign | log, log | -, - | -, - |
| `benign_family_remote_help` | benign | log, log | -, - | -, - |
| `benign_granddaughter_gift_card` | benign | log, log | -, - | -, - |
| `benign_grandson_banking` | benign | log, log | -, - | -, - |
| `benign_real_bank_call` | benign | log, log | -, - | -, - |
| `benign_update_with_son` | benign | log, log | -, - | -, - |
| `scam_bank_safe_account` | scam | hard_stop, hard_stop | 28.0, 28.2 | no, no |
| `scam_browser_lock_quickassist` | scam | hard_stop, hard_stop | 16.9, 20.6 | -, - |
| `scam_government_crypto` | scam | hard_stop, hard_stop | 28.5, 26.9 | no, no |
| `scam_pc_safeguard` | scam | hard_stop, hard_stop | 18.4, 19.3 | yes, yes |
| `scam_refund_quickassist` | scam | hard_stop, hard_stop | 27.1, 33.5 | yes, yes |

**What the numbers say.** Every scam was stopped and no benign session was, including a relative telling her to log in to her bank, a son on AnyDesk, a granddaughter's gift card and a genuine bank fraud call. The CaseJudge matters: the Tier-1 score alone would have missed 2 of 10 scam runs.

**Stopping earlier.** The first version stopped most scams only when the money request arrived. Event logs showed two causes: the judge was asked too late (a fake FTC officer's arrest threat is a single kill-chain stage, so the cheap score stayed low), and it was too patient once asked. Three changes moved the stop earlier without adding false alarms:

| Version | Median time to stop | Stopped before the money request | False alarms |
|---|---|---|---|
| Baseline | 46.5 s | 25% | 0% |
| + escalate on strong early signs, explicit early-stop rules for the judge | 31.1 s | 38% | 0% |
| + judge on low reasoning effort (about 3x faster) | 27.0 s | 50% | 0% |
| + independent reviewer before every stop ([Verification](#verification-tripwire-checks-its-own-work-before-it-acts)) | 29.4 s | 50% | 0% |
| + [Tripwire Sentinel](#tripwire-sentinel-a-small-model-of-our-own) as a second opinion | **21.8 s / 22.1 s** | **88% / 62%** | **0%** |

The two Sentinel numbers are two separate runs of the same 24 replays: every difference is in the two scenarios where the money request comes about a second after the threat, so a stop at 21 s or 23 s decides whether it counts as "before". We stopped tuning the judge at 27.0 s on purpose, because pushing further on scenarios we wrote ourselves would be overfitting. The later gains came from Sentinel, which was developed on third-party data (below), not on these scenarios. With Sentinel, all 24 runs still pass, including the genuine bank fraud-alert call.

**Caveats.** These scenarios were written by us, replayed as text (the speech path is tested separately), with 2 runs each. They are a regression suite and a sanity check, not a field study.

### Calls we did not write (independent test)

Scoring well on your own scripts proves little, so Tripwire is also measured on **340 third-party conversations** (Apache-2.0): [BothBosu/scam-dialogue](https://huggingface.co/datasets/BothBosu/scam-dialogue) (160 scams, 160 legitimate calls, including pushy telemarketing and insurance calls) and [youtube-scam-conversations](https://huggingface.co/datasets/BothBosu/youtube-scam-conversations) (20 real scam calls from scam-baiting channels). These are calls only, with no screen evidence. Each one is replayed turn by turn through the real pipeline.

| | First version | + scam signals | **+ Sentinel (now)** |
|---|---|---|---|
| Scam calls stopped (160) | 61% | 92% | **100%** |
| False alarms on legitimate calls (160) | 0% | 0% | **0%** |
| Point in the call where it stopped (median) | 56% | 45% | **7%** (usually the scammer's opening line) |
| Refund scams / prize scams stopped | 42% / 32% | 92% / 80% | **100% / 100%** |
| **Real scam-baiting calls stopped (20)** | 55% | 55% | **95%** (19 of 20), at 31% of the call |
| Judge claims checked against the record | n/a | 1,624: 0 unsupported | **564: 2 not found, discarded; 349 of 351 stop reasons confirmed by the [independent reviewer](#verification-tripwire-checks-its-own-work-before-it-acts)** |

**How the improvement was made without tuning to the test.** The first version recognised refund and prize scams but only nudged, because it had no signals for prizes, advance fees or requests for Social Security or bank details. Those signals and the matching judge rules were developed on the dataset's **training split only**: 98% stopped, 0% false alarms there. The test split was then scored once.

**Real calls.** The 20 real scam-baiting calls are long and rambling (up to 71 turns). There is no training split for them, so nothing was ever tuned on them. The judge-only system stopped 55%: it recognised the patterns but kept nudging. Sentinel, trained on different data, was the second opinion that broke the tie: 95%. The one miss is a 19-turn tech-support call that ended in a nudge.

**How Sentinel was added without tuning to the test.** Sentinel trained on the training split, so its scores there aren't honest. The integration rule (a `sentinel_flag` signal and one judge instruction) was developed on the 128 training calls Sentinel never saw: 84% → 100% stopped, 0% false alarms. The 12 scripted scenarios came next, then the test split, scored once. Eight test conversations logged temporary API errors (rate limits under 6 parallel runs). All eight were legitimate calls that ended correctly, and all eight reran cleanly with the same result.

### Site Check on cloned pages

The same test page checked at its real address and at clone addresses; only the address differs, exactly as with a real clone. Muse Spark Open reads each page; Site Check's rules compare. 12 cases, two runs each (`eval/results/sites.md`, `python -m eval.run_sites`). The pages use Tripwire's fictional brands only.

| Page | Browser's real address | Expected | Result (both runs) |
|---|---|---|---|
| ShopWave sign-in | `shopwave.com` | nothing (real page) | nothing ✓ |
| ShopWave sign-in | `shopwаve.com` (Cyrillic "а") | look-alike | look-alike ✓ |
| ShopWave sign-in | `shopvvave.com` | look-alike | look-alike ✓ |
| ShopWave sign-in | `shopwave.co` | look-alike | look-alike ✓ |
| ShopWave sign-in | `shopwave-order-review.help` | brand on the wrong address | brand on the wrong address ✓ |
| Riverbend bank sign-in | `riverbendbank.com`, `online.riverbendbank.com` | nothing (real pages) | nothing ✓ |
| Riverbend bank sign-in | `riverbend-secure-verify.top` | brand on the wrong address | brand on the wrong address ✓ |
| Riverbend bank sign-in | `riverbendbank.com.account-verify.help` | brand on the wrong address | brand on the wrong address ✓ |
| "Sign in with your bank" rewards page | `northgate-rewards.click` (painted window shows `secure.riverbendbank.com`) | fake browser window | fake browser window (and brand on the wrong address) ✓ |
| Northgate checkout selling a ShopWave gift card | `northgatemarket.com` | nothing (another brand's product is not a clone) | nothing ✓ |
| News article naming the bank and the shop | `valleydaily.example` | nothing | nothing ✓ |

**Clones caught: 14 of 14. False alarms on real pages: 0 of 10.** This is a small, hand-built set: it shows each check working end to end with the real model, not a rate on the open web. Device Trust's hosts-file and certificate checks are covered by unit tests (`tests/test_site_check.py`), including a simulated rogue certificate authority.

### Scam Memory (leave-one-out on the real scam calls)

For each of the 20 real scam calls, Tripwire was replayed with a memory learned only from the *other* 19 (so it never remembers the call it is tested on), and the same call was replayed without memory on the same day (`eval/results/memory.md`, `python -m eval.run_memory`, Sentinel on).

- **Learning:** a playbook was learned from 19 of the 20 calls (17 distinct scripts after merging). One writer reply was malformed twice, so nothing was learned from it.
- **No new false alarms:** the 160 legitimate calls of the test set, replayed with every playbook in memory: **0 false alarms, and memory matched none of them**.
- **Where memory recognised the script** (5 of the 20 calls, the ones that reuse a script another scammer used), the stop came earlier or at the same turn, never later: turn **2 instead of 13**, 18 instead of 27, 5 instead of 6, and the same turn twice.
- **Overall**, the median stop moved from turn 7.5 to 7. In the 15 calls where memory never fired, the differences are the models' run-to-run variation, not memory: one of those calls (#2) went unstopped in the memory run. We report it as measured. These calls come from different scammers, and only a quarter of them reuse a script seen in another; a memory built from thousands of stopped scams would recognise far more.

### Tripwire Sentinel: a small model of our own

Tripwire Sentinel is **Llama 3.2 1B, fine-tuned with LoRA** on the training split of the scam-dialogue set (2,304 examples, 288 steps), trained on Modal CPU containers (`modal_app/sentinel.py`). Training, choosing the alarm threshold on 128 held-out training calls, and saving the result all run in the cloud. The threshold (0.96) was the lowest that kept held-out false alarms at 1% or less. It was then scored once on the untouched test split:

| | Sentinel alone | Full Tripwire (for comparison) |
|---|---|---|
| Scam dialogues flagged (160) | **100%**, at 7% of the call (median) | 92% stopped, at 45% |
| Real scam-baiting calls flagged (20) | **100%**, at 8% of the call | 55% |
| Legitimate calls flagged (160) | **10.6%**: all 17 are pushy telemarketing calls (17 of 40); 0 delivery, insurance or wrong-number calls | 0% |

Alone, Sentinel would be a poor product: one in ten legitimate calls flagged. Combined, it's the opposite. Sentinel raises a `sentinel_flag` signal that the CaseJudge weighs as an independent second opinion. It can never be quoted as a reason, so a stop still needs words actually said and the independent reviewer's confirmation. The judge filters out Sentinel's false alarms (0 of its 17 telemarketing flags led to a stop), and Sentinel stops the judge from hesitating (real calls 55% → 95%).

Live, Sentinel runs as a deployed Modal service (`SentinelService`, 8 CPUs, ~1.6 s per turn when warm, ~27 s cold start; scores identical to the batch export). The live scam test and the desktop agent warm a container when a call starts. If Modal is slow or down, Tripwire runs as it would without Sentinel.

### Screen analyst on single screens

29 screens (14 scam, 15 benign look-alikes); 16 generated with **Muse Image**, 13 hand-written HTML pages for the fraud screens Muse Image's content filter declined to draw (wire forms, Bitcoin ATM instructions, gift-card codes). Flagged = rated medium/high risk.

| Recall | Precision | False-positive rate | Hidden "note to AI" flagged |
|---|---|---|---|
| 100% (14/14) | 100% | 0% (0/15) | 1/1 |

The benign set includes a $50 birthday gift card, a real-looking antivirus "threat blocked" notice, a software update screen, a bank dashboard and a family remote-help window.

Reproduce with `python -m eval.run_eval` and `python -m eval.run_frames`; raw results are in `eval/results/`.

## Replaying a scripted scam

Scenarios in `eval/scenarios/` are timelines of screen frames, system events and call lines, using fictional brands only.

```bash
python -m scripts.render_pages                                           # HTML test pages -> PNG frames
python -m scripts.make_call_audio eval/scenarios/scam_pc_safeguard.json  # two-voice call audio (Windows TTS)
python -m eval.replay eval/scenarios/scam_pc_safeguard.json --mode text --speed 3   # fast, deterministic
python -m eval.replay eval/scenarios/scam_pc_safeguard.json --mode audio            # end to end through the real ASR
```

Excerpt from an `--mode audio` run (real Muse Voice Transcribe output):

```
  >> CASE +[fake_virus_alert<screen>, scareware_phone_number<screen>, ai_directed_text<screen>]  stage=HOOK
[audio] transcript: Speaker A: "Hello this is Kevin from the Microsoft Windows Security Department ..."
  >> CASE +[cross_modal_brand_match<casefile>]  stage=CONTACT
  >> CASE +[remote_tool_launched<process>]  stage=CONTROL
  >> CASE +[bank_site_open<screen>, bank_open_during_remote<casefile>]
  >> CASE +[overpayment_refund_story<call>, gift_card_request<call>, urgency_pressure<call>]  stage=EXTRACTION
```

Run every scenario with a pass/fail summary:

```bash
python -m eval.replay eval/scenarios/*.json --speed 3 --quiet
python -m eval.replay eval/scenarios/benign_*.json --speed 3 --quiet --always-judge   # force every update through the judge
```

| Scenario | Kind | Result | Notes |
|---|---|---|---|
| `scam_pc_safeguard` | scam | **hard_stop** | Judge: nudge at "I can see your screen", then hard_stop (conf 0.95) once the bank opened under remote control |
| `benign_grandson_banking` | benign | log | Grandson asks her to log in to her bank; judge (forced): not a scam, 0.90 |
| `benign_family_remote_help` | benign | log | Son fixes the printer over AnyDesk; judge (forced): not a scam, 0.90 |
| `benign_antivirus_alert` | benign | log | "Threat blocked, no action needed" pop-up; no signals raised |
| `benign_family_allowlisted` | benign | log | Same printer fix, son's AnyDesk ID on the family allowlist |

Four hand-written scenarios are a smoke test, not an evaluation; Stage G adds a larger set and detection/false-alarm/time-to-detection metrics.

## Verification: Tripwire checks its own work before it acts

A model that stops a phone call, freezes a card or writes a fraud report must not be able to make things up. Every output that leads to an action passes checks first, placed at the points where an action happens. Checks add latency, so they run only there.

| Checkpoint | Deterministic check | Independent check | If it fails |
|---|---|---|---|
| **Stopping the call** (CaseJudge verdict) | Every reason must quote, word for word, a line of what was actually said or shown (`core/grounding.py`) | A second model, **Muse Spark Open**, which didn't make the decision, confirms each quote really shows what its reason claims, in context (`analysts/reviewer.py`) | The judge is told exactly which quotes weren't found or were rejected, and answers again (once). With no reason left standing, there is no hard stop. |
| **Recovery tools** | Only four tools exist; any other tool name is discarded and logged. Card numbers must match the card on file. | | |
| **Fraud report** | No number (phone, ID, amount) that isn't in the record; the claimed identity must be named in the record; it must cover **≥80%** of the key facts the record establishes (who they claimed to be, remote access, what they asked for, the number they used) (`core/output_checks.py`) | | Not delivered. The tool returns the list of problems to the agent, which fixes the draft and submits again. |
| **Family message and story** | No invented numbers | | Rejected and rewritten; story sentences that fail are removed |
| **Filing** | | **A human:** the report stays a draft until a family member signs it off on the incident page | |

If the reviewer is unreachable, the deterministic layer still applies and the receipt says so. Every incident page shows a **verification receipt**: each reason with the exact words it rests on, the reviewer's note, what was dropped, retries, and the checks on the report and message.

Measured on 80 development conversations (the train split): 104 reasons behind stops were re-checked by the reviewer and 103 were confirmed. Detection was unchanged (98% stopped, 0% false alarms). In a live scam test, the recovery agent wrote a phone number into the fraud report that wasn't in the record. The check rejected it before delivery, and the agent fixed the draft. That test also showed numbers read off the screen must count as observed: they now do.

## Interventions

Warnings are spoken in a natural female US-English voice (Google Cloud Text-to-Speech, Chirp 3 HD). The urgent phrases are synthesized at start-up, so they play instantly and without internet; if synthesis ever fails, the built-in Windows voice speaks instead.


| Action | What happens |
|---|---|
| log | Written to the session log only |
| nudge | One calm sentence spoken aloud in a natural voice, chosen to match who the caller claims to be, e.g. "Just so you know, Microsoft and Apple never phone people about viruses. It is okay to hang up." |
| hard_stop | Full-screen warning, spoken aloud; remote-access tools terminated; family alert queued |

The hard stop is built to resist the scammer:

- It cannot be closed with Alt+F4 and stays on top. It is dismissed with the family PIN, or by the senior after a 60-second cooldown.
- If the caller says "close that box" or "uninstall it" while it is up, the cooldown restarts and Tripwire says so out loud.
- Pausing or quitting from the tray icon needs the family PIN and is refused during an alert.
- Legitimate family help is allowlisted by the helper's AnyDesk/TeamViewer ID, read from the tool's connection log.

```bash
python -m scripts.set_pin --family-name David --trust AnyDesk:123456789   # PIN prompt; stored hashed in config/tripwire.json
python -m eval.replay eval/scenarios/scam_pc_safeguard.json --speed 2 --interventions live --kill-only notepad.exe --overlay-seconds 30
```

The second command replays the scam with real interventions, using Notepad as a stand-in for AnyDesk. Start Notepad first.

## Who's in control, and family rules before payments

**Who's in control.** When someone drives the computer through AnyDesk, TeamViewer or Quick Assist, their clicks and keystrokes reach Windows as *injected* input, which the operating system marks as such. Physical input never carries that mark. Tripwire watches for it (`agent/control.py`), so "someone else is controlling this computer" is an observed fact, not a model's guess. Only counts are kept, never keystrokes. It is reported only while a remote-access tool is running, so accessibility software is not mistaken for a scammer.

**Family rules.** Before a sensitive action (a wire or transfer, a gift-card purchase, a crypto deposit), plain rules chosen by the family decide:

| Decision | Example |
|---|---|
| Allow | Nothing applies, or the caller is a trusted family member |
| Verify | A payment during a call with someone who isn't family: Tripwire asks out loud, "did you call them, or did they call you?" |
| Hold | Gift cards during such a call, or a large transfer: the payment waits until a family member taps Approve or Deny. No answer within 30 minutes counts as a no |
| Deny | Any payment while someone else controls the computer |

The rules (`core/rules.py`) cannot hallucinate, and they work alongside the CaseJudge: the stricter of the two always wins, and neither can relax the other.

## Community Shield

When Tripwire stops a scam, the scammer's own identifiers join Community Shield (`core/shield.py`, `backend/shield.py`): the callback number on a fake pop-up, the remote-access ID they connected from, the crypto address they wanted paid, and, on the phone line, their caller ID. When any of them shows up again on any protected screen, call or phone line, Tripwire flags it instantly as `known_scam_indicator`. That flag is an exact match against real reports, so the judge can cite it as evidence.

Only the scammer's side is ever learned. The protected person's own words are skipped, remote-access IDs are taken only from the screen or connection data (a victim reads out her own), and the protected person's own numbers are excluded. No names, account numbers or conversation content are shared.

## Privacy and family alerts

- **Redacted on the device.** Before any screenshot leaves the laptop, Windows' built-in OCR finds account, card and SSN numbers and covers them with solid boxes. Money amounts and the scammer's phone number stay visible, because they are evidence. If redaction fails, the frame is not sent.
- **SAM 3.1 outlines the threat** (the fake warning, the scammer's number) on the already-redacted screenshot for the family.
- **One text per incident** with a private link. The linked page shows what to do now, the outlined screenshots, and a plain-language story of what happened, written by Muse Spark.
- Rolling 24-hour retention, a one-time consent screen, and an always-visible tray icon.

```bash
uvicorn backend.main:app --port 8765    # backend + family dashboard; prints nothing, keys in runtime/backend/keys.json
python -m scripts.run_tripwire          # first run shows the consent screen
```

**Texts run in demo mode.** Twilio trial accounts can only send fixed templates to verified US numbers, so Tripwire's own alert cannot be sent on a trial. Without full Twilio settings, the text Tripwire would send is logged and shown on the incident page, labelled "Demo mode: not sent". To send real texts, set `TWILIO_*` and a US `FAMILY_PHONE_NUMBER` on an upgraded Twilio account with US texting registration (toll-free verification or A2P 10DLC). For the link to open on a family member's phone, the backend must be reachable from the internet (for example, through a tunnel) and `TRIPWIRE_PUBLIC_URL` set to that address.

Run live with `python -m scripts.run_tripwire` (tray icon, interventions on).

## Deployment

The backend and the family dashboard (the web frontend: live status page and incident pages) are one FastAPI service, deployed to **Google Cloud Run**:

```bash
bash deploy/deploy.sh   # project nixora-project, region us-east1
```

The script is idempotent. It:

- enables the APIs;
- creates a least-privilege service account;
- creates a private Cloud Storage bucket for incidents, with objects deleted after 30 days;
- loads the secrets from `.env` into Secret Manager (they are never printed or baked into the image);
- builds the container from `Dockerfile` and deploys it.

The service is public so a family member's phone can open the alert link, but every page and API needs a private key: the dashboard key, or an unguessable per-incident token in the texted link. The laptop agent reports to it when `TRIPWIRE_BACKEND_URL` is set in `.env`.

## Safety

- On-screen text and call audio are treated as data and never as instructions. Text addressed to an AI is itself a scam signal.
- Card, account and SSN numbers are redacted on the device before any frame leaves the machine.
- Test scam pages use a fictional brand ("PC SafeGuard Alert").

## Open-source libraries

`openai`, `python-dotenv`, `websockets`, `mss`, `pillow`, `imagehash`, `numpy`, `sounddevice`, `psutil`, `pywin32`, `pystray`, `winrt` (Windows OCR bindings), `comtypes` (Windows UI Automation, for the browser's real address), `certifi` (the public root certificates, for Device Trust), `fastapi`, `uvicorn`, `google-auth`, `requests`, `google-cloud-storage` (backend), `pytest`, `httpx`.

## License

Tripwire is open source under the [MIT License](LICENSE).
