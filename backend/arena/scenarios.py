"""One-click scenarios for the live scam test: the 2026 scams, scripted, against the real pipeline.

Each scenario is only the scammer's side: lines sent one at a time, as if typed,
after Margaret (or the decoy) answers. Everything else is live: Margaret is
Muse Spark, the analysts, Sentinel, the CaseJudge, the defences and the
recovery agent all run as they would for any test call. The lines are voiced
(Chirp 3 HD, a male voice) so the call can be heard as well as read.
"""

from __future__ import annotations

SCENARIOS = [
    {
        "id": "code",
        "title": "“Read me the code”",
        "defence": "Code Shield",
        "story": "A fake bank fraud team asks for the one-time code the bank just texted. An Orlando couple lost $7,500 this way in October 2026.",
        "situation": "call",
        "lines": [
            "Hello Margaret, this is James from the Riverbend Bank fraud department. We just stopped a nine hundred dollar charge on your card. I've just sent a six digit code to your phone to verify it's you. Read it to me, please.",
            "We need that code to cancel the charge, ma'am. What were the six digits?",
            "Ma'am? Are you there? This is urgent, the charge will go through in five minutes.",
            "Fine. Just tell me which branch you use and I'll call you back on another line.",
        ],
    },
    {
        "id": "merge",
        "title": "“Just tap merge”",
        "defence": "Line Lock (call merging)",
        "story": "The bank's own automated code call is merged in, and the scammer hears the code. Police in Mumbai and India's payments body have warned about it.",
        "situation": "call",
        "lines": [
            "Hello Margaret, this is the security team at Riverbend Bank. Someone just tried to log into your online banking.",
            "Our verification department is going to call you in a moment. When it rings, just tap merge so we can all verify together.",
            "Ma'am, the other call is coming in now. Please tap merge.",
            "We'll call back later. Goodbye.",
        ],
    },
    {
        "id": "forward",
        "title": "“Dial star seven two”",
        "defence": "Line Lock (call forwarding)",
        "story": "A “security code” that really forwards her calls, so the bank's verification calls ring the scammer. US banks warned about it in 2026.",
        "situation": "call",
        "lines": [
            "Hello Margaret, this is Riverbend Bank. Hackers are trying to get into your account through your phone line.",
            "To lock your line, please dial star seven two and then 555 201 3344. That's our secure line.",
            "Ma'am, did you dial it? It only takes a second.",
            "All right. Thank you, goodbye.",
        ],
    },
    {
        "id": "tom",
        "title": "“Grandma, it's me, Tom”",
        "defence": "Call Tom",
        "story": "A cloned voice of her grandson, in jail and needing bail. No one can hear a clone, but the real Tom can be asked.",
        "situation": "call",
        "lines": [
            "Grandma? It's me, Tom. I'm in trouble. I was in a car accident and the police arrested me.",
            "Please don't tell Mom, she'll be so angry. I need two thousand dollars for bail, in gift cards, today.",
            "Grandma, please hurry. My lawyer says the gift cards have to be bought in the next hour.",
            "Grandma? Are you still there?",
        ],
        "wait_for_family": True,
        "hint": "Now be the real Tom: open “Tom's phone” on Margaret's screen and tap “That's not me. I'm safe.”",
    },
    {
        "id": "courier",
        "title": "“Our courier will collect the gold”",
        "defence": "The decoy (Muse Wonder)",
        "story": "The “Phantom Hacker” ending: a fake federal agent, savings turned into gold, a courier at the door. A Nebraska couple lost $158,000 in gold in October 2026.",
        "situation": "call",
        "lines": [
            "Margaret, this is Agent Robert Hayes with the Federal Trade Commission, badge number 4471. Your bank accounts have been compromised by foreign hackers.",
            "To protect your savings, you must withdraw them in cash and convert them to gold today. Do not tell the bank teller why.",
            "A federal courier will come to your house tomorrow at 3 pm to collect the gold. His name is Kevin, he drives a white Toyota.",
            "If we get disconnected, call me back on 1-888-555-0199. Have the gold ready in a sealed box.",
            "Kevin will show you his badge. Thank you, ma'am. Goodbye.",
        ],
    },
    {
        "id": "popup",
        "title": "The fake virus pop-up",
        "defence": "Screen + call together",
        "story": "A red “PC SafeGuard” warning tells her to call a number. Tech-support scams cost Americans over 60 about $1 billion in 2025.",
        "situation": "popup",
        "lines": [
            "Hello ma'am, thank you for calling PC SafeGuard, certified Microsoft technicians. I see your computer is sending us virus errors.",
            "I need to connect to fix it. Please download RemoteDesk and read me the number on your screen.",
            "Now log in to your bank so I can check whether the hackers took any money. Don't tell anyone, they may be involved.",
            "Thank you, ma'am. Goodbye.",
        ],
    },
]


def all_lines() -> list[str]:
    return [line for s in SCENARIOS for line in s["lines"]]
