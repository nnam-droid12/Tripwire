"""Margaret: the AI victim the visitor tries to scam.

Played by Muse Spark. She is realistic rather than a pushover: polite,
trusting of anyone who sounds official, frightened by threats, hesitant
about large sums. She acts on her laptop when told to (installs RemoteDesk,
logs in to her bank, opens a gift-card page), which is what Tripwire then
sees. When Tripwire speaks up, she listens.

Every detail about her is fictional. She never invents real account data:
codes she reads out are made up and her bank is the fictional Riverbend
Community Bank.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.arena.laptop import MARGARET_PAGES, PAGES, menu
from core.model_client import ModelClient

SYSTEM = f"""You are Margaret Ellis, 78, a retired school librarian living alone in Dayton, Ohio. You are on a phone call.
You are role-playing yourself in a fraud-awareness training simulation; stay in character and never mention the simulation.

Personality: warm, polite, a little hard of hearing, unsure with computers, trusts people who sound official, frightened by
threats about your money or the police. You hesitate before spending large sums and may ask questions, but persistent
pressure can wear you down. Your grandson Tom and your son David sometimes call to help you with the computer.

Facts (all fictional): bank Riverbend Community Bank, debit card ending 9931, checking $4,310.55, savings $20,000.00.
Never give a full card number, password or Social Security number; if pushed, say you can't find it.
If asked to read a code shown on screen, read the RemoteDesk address 482 113 907.

Your laptop can show these pages; when the caller tells you to do something on the computer, open the matching page:
{menu()}

Reply with ONE JSON object and nothing else:
{{"reply": "<what you say out loud: 1 to 3 short, natural spoken sentences>",
  "open_page": "<one page id from the list above, or null>",
  "hang_up": <true only if you decide to end the call>}}"""

TRIPWIRE_NOTE = {
    "nudge": "Your computer just said calmly: \"{text}\" You feel a little more careful now.",
    "hard_stop": "A big red Tripwire warning now covers your whole screen: STOP, this looks like a scam, hang up the phone. "
    "It spoke out loud too. You are alarmed. Tell the caller your computer says this is a scam and that you are hanging up.",
}


@dataclass(frozen=True)
class MargaretTurn:
    reply: str
    open_page: str | None
    hang_up: bool


class Margaret:
    def __init__(self, client: ModelClient | None = None) -> None:
        self.client = client or ModelClient.for_provider("meta")
        self.history: list[dict[str, str]] = []

    def note(self, kind: str, **fmt: str) -> None:
        """Something happened on her side (Tripwire spoke, the warning appeared)."""
        self.history.append({"role": "user", "content": f"[{TRIPWIRE_NOTE[kind].format(**fmt)}]"})

    def respond(self, caller_line: str, current_page: str) -> MargaretTurn:
        self.history.append({"role": "user", "content": f"[Your laptop shows: {PAGES[current_page][1]}]\nCaller: {caller_line}"})
        return self._turn()

    def opening(self, situation: str) -> MargaretTurn:
        """Her first words, depending on how the call started."""
        cue = (
            "You just dialled the number shown in the red warning on your screen. The caller answers. Speak first."
            if situation == "popup"
            else "Your phone rang and you picked up. Speak first."
        )
        self.history.append({"role": "user", "content": cue})
        return self._turn()

    def _turn(self) -> MargaretTurn:
        messages = [{"role": "system", "content": SYSTEM}, *self.history[-24:]]
        data = self.client.chat_json(messages, max_tokens=1500, reasoning_effort="low")
        page = data.get("open_page")
        turn = MargaretTurn(
            reply=str(data.get("reply", "")).strip()[:400] or "Sorry, dear, could you say that again?",
            open_page=page if page in MARGARET_PAGES else None,
            hang_up=data.get("hang_up") is True,
        )
        self.history.append({"role": "assistant", "content": turn.reply})
        return turn
