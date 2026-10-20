"""
Medidor de dano ao vivo para Black Desert (protótipo).

Lê o tráfego do jogo como o capture.py (sem tocar no processo do jogo), calcula
o dano de cada jogador pela queda de vida dos monstros e mostra numa janela.
Cada sessão gera uma pasta em capturas/ com resumo.txt, golpes.csv e captura.pcap.

Uso:
    python meter.py                    # ao vivo
    python meter.py --replay PASTA     # repete uma captura gravada (para testes)
    python meter.py --replay PASTA --sem-janela   # só gera o resumo, sem janela
"""
import argparse
import csv
import json
import queue
import re
import struct
import sys
import threading
import time
import tkinter as tk
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, PcapReader

from capture import Capture, MarkerLog, write_info

FROZEN = getattr(sys, "frozen", False)  # rodando como .exe (PyInstaller)
VERSION = "1.3.9"  # mudar a cada release (o .exe compara com a última release do GitHub)
UPDATE_REPO = "Lucas-Amaralz/DPS-Meter-BDO"
UPDATE_ASSET = "DPS-Meter-BDO.zip"
UPDATE_CHECK_EVERY = 3600  # s
# config, caches, capturas e ícones ficam ao lado do programa (do .exe ou do meter.py)
APP_DIR = Path(sys.executable).parent if FROZEN else Path(__file__).parent

# --- Protocolo (descoberto nas capturas de 2026-10-19) ---
# Mensagem: [u16 tamanho, inclui cabeçalho][u8 0=aberta 1=cifrada][u16 tipo][corpo]
OP_HP = 0x0F4E
# Corpo do 0x0f4e: +0 i64 origem (<0 = monstro), +12 f32 vida nova, +16 u32 quem causou,
#                  +24 u32 alvo, +36 f32 vida máxima, +40 u32 contador de golpes do alvo
OP_PARTY = 0x1B46
# Corpo do 0x1b46 (lista da pt, chega ao entrar na pt): +0 u8 quantidade, depois blocos
# de 269 bytes a partir do +25: +16 u8 classe, +65 u8 nível, +73 família (UTF-16),
# +139 personagem (UTF-16), +265 u32 ator
PARTY_START, PARTY_ENTRY = 25, 269
OP_PARTY_STATUS = 0x0BD5
# Corpo do 0x0bd5 (estado da pt, a cada ~10 s, inclusive membros longe): +12 u8 quantidade,
# blocos de 53 bytes: ator em +52+53k, vida atual/máxima (i32) logo antes do ator (-9/-5)
STATUS_ACTOR, STATUS_ENTRY = 52, 53
OP_PARTY_MEMBER = 0x0ED5
# Corpo do 0x0ed5 (ficha de quem entra na pt): um bloco igual ao da lista da pt, no +0
OP_SELF_PROFILE = 0x1A72
SELF_SIGNAL_WINDOW = 600.0  # s: sem sinal certeiro há tanto tempo, volta a usar os golpes
# Corpo do 0x1a72: chega só sobre o próprio jogador, ao entrar no jogo ou trocar de canal;
# o nome do personagem fica em +65 (UTF-16)
OP_PROFILE = 0x1771
# Corpo do 0x1771 (perfil de jogador que aparece por perto): +6 nome (UTF-16), ator no fim
# Código de classe do jogo = número usado no site oficial (sa.playblackdesert.com/GameInfo/Class,
# imagens em .../classes/class_<código>/). Nomes como aparecem no site em pt-BR.
CLASSES = {
    0: "Guerreiro", 1: "Hashashin", 2: "Sage", 3: "Wukong", 4: "Caçadora", 5: "Guardiã",
    6: "Erudita", 7: "Drakania", 8: "Feiticeira", 9: "Nova", 10: "Corsária", 11: "Lahn",
    12: "Berserker", 15: "Me-Gu", 16: "Domadora", 17: "Shai", 19: "Lutador", 20: "Musah",
    21: "Maehwa", 23: "Mística", 24: "Valquíria", 25: "Kunoichi", 26: "Ninja",
    27: "Cavaleira das Trevas", 28: "Mago", 29: "Arqueiro", 30: "Wu-Sa", 31: "Bruxa",
    32: "Serafim", 33: "Do-Sa", 34: "Deadeye", 35: "Agent",
}
# ícone do programa (no .exe vem junto, dentro de _internal)
RES_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR / "empacotar"))
ICONS_DIR = APP_DIR / "icones"  # emblemas recortados do site oficial (ver download_icons)


def class_name(code):
    return CLASSES.get(code, f"classe {code}") if code is not None else ""


OP_ATTACK = 0x16BC
# Corpo do 0x16bc (resultado de golpes; em algumas áreas é a única fonte do dano):
# +0..9 cabeçalho, depois blocos de 115 bytes: +69 u32 quem bateu, +73 u32 alvo,
# +77 f32 dano do golpe, +81 f32 vida do alvo depois do golpe
ATTACK_START, ATTACK_ENTRY = 10, 115
# Mensagens que só o próprio jogador recebe sobre si: (tipo, tamanho do corpo, posição do ator)
SELF_SIGNALS = {0x141E: (58, 26), 0x1C4B: (243, 0)}
IGNORED_ATTACKERS = {0xFFFFFC00}
PARTY_TIMEOUT = 35.0  # s sem o estado da pt (chega a cada ~10 s) = você saiu da pt
COMBAT_GAP = 5.0  # segundos sem golpe que não contam como tempo de combate
# Modo BOSS: só contam alvos grandes (boss e sub-bosses); adds e mobs comuns ficam de fora
BOSS_MIN_HP = 3_000_000
BOSS_DEATH_FRAC = 0.002  # vida <= 0,2% da máxima = morreu (o golpe final nem sempre chega)
BOSS_LOW_FRAC, BOSS_IDLE_DEATH = 0.03, 6.0  # ou: < 3% e 6 s sem levar golpe
BOSS_SWITCH_IDLE = 5.0  # s sem golpe no boss atual para seguir outro boss do mesmo porte
BOSS_ABANDON = 60.0  # s sem nenhum golpe da pt: luta largada, o relógio para
UNFINISHED_MIN_TIME = 5.0  # s de combate para guardar no histórico ao zerar/fechar


class StreamParser:
    """Remonta um fluxo TCP e separa as mensagens do jogo."""

    MAX_PENDING = 256

    def __init__(self):
        self.next_seq = None
        self.pending = {}
        self.buf = bytearray()
        self.synced = False

    def feed(self, seq, data):
        if self.next_seq is None:
            self.next_seq = seq
        if seq < self.next_seq:  # retransmissão ou sobreposição
            if seq + len(data) <= self.next_seq:
                return []
            data = data[self.next_seq - seq:]
            seq = self.next_seq
        if seq > self.next_seq:
            self.pending[seq] = data
            if len(self.pending) > self.MAX_PENDING:  # buraco que não vai fechar: pula
                self.next_seq = min(self.pending)
                self.buf.clear()
                self.synced = False
            else:
                return []
        else:
            self.buf += data
            self.next_seq += len(data)
        while self.next_seq in self.pending:
            d = self.pending.pop(self.next_seq)
            self.buf += d
            self.next_seq += len(d)
        return self._extract()

    @staticmethod
    def _chain(buf, off):
        """Quantas mensagens seguidas parecem válidas a partir de off."""
        pos, count = off, 0
        while pos + 5 <= len(buf):
            n = buf[pos] | buf[pos + 1] << 8
            if n < 5 or buf[pos + 2] > 1:
                return count, False
            if pos + n > len(buf):
                return count, True
            pos += n
            count += 1
        return count, True

    def _resync(self):
        for off in range(0, max(0, len(self.buf) - 5)):
            count, ok = self._chain(self.buf, off)
            if count >= 4 or (ok and count >= 2 and off == 0):
                del self.buf[:off]
                self.synced = True
                return
        if len(self.buf) > 1 << 16:
            del self.buf[:-4096]

    def _extract(self):
        if not self.synced:
            self._resync()
            if not self.synced:
                return []
        out = []
        while len(self.buf) >= 5:
            n = self.buf[0] | self.buf[1] << 8
            if n < 5 or self.buf[2] > 1:
                self.synced = False
                return out + self._extract()
            if len(self.buf) < n:
                break
            out.append(bytes(self.buf[:n]))
            del self.buf[:n]
        return out


class Combat:
    """Soma o dano por jogador a partir das atualizações de vida."""

    def __init__(self, log_path=None):
        self.lock = threading.Lock()
        self.log_file = open(log_path, "w", newline="", encoding="utf-8", buffering=1) if log_path else None
        if self.log_file:
            self.log = csv.writer(self.log_file)
            self.log.writerow(["hora", "t", "atacante", "alvo", "dano", "vida_antes",
                               "vida_depois", "vida_max", "contador"])
        self.hp = {}
        self.players = {}  # ator -> vida máxima (jogadores vistos)
        # ator -> (personagem, família, classe, nível); self_actor = o próprio jogador
        self.party, self.self_actor = self.load_party_cache()
        self.first_t = None  # horário do primeiro pacote
        self.last_t = None
        self.status_seen = False  # já chegou o estado da pt (0x0bd5)?
        self.last_status_t = None  # horário (do pacote) do último estado da pt
        self.self_votes = Counter()  # votos de "este ator é você" (os antigos perdem força)
        self.max_hp = {}  # vida máxima de cada monstro (da 0x0f4e)
        # dano já creditado pela 0x16bc que ainda vai aparecer na próxima queda da 0x0f4e
        self.explained = Counter()
        # boss/dg: o tempo é a luta inteira (1º ao último golpe da pt, pausas incluídas)
        self.boss_mode = bool(load_config().get("modo_boss", False))
        # pvp: dano de jogador em jogador perto de você (exclui o modo boss)
        self.pvp_mode = bool(load_config().get("modo_pvp", False)) and not self.boss_mode
        self.player_hp = {}  # vida atual dos jogadores (para o dano de PvP)
        self.known_names, self.known_info = self.load_names_cache()  # ator -> nome / ficha
        self.past_party = {}  # quem saiu da pt (para continuar com nome no ranking)
        self.self_name = load_config().get("meu_personagem")  # nome do próprio jogador
        self.self_signal_t = None  # último sinal certeiro de "este ator é você"
        self.target_max = {}  # maior vida já vista de cada monstro (para achar boss)
        self.target_hp = {}  # vida mais recente de cada monstro
        self.boss_min_hp = float(load_config().get("vida_minima_boss", BOSS_MIN_HP))
        self.finished = []  # lutas de boss encerradas (a janela pega e guarda no histórico)
        self.dead_bosses = set()  # bosses que já morreram (não começam luta nova)
        self.reset()

    def reset(self):
        with self.lock:
            self._reset_counters()

    def _reset_counters(self):
        """Zera a contagem (com o lock já pego)."""
        if True:
            self.enc_state = "idle"  # modo boss: idle -> active (lutando) -> paused (morreu)
            self.enc_boss = None  # alvo principal da luta (o de mais vida)
            self.enc_boss_t = None
            self.damage = Counter()
            self.hits = Counter()
            self.biggest = Counter()
            self.combat_time = 0.0
            self.last_hit = None
            self.last_hit_wall = 0.0
            self.first_hit = None
            self.total_hits = 0
            self.was_party = set()  # quem bateu enquanto estava na pt
            self.active = Counter()  # tempo ativo de cada jogador (s), para o DPS individual
            self.last_hit_by = {}
            self.pvp_dmg, self.pvp_taken, self.pvp_hits = Counter(), Counter(), Counter()
            self.pvp_kills, self.pvp_deaths = Counter(), Counter()
            self.pvp_first = self.pvp_last = None
            self.pve_taken = Counter()  # dano que cada um recebeu de monstros
            self.deaths = Counter()  # mortes de cada um
            self.tgt_dmg = Counter()  # dano em cada alvo (para estimar quando o boss morre)

    @staticmethod
    def _utf16(b, off, size=64):
        raw = b[off:off + size]
        end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), len(raw))
        return raw[:end].decode("utf-16-le", "replace")

    def _member(self, b, e):
        """Bloco de membro da pt em b[e:]: (ator, (personagem, família, classe, nível))."""
        actor = struct.unpack_from("<I", b, e + 265)[0]
        name, family = self._utf16(b, e + 139), self._utf16(b, e + 73)
        return actor, (name, family, b[e + 16], b[e + 65])

    def on_party(self, b):
        count = b[0]
        if not 0 < count <= 20 or len(b) < PARTY_START + count * PARTY_ENTRY:
            return
        party = {}
        last = None
        for k in range(count):
            actor, info = self._member(b, PARTY_START + k * PARTY_ENTRY)
            if actor and info[0]:
                party[actor] = info
                last = actor
        with self.lock:
            self._replace_party(party)
            self.last_status_t = self.last_t  # lista nova = pt viva
            if last:  # o próprio jogador é sempre o último da lista
                self.self_votes[last] += 5
                self.self_actor = last
            self.known_names.update({a: v[0] for a, v in party.items()})
            self.known_info.update(party)
            names = dict(self.known_names)
        self.save_party_cache(party)
        self.save_names_cache(names)
        if last and party[last][2] is not None:
            classes = load_config().get("minhas_classes", {})
            if classes.get(party[last][0]) != party[last][2]:
                classes[party[last][0]] = party[last][2]
                save_config(minhas_classes=classes)

    def on_party_member(self, b):
        """Ficha de quem entra na pt (nome, família, classe, nível)."""
        if len(b) < PARTY_ENTRY:
            return
        actor, info = self._member(b, 0)
        if not actor or not info[0]:
            return
        with self.lock:
            self.known_info[actor] = info
            self.known_names[actor] = info[0]
            if actor in self.party:
                self.party[actor] = info
            party, names = dict(self.party), dict(self.known_names)
        self.save_party_cache(party)
        self.save_names_cache(names)

    # A lista da pt só chega ao entrar na pt. Como os IDs continuam os mesmos enquanto o
    # jogo está aberto, a última lista fica salva para quando o meter for reaberto.
    PARTY_CACHE = APP_DIR / "pt_cache.json"
    PARTY_CACHE_MAX_AGE = 12 * 3600

    @classmethod
    def load_party_cache(cls):
        try:
            data = json.loads(cls.PARTY_CACHE.read_text(encoding="utf-8"))
            if time.time() - data["salvo"] > cls.PARTY_CACHE_MAX_AGE:
                return {}, None
            # listas antigas não tinham classe e nível
            party = {int(a, 16): (tuple(v) + (None, None))[:4] for a, v in data["pt"].items()}
            return party, int(data["eu"], 16) if data.get("eu") else None
        except (OSError, ValueError, KeyError, TypeError):
            return {}, None

    def save_party_cache(self, party):
        data = {"salvo": time.time(), "pt": {f"{a:08x}": list(v) for a, v in party.items()},
                "eu": f"{self.self_actor:08x}" if self.self_actor else None}
        try:
            self.PARTY_CACHE.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        except OSError:
            pass

    def _replace_party(self, party):
        """Troca a pt (com o lock já pego), guardando os dados de quem saiu."""
        for a, entry in self.party.items():
            if a not in party:
                self.past_party[a] = entry
        self.party = party

    def on_party_status(self, b):
        """Atualiza quem está na pt: entra quem aparece, sai quem sumiu."""
        if len(b) < 13:
            return
        count = b[12]
        if not 0 < count <= 20 or len(b) < STATUS_ACTOR + STATUS_ENTRY * (count - 1) + 4:
            return
        actors = [struct.unpack_from("<I", b, STATUS_ACTOR + STATUS_ENTRY * k)[0]
                  for k in range(count)]
        with self.lock:
            self.status_seen = True
            self.last_status_t = self.last_t
            if set(actors) == set(self.party):
                return
            party = {}
            for a in actors:
                old = self.party.get(a)
                if old and old[0]:
                    party[a] = old
                elif a in self.known_info:  # recém-chegado cuja ficha já veio
                    party[a] = self.known_info[a]
                else:  # recém-chegado: nome do perfil, se já apareceu por perto
                    party[a] = (self.known_names.get(a) or (old[0] if old else None),
                                *(old[1:] if old else ("", None, None)))
            self._replace_party(party)
        self.save_party_cache(party)

    def on_profile(self, b):
        if len(b) < 10:
            return
        actor = struct.unpack_from("<I", b, len(b) - 4)[0]
        name = self._utf16(b, 6)
        if not actor or not name:
            return
        with self.lock:
            if self.known_names.get(actor) == name:
                return
            self.known_names[actor] = name
            if self.self_name and name == self.self_name:
                self.self_votes[actor] += 5
                self.self_actor = actor
            entry = self.party.get(actor)
            if entry and not entry[0]:
                self.party[actor] = (name,) + entry[1:]
            names = dict(self.known_names)
        self.save_names_cache(names)

    # Nomes aprendidos pelos perfis ficam salvos: o perfil só chega quando a pessoa aparece
    # por perto, então reabrir o meter não pode apagar o que ele já sabia.
    NAMES_CACHE = APP_DIR / "nomes_cache.json"
    NAMES_CACHE_MAX = 2000

    @classmethod
    def load_names_cache(cls):
        try:
            data = json.loads(cls.NAMES_CACHE.read_text(encoding="utf-8"))
            if time.time() - data["salvo"] > cls.PARTY_CACHE_MAX_AGE:
                return {}, {}
            names = {int(a, 16): n for a, n in data["nomes"].items()}
            info = {int(a, 16): tuple(v) for a, v in data.get("fichas", {}).items()}
            return names, info
        except (OSError, ValueError, KeyError, TypeError):
            return {}, {}

    def save_names_cache(self, names):
        items = list(names.items())[-self.NAMES_CACHE_MAX:]
        with self.lock:
            info = list(self.known_info.items())[-self.NAMES_CACHE_MAX:]
        data = {"salvo": time.time(), "nomes": {f"{a:08x}": n for a, n in items},
                "fichas": {f"{a:08x}": list(v) for a, v in info}}
        try:
            self.NAMES_CACHE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def check_party_alive(self, t):
        """Sem o estado da pt por PARTY_TIMEOUT: você não está mais em pt (fica só você)."""
        if not self.party:
            return
        since = self.last_status_t if self.last_status_t is not None else self.first_t
        if t - since > PARTY_TIMEOUT:
            with self.lock:
                self._replace_party({})
                self.was_party.clear()
            self.save_party_cache({})

    def on_message(self, t, m):
        if self.first_t is None:
            self.first_t = t
        self.last_t = t
        self.check_party_alive(t)
        self.check_boss_dead(t)
        if m[2] != 0 or len(m) < 6:
            return
        op = m[3] | m[4] << 8
        if op == OP_PARTY:
            self.on_party(m[5:])
            return
        if op == OP_PARTY_STATUS:
            self.on_party_status(m[5:])
            return
        if op == OP_PROFILE:
            self.on_profile(m[5:])
            return
        if op == OP_SELF_PROFILE:
            b = m[5:]
            name = self._utf16(b, 65) if len(b) > 65 + 4 else ""
            if name and name != self.self_name:
                self.self_name = name
                save_config(meu_personagem=name)
            return
        if op == OP_PARTY_MEMBER:
            self.on_party_member(m[5:])
            return
        if op in SELF_SIGNALS:
            size, pos = SELF_SIGNALS[op]
            if len(m) - 5 == size:
                self.self_signal_t = t  # este servidor manda os sinais certeiros
                self._vote_self(struct.unpack_from("<I", m, 5 + pos)[0], 1.0)
            return
        if op == OP_ATTACK:
            self.on_attack(t, m[5:])
            return
        if op != OP_HP or len(m) < 5 + 44:
            return
        b = m[5:]
        origin = struct.unpack_from("<q", b, 0)[0]
        value = struct.unpack_from("<f", b, 12)[0]
        who = struct.unpack_from("<I", b, 16)[0]
        target = struct.unpack_from("<I", b, 24)[0]
        max_hp = struct.unpack_from("<f", b, 36)[0]
        seq = struct.unpack_from("<I", b, 40)[0]
        with self.lock:
            if origin > 0:  # vida de jogador
                self.players[target] = max_hp
                prev_p = self.player_hp.get(target)
                self.player_hp[target] = value
                # PvP: um jogador tirando vida de outro (dano de monstro em jogador não entra;
                # IDs de jogador terminam em 02/03/0a, os de monstro não)
                if (prev_p is not None and value < prev_p and who != target
                        and who not in IGNORED_ATTACKERS
                        and (who in self.players or (who & 0xFF) in (0x02, 0x03, 0x0A))):
                    dmg_p = prev_p - value
                    self.pvp_dmg[who] += dmg_p
                    self.pvp_taken[target] += dmg_p
                    self.pvp_hits[who] += 1
                    if value <= 0:
                        self.pvp_kills[who] += 1
                        self.pvp_deaths[target] += 1
                    if self.pvp_first is None:
                        self.pvp_first = t
                    self.pvp_last = t
                    if self.pvp_mode:
                        self.last_hit_wall = time.time()
                elif (prev_p is not None and value < prev_p and who != target
                      and who not in IGNORED_ATTACKERS
                      and (not self.boss_mode or self.enc_state == "active")):
                    self.pve_taken[target] += prev_p - value  # dano de monstro
                if (prev_p is not None and prev_p > 0 and value <= 0
                        and (not self.boss_mode or self.enc_state == "active")):
                    self.deaths[target] += 1
                return
            self.max_hp[target] = max_hp
            self.target_max[target] = max(self.target_max.get(target, 0), max_hp)
            prev = self.hp.get(target, max_hp if seq == 1 else None)
            self.hp[target] = value
            if prev is None or value >= prev or who in IGNORED_ATTACKERS:
                return
            drop = prev - value
            if drop > max_hp > 0:
                return
            # golpes que a 0x16bc já contou estão "dentro" desta queda: desconta
            taken = min(drop, self.explained[target])
            self.explained[target] -= taken
            rest = drop - taken
        if rest > 0:
            self._credit(t, who, target, rest, prev, value, max_hp, seq)

    def on_attack(self, t, b):
        """Resultado de golpes (0x16bc): quem bateu, alvo, dano e vida que sobrou."""
        for e in range(ATTACK_START, len(b) - ATTACK_ENTRY + 1, ATTACK_ENTRY):
            who = struct.unpack_from("<I", b, e + 69)[0]
            target = struct.unpack_from("<I", b, e + 73)[0]
            dmg, value = struct.unpack_from("<ff", b, e + 77)
            if not who or not target or not (0 < dmg < 1e10) or not (0 <= value < 1e12):
                continue
            # golpes aqui também são de quem está perto: só servem de pista quando o
            # servidor não manda os sinais certeiros (0x141e/0x1c4b)
            if self.self_signal_t is None or t - self.self_signal_t > SELF_SIGNAL_WINDOW:
                self._vote_self(who, 0.5)
            with self.lock:
                if target in self.players:  # golpe em jogador: é PvP, não PvE
                    continue
                self.target_max[target] = max(self.target_max.get(target, 0), value + dmg)
                max_hp = self.max_hp.get(target, 0)
                if who not in IGNORED_ATTACKERS:
                    self.explained[target] += dmg
            if who not in IGNORED_ATTACKERS:
                self._credit(t, who, target, dmg, value + dmg, value, max_hp, None)

    def _tmax(self, target):
        return max(self.max_hp.get(target, 0), self.target_max.get(target, 0))

    def _end_encounter(self):
        """Boss morreu: pausa o tempo e guarda o resultado (com o lock já pego)."""
        if self.enc_state != "active":
            return
        self.enc_state = "paused"
        self.dead_bosses.add(self.enc_boss)
        summary = self._snapshot_nolock()
        summary["boss_vida"] = self._tmax(self.enc_boss) if self.enc_boss else 0
        summary["fim"] = time.time()
        summary["tipo"] = "boss"
        self.finished.append(summary)

    def take_unfinished(self):
        """Contagem que ainda não foi para o histórico (antes de zerar, trocar de modo ou fechar)."""
        with self.lock:
            if self.pvp_mode or (self.boss_mode and self.enc_state != "active"):
                return None  # PvP não vai ao histórico; boss já morto já foi salvo
            s = self._snapshot_nolock()
            if not s["total"] or s["tempo"] < UNFINISHED_MIN_TIME:
                return None
            s["boss_vida"] = 0  # luta incompleta não entra nos recordes
            s["fim"] = time.time()
            s["tipo"] = "boss (interrompida)" if self.boss_mode else "caça"
            return s

    def check_boss_dead(self, t):
        """Boss com pouca vida que parou de levar golpe também conta como morto."""
        if not self.boss_mode or self.enc_state != "active" or self.enc_boss is None:
            return
        with self.lock:
            b = self.enc_boss
            hp, tmax = self.target_hp.get(b), self._tmax(b)
            if (hp is not None and tmax and hp <= tmax * BOSS_LOW_FRAC
                    and self.enc_boss_t is not None and t - self.enc_boss_t > BOSS_IDLE_DEATH):
                self._end_encounter()

    def _vote_self(self, actor, weight):
        """Junta sinais de qual ator é o próprio jogador; votos antigos perdem força."""
        if not actor or actor in IGNORED_ATTACKERS:
            return
        with self.lock:
            other = self.known_names.get(actor)
            if self.self_name and other and other != self.self_name:
                return  # o perfil desse ator veio com outro nome: é outra pessoa
            for k in list(self.self_votes):
                self.self_votes[k] *= 0.98
            self.self_votes[actor] += weight
            best = max(self.self_votes, key=self.self_votes.get)
            if self.self_votes[best] >= 3 and best != self.self_actor:
                self.self_actor = best

    def _credit(self, t, who, target, dmg, prev, value, max_hp, seq):
        """Credita dano a quem bateu (vindo da 0x16bc, exato, ou da queda de vida da 0x0f4e)."""
        with self.lock:
            self.target_hp[target] = value
            if self.boss_mode:
                tmax = self._tmax(target)
                if tmax < self.boss_min_hp:
                    return  # boss/dg: adds e mobs comuns não contam
                ours = who in self.party or who == self.self_actor
                if self.enc_state != "active":
                    if not ours or target in self.dead_bosses or value <= tmax * BOSS_LOW_FRAC:
                        return  # só um golpe da pt num boss vivo começa uma luta
                    self._reset_counters()  # luta nova (a anterior já foi para o histórico)
                    self.enc_state = "active"
                if self.enc_boss is None or tmax > self._tmax(self.enc_boss):
                    self.enc_boss = target
                elif (target != self.enc_boss and tmax >= 0.5 * self._tmax(self.enc_boss)
                      and self.enc_boss_t is not None and t - self.enc_boss_t > BOSS_SWITCH_IDLE):
                    # o boss de antes parou de levar golpe e a pt bate em outro do mesmo porte:
                    # troca de fase (o jogo cria outro ator) ou o próximo boss da dg
                    self.dead_bosses.add(self.enc_boss)
                    self.enc_boss = target
                if target == self.enc_boss:
                    self.enc_boss_t = t
            # O tempo de combate só anda com golpes da pt e seus (quem está fora não conta)
            if who in self.party or who == self.self_actor:
                if self.last_hit is not None:
                    gap = t - self.last_hit
                    if 0 < gap <= COMBAT_GAP:
                        self.combat_time += gap
                if self.first_hit is None:
                    self.first_hit = t
                self.last_hit = t
                self.last_hit_wall = time.time()
            if who in self.party:
                self.was_party.add(who)
            prev_t = self.last_hit_by.get(who)
            if prev_t is not None and 0 < t - prev_t <= COMBAT_GAP:
                self.active[who] += t - prev_t
            self.last_hit_by[who] = t
            self.damage[who] += dmg
            self.tgt_dmg[target] += dmg
            self.hits[who] += 1
            self.total_hits += 1
            self.biggest[who] = max(self.biggest[who], dmg)
            if (self.boss_mode and target == self.enc_boss
                    and value <= self._tmax(target) * BOSS_DEATH_FRAC):
                self._end_encounter()
        if self.log_file:
            self.log.writerow([datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3],
                               f"{t:.3f}", f"{who:08x}", f"{target:08x}", f"{dmg:.0f}",
                               f"{prev:.0f}", f"{value:.0f}", f"{max_hp:.0f}",
                               "" if seq is None else seq])

    def snapshot(self):
        with self.lock:
            return self._snapshot_nolock()

    def _snapshot_nolock(self):
        if True:
            if self.pvp_mode:
                return self._pvp_snapshot()
            if self.boss_mode:  # a luta inteira, do 1º golpe da pt até agora (ou até o boss morrer)
                if self.first_hit is None:
                    tempo = 0.0
                elif (self.enc_state == "active"  # o relógio anda mesmo sem golpes (boss inalvejável)
                      and (self.last_t or 0) - self.last_hit < BOSS_ABANDON):
                    tempo = max(self.last_t or 0, self.last_hit) - self.first_hit
                else:
                    tempo = self.last_hit - self.first_hit
            else:  # grind: pausas maiores que COMBAT_GAP não contam
                tempo = self.combat_time
            dur = max(tempo, 1.0)

            def row(who, d):
                # boss: todos sobre o tempo da luta; grind: cada um sobre o próprio tempo ativo
                own = dur if self.boss_mode else max(self.active[who], 1.0)
                return {"ator": who, "dano": d, "pct": d / total if total else 0,
                        "dps": d / own, "ativo": self.active[who],
                        "golpes": self.hits[who], "maior": self.biggest[who],
                        "jogador": who in self.players or who in self.party,
                        "vida_max": self.players.get(who),
                        "recebido_pve": self.pve_taken[who], "mortes": self.deaths[who]}

            # O ranking é só da pt (sem pt conhecida, fica vazio); quem está fora vai à parte
            in_party = lambda who: (who in self.party or who in self.was_party
                                    or who == self.self_actor)
            ranked = [(w, d) for w, d in self.damage.most_common() if in_party(w)]
            total = sum(d for _, d in ranked)
            rows = [row(w, d) for w, d in ranked]
            # Membros da pt que ainda não causaram dano (parados, afk ou longe) vão no fim
            rows += [row(w, 0) for w in self.party if w not in self.damage]
            if self.self_actor and self.self_actor not in self.damage \
                    and self.self_actor not in self.party:
                rows.append(row(self.self_actor, 0))
            outside = [row(w, d) for w, d in self.damage.most_common() if not in_party(w)]
            boss_pct = eta = None
            if self.boss_mode and self.enc_boss is not None and self._tmax(self.enc_boss):
                hp_now = self.target_hp.get(self.enc_boss, 0)
                boss_pct = hp_now / self._tmax(self.enc_boss)
                rate = self.tgt_dmg[self.enc_boss] / dur  # dano por segundo no boss
                if self.enc_state == "active" and rate > 0 and tempo >= 5:
                    eta = hp_now / rate
            return {"total": total, "tempo": tempo, "dps": total / dur, "boss": self.boss_mode,
                    "pvp": False, "luta": self.enc_state, "boss_pct": boss_pct, "eta": eta,
                    "ativo": time.time() - self.last_hit_wall < COMBAT_GAP,
                    "golpes": sum(self.hits[w] for w, _ in ranked), "linhas": rows,
                    "fora": outside}

    def _pvp_snapshot(self):
        """Todos os jogadores lutando perto: dano causado, recebido, abates e mortes."""
        tempo = (self.pvp_last - self.pvp_first) if self.pvp_first is not None else 0.0
        dur = max(tempo, 1.0)
        total = sum(self.pvp_dmg.values())
        actors = sorted(set(self.pvp_dmg) | set(self.pvp_taken),
                        key=lambda a: (-self.pvp_dmg[a], -self.pvp_taken[a]))
        rows = [{"ator": a, "dano": self.pvp_dmg[a], "pct": self.pvp_dmg[a] / total if total else 0,
                 "dps": self.pvp_dmg[a] / dur, "ativo": tempo, "golpes": self.pvp_hits[a],
                 "maior": 0, "jogador": True, "vida_max": self.players.get(a),
                 "recebido": self.pvp_taken[a], "abates": self.pvp_kills[a],
                 "mortes": self.pvp_deaths[a]} for a in actors]
        return {"total": total, "tempo": tempo, "dps": total / dur, "boss": False, "pvp": True,
                "ativo": time.time() - self.last_hit_wall < COMBAT_GAP,
                "golpes": sum(self.pvp_hits.values()), "linhas": rows, "fora": []}

    def close(self):
        if self.log_file:
            self.log_file.close()


CONFIG_PATH = APP_DIR / "config.json"


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(**changes):
    cfg = load_config()
    cfg.update(changes)
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def fmt(n):
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(n) >= div:
            return f"{n / div:.1f}{suf}".replace(".", ",")
    return f"{n:.0f}"


def fmt_time(s):
    s = int(s)
    return f"{s // 60:02d}:{s % 60:02d}"


class MeterCapture(Capture):
    """Captura que, além de gravar, entrega as mensagens do servidor ao Combat."""

    def __init__(self, out_dir, process_names, combat, record=True):
        super().__init__(out_dir, process_names)
        self.combat = combat
        self.parsers = {}
        if not record:  # sem o tráfego bruto (captura.pcap): só os resultados
            self.writer.close()
            self.writer = None
            (out_dir / "captura.pcap").unlink(missing_ok=True)

    def _from_server(self, ip, port):
        ports = self.remote.get(ip)
        return ports is not None and (not ip.startswith("127.") or port in ports)

    def stop(self):
        if self.writer:
            super().stop()
        else:
            self.stop_event.set()
            if self.sniffer:
                self.sniffer.stop()

    def _store(self, pkt):
        if self.writer:
            super()._store(pkt)
        else:
            self.count += 1
        if TCP not in pkt:
            return
        ip, tcp = pkt[IP], pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload or not self._from_server(ip.src, tcp.sport):
            return
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        parser = self.parsers.setdefault(key, StreamParser())
        t = float(pkt.time)
        for m in parser.feed(tcp.seq, payload):
            self.combat.on_message(t, m)


def replay(cap_dir, combat, speed=None, stop=None):
    """Repete uma captura gravada pelo capture.py ou pelo meter."""
    servers = {}
    for line in (cap_dir / "info.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("servidor: "):
            ip, _, ports = line[len("servidor: "):].partition(" portas ")
            servers[ip] = {int(p) for p in ports.strip("[]").split(",") if p.strip()}
    parsers = {}
    start_wall = start_pkt = None
    for pkt in PcapReader(str(cap_dir / "captura.pcap")):
        if stop is not None and stop.is_set():
            return
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        ports = servers.get(ip.src)
        if ports is None or (ip.src.startswith("127.") and tcp.sport not in ports):
            continue
        payload = bytes(tcp.payload)
        if not payload:
            continue
        t = float(pkt.time)
        if speed:
            if start_wall is None:
                start_wall, start_pkt = time.time(), t
            wait = (t - start_pkt) / speed - (time.time() - start_wall)
            if wait > 0:
                time.sleep(wait)
        parser = parsers.setdefault((ip.src, tcp.sport, ip.dst, tcp.dport), StreamParser())
        for m in parser.feed(tcp.seq, payload):
            combat.on_message(t, m)


class Session:
    """Pasta da sessão, nomes dados pelo usuário e o resumo em txt."""

    def __init__(self, out_dir, combat):
        self.out_dir = out_dir
        self.combat = combat
        self.names = {}  # nomes dados à mão (têm prioridade)
        self.me = None
        self.my_name = load_config().get("meu_personagem")
        self.notes = MarkerLog(out_dir / "marcadores.csv")
        self.started = time.time()

    def party_name(self, actor):
        with self.combat.lock:
            entry = self.combat.party.get(actor) or self.combat.past_party.get(actor)
        return entry[0] if entry else None

    def party_class_code(self, actor):
        with self.combat.lock:
            entry = (self.combat.party.get(actor) or self.combat.past_party.get(actor)
                     or self.combat.known_info.get(actor))
            if entry and entry[2] is not None:
                return entry[2]
            # o ID muda ao trocar de canal: procura uma ficha antiga com o mesmo nome
            name = (self.names.get(actor) or self.combat.known_names.get(actor)
                    or (entry[0] if entry else None))
            info = list(self.combat.known_info.values())
        if not name and self.is_me(actor):
            name = self.combat.self_name or self.my_name
        if name:
            for v in reversed(info):
                if v[0] == name and v[2] is not None:
                    return v[2]
        if self.is_me(actor):  # sem pt: a classe guardada da última vez que você entrou numa
            mine = self.combat.self_name or self.my_name or name
            code = load_config().get("minhas_classes", {}).get(mine) if mine else None
            if code is not None:
                return code
        return None

    def party_class(self, actor):
        with self.combat.lock:
            entry = self.combat.party.get(actor) or self.combat.past_party.get(actor)
        return class_name(entry[2]) if entry else ""

    def my_actor(self):
        """Você: marcado à mão > pelo nome salvo na pt > detectado pelo meter."""
        if self.me is not None:
            return self.me
        with self.combat.lock:
            party = dict(self.combat.party)
            detected = self.combat.self_actor
        if self.my_name:
            for a, v in party.items():
                if v[0] == self.my_name:
                    return a
        if detected in party and party[detected][0] and party[detected][0] != self.my_name:
            self.my_name = party[detected][0]  # lembra o seu nome para quando estiver sem pt
            save_config(meu_personagem=self.my_name)
        return detected

    def is_me(self, actor):
        return actor == self.my_actor()

    def set_me(self, actor):
        self.me = None if self.me == actor else actor
        if self.me is not None:
            with self.combat.lock:
                self.combat.self_actor = actor
        name = self.party_name(actor) or self.names.get(actor)
        if self.me is not None and name:
            self.my_name = name
            save_config(meu_personagem=name)

    def label(self, actor, mark_me=False):
        with self.combat.lock:
            known = self.combat.known_names.get(actor)
            left = actor not in self.combat.party and actor in self.combat.past_party
        me = self.is_me(actor)
        mine = self.combat.self_name or self.my_name
        name = (self.names.get(actor) or self.party_name(actor) or known
                or (mine if me else None) or ("Você" if me else f"{actor:08x}"))
        if me:  # "(você)" só no resumo.txt; na janela o contorno dourado já indica
            return f"{name} (você)" if mark_me else name
        return f"{name} (saiu)" if left else name

    HISTORY = APP_DIR / "historico.json"
    HISTORY_MAX = 100

    def load_history(self):
        try:
            return json.loads(self.HISTORY.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def add_history(self, s):
        """Guarda uma luta de boss encerrada (com nomes e classes já resolvidos)."""
        item = {
            "quando": datetime.fromtimestamp(s.get("fim", time.time())).strftime("%d/%m %H:%M"),
            "tempo": s["tempo"], "total": s["total"], "dps": s["dps"],
            "boss_vida": s.get("boss_vida", 0), "tipo": s.get("tipo", "boss"),
            "linhas": [[self.label(r["ator"]), r["dano"], r["dps"], r["pct"],
                        self.party_class_code(r["ator"]), self.is_me(r["ator"]),
                        r.get("recebido_pve", 0), r.get("mortes", 0)]
                       for r in s["linhas"] if r["dano"] > 0 or r.get("mortes")],
        }
        hist = self.load_history()
        # recorde: o mesmo boss tem sempre a mesma vida máxima
        same = [h for h in hist if h.get("boss_vida") and item["boss_vida"]
                and abs(h["boss_vida"] - item["boss_vida"]) <= 0.005 * item["boss_vida"]]
        if same:
            best = min(h["tempo"] for h in same)
            item["recorde_tempo"] = best
            best_dps = {}
            for h in same:
                for row in h["linhas"]:
                    best_dps[row[0]] = max(best_dps.get(row[0], 0), row[2])
            item["recordes_dps"] = [row[0] for row in item["linhas"]
                                    if row[0] in best_dps and row[2] > best_dps[row[0]]]
        hist.append(item)
        try:
            self.HISTORY.write_text(json.dumps(hist[-self.HISTORY_MAX:], ensure_ascii=False),
                                    encoding="utf-8")
        except OSError:
            pass
        self.add_note(f"[{item['tipo']} salva] {fmt_time(item['tempo'])} total {item['total']:,.0f}")
        return item

    def add_note(self, text):
        self.notes.append((time.time(), "nota", text))

    def write_summary(self):
        s = self.combat.snapshot()
        lines = [
            f"Resumo do DPS Meter BDO - {datetime.now():%d/%m/%Y %H:%M:%S}",
            f"Sessão iniciada: {datetime.fromtimestamp(self.started):%H:%M:%S}",
            "Modo: " + ("PVP (dano entre jogadores, tempo = luta inteira)" if s["pvp"] else
                        "BOSS/DG (tempo = luta inteira)" if s["boss"] else "grind"),
            f"Tempo de combate: {fmt_time(s['tempo'])}   Dano total: {s['total']:,.0f}"
            f"   DPS da pt: {s['dps']:,.0f}   Golpes: {s['golpes']}",
            "",
            f"{'jogador':<24}{'dano':>16}{'%':>8}{'DPS':>14}{'ativo':>8}{'golpes':>8}{'maior golpe':>14}"
            f"{'vida máx':>10}",
        ]
        for r in s["linhas"]:
            tipo = "" if r["jogador"] else " [?]"
            vida = f"{r['vida_max']:.0f}" if r["vida_max"] else "-"
            lines.append(
                f"{self.label(r['ator'], True) + tipo:<24}{r['dano']:>16,.0f}{r['pct']:>8.1%}"
                f"{r['dps']:>14,.0f}{fmt_time(r['ativo']):>8}{r['golpes']:>8}{r['maior']:>14,.0f}{vida:>10}"
            )
        if not s["pvp"] and any(r.get("recebido_pve") or r.get("mortes") for r in s["linhas"]):
            lines += ["", "Dano recebido de monstros / mortes:"]
            lines += [f"  {self.label(r['ator'], True)}: recebeu {r.get('recebido_pve', 0):,.0f}, "
                      f"{r.get('mortes', 0)} mortes" for r in s["linhas"]]
        if s["pvp"]:
            lines += ["", "PvP (recebido / abates / mortes):"]
            lines += [f"  {self.label(r['ator'], True)}: recebeu {r['recebido']:,.0f}, "
                      f"{r['abates']} abates, {r['mortes']} mortes" for r in s["linhas"]]
        if s["fora"]:
            lines += ["", "Fora da pt (não aparecem na janela):"]
            lines += [f"  {self.label(r['ator'], True)}: {r['dano']:,.0f} em {r['golpes']} golpes"
                      for r in s["fora"]]
        with self.combat.lock:
            players = dict(self.combat.players)
            party = dict(self.combat.party)
        lines += ["", "Pt (ator: personagem / família):"]
        lines += [f"  {a:08x}: {n or '(nome ainda desconhecido)'}"
                  + (f" / {f}" if f else "") + (f" / {class_name(c)}" if c is not None else "")
                  + (f" nv. {lv}" if lv else "")
                  for a, (n, f, c, lv) in party.items()] or [
            "  (lista da pt não recebida: entre na pt com o meter aberto)"]
        lines += ["", "Jogadores vistos (ator: vida máxima):"]
        lines += [f"  {self.label(a, True)}: {v:.0f}" for a, v in players.items()]
        lines += ["", "[?] = quem causou dano mas não foi visto como jogador (pet, invocação, outro)"]
        (self.out_dir / "resumo.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def close(self):
        self.write_summary()
        self.notes.close()
        self.combat.close()


# --- Janela ---
BG, PANEL, TRACK, LINE = "#0f1115", "#171a21", "#1d2129", "#2a2f3a"
FG, MUTED, DIM, GOLD, GREEN = "#e8eaed", "#7d8590", "#4a505c", "#e0a83a", "#3fbf7f"
PALETTE = ["#4f8ff7", "#e05d6f", "#3fbf8f", "#a77bf3", "#f08c3c", "#36b9cc", "#d4c24a", "#e86fb5"]
UI, NUM, ICONS = "Segoe UI", "Bahnschrift", "Segoe MDL2 Assets"
ICON_RESET, ICON_PIN, ICON_CLOSE, ICON_NOTE, ICON_COPY = "", "", "", "", ""

GWL_EXSTYLE = -20
WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_APPWINDOW = 0x08000000, 0x00000080, 0x00040000
WS_EX_TRANSPARENT, WS_EX_LAYERED = 0x00000020, 0x00080000
MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 0x1, 0x2, 0x4, 0x8, 0x4000
WM_HOTKEY = 0x0312
SW_HIDE, SW_SHOWNOACTIVATE = 0, 4
AUTO_LOCK = 15.0  # segundos destravado sem uso até travar sozinho
RESTART_CODE = 3  # código de saída que faz o meter.bat abrir o meter de novo
UPDATE_IDLE = 10.0  # segundos sem combate para aplicar uma atualização sozinho
# no .exe não há código para vigiar: atualização é trocar a pasta
WATCHED = [] if FROZEN else [APP_DIR / n for n in ("meter.py", "capture.py")]
ICON_UPDATE = ""
ICON_HISTORY = "\ue81c"


def parse_hotkey(text):
    """'alt+x' -> (modificadores, tecla virtual)."""
    mods, vk = 0, None
    for part in text.lower().replace(" ", "").split("+"):
        if part in ("alt",):
            mods |= MOD_ALT
        elif part in ("ctrl", "control"):
            mods |= MOD_CONTROL
        elif part == "shift":
            mods |= MOD_SHIFT
        elif part == "win":
            mods |= MOD_WIN
        elif len(part) == 1 and part.isalnum():
            vk = ord(part.upper())
        elif part.startswith("f") and part[1:].isdigit() and 1 <= int(part[1:]) <= 12:
            vk = 0x70 + int(part[1:]) - 1
    return mods, vk


class HotKey(threading.Thread):
    """Atalho global registrado no Windows (RegisterHotKey, como Discord/OBS).

    Não lê o teclado: o Windows só avisa quando a combinação é apertada."""

    def __init__(self, text):
        super().__init__(daemon=True)
        self.text = text
        self.pressed = threading.Event()
        self.ready = threading.Event()
        self.ok = False

    def run(self):
        import ctypes
        import ctypes.wintypes as wt
        user32 = ctypes.windll.user32
        mods, vk = parse_hotkey(self.text)
        self.ok = vk is not None and bool(user32.RegisterHotKey(None, 1, mods | MOD_NOREPEAT, vk))
        self.ready.set()
        if not self.ok:
            return
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            if msg.message == WM_HOTKEY:
                self.pressed.set()


def blend(c1, c2, a):
    """Mistura c1 sobre c2 (a = quanto de c1)."""
    x = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    y = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(p * a + q * (1 - a)):02x}" for p, q in zip(x, y))


def rounded(canvas, x1, y1, x2, y2, r, **kw):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


# Cor de cada classe nas barras (as que não estão aqui usam a PALETTE)
CLASS_COLORS = {
    7: "#2fa889", 12: "#d0643a", 15: "#c24f7c", 27: "#7b52d6", 30: "#3a8fd6",
    0: "#c9473f", 4: "#5aa548", 8: "#8e44ad", 16: "#d9a63a", 20: "#3f74c9", 21: "#d65a8a",
    24: "#d4b44a", 25: "#4b9d9d", 26: "#465a9e", 28: "#3d6fd1", 31: "#b44fc9",
}


def hex_rgb(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


def mix(a, b, t):
    """t de a + (1 - t) de b (cores em tupla RGB)."""
    return tuple(int(x * t + y * (1 - t)) for x, y in zip(a, b))


def render_bar(w, h, color, frac, outline=None, radius=7):
    """Barra arredondada: trilho escuro na cor da classe + preenchimento em gradiente."""
    from PIL import Image, ImageDraw
    base = hex_rgb(color)
    img = Image.new("RGBA", (w, h), mix(base, hex_rgb(BG), 0.20) + (255,))
    fw = int(round(w * max(0.0, min(1.0, frac))))
    if fw > 0:
        left, right = mix(base, (255, 255, 255), 0.95), mix(base, (0, 0, 0), 0.50)
        strip = Image.new("RGBA", (fw, 1))
        strip.putdata([mix(left, right, 1 - x / max(1, fw - 1)) + (255,) for x in range(fw)])
        img.paste(strip.resize((fw, h)), (0, 0))
    shine = Image.new("L", (1, h))
    shine.putdata([int(38 * max(0.0, 1 - y / (h * 0.55))) for y in range(h)])
    glow = Image.new("RGBA", (w, h), (255, 255, 255, 0))
    glow.putalpha(shine.resize((w, h)))
    img = Image.alpha_composite(img, glow)
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w - 1, h - 1), radius=radius, fill=255)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    if outline:
        ImageDraw.Draw(out).rounded_rectangle((0, 0, w - 1, h - 1), radius=radius,
                                              outline=hex_rgb(outline) + (255,), width=2)
    return out


ICON_URL = ("https://static.pearlcdn.com/asset/portal/bdo_sa/contents/img/classes/"
            "class_{}/class_detail_top_symbol.png")


def extract_emblem(im):
    """Recorta o emblema do meio da faixa do site oficial e tira o fundo."""
    from PIL import Image
    im = im.convert("RGBA")
    w, h = im.size
    crop = im.crop((w // 2 - 110, 30, w // 2 + 110, h))
    px = crop.load()
    cw, ch = crop.size
    # cor do fundo: mediana das colunas das pontas, na parte de baixo da faixa
    samples = [px[x, y][:3] for x in (2, 3, cw - 3, cw - 2) for y in range(ch - 60, ch - 5)]
    bg_light = sum(sorted(c[i] for c in samples)[len(samples) // 2] for i in range(3)) / 3
    # topo da faixa em cada coluna (onde a imagem fica opaca); a borda curva fica logo abaixo
    top = [next((y for y in range(ch) if px[x, y][3] > 250), ch) for x in range(cw)]
    out = Image.new("RGBA", crop.size)
    po = out.load()
    for y in range(ch):
        for x in range(cw):
            r, g, b, a = px[x, y]
            if a < 250 or y < top[x] + 10:
                continue
            alpha = max(0, min(255, int(((r + g + b) / 3 - bg_light - 18) * 5)))
            po[x, y] = (r, g, b, alpha)
    box = out.getchannel("A").point(lambda v: 255 if v > 60 else 0).getbbox()
    if not box:
        return None
    out = out.crop(box)
    side = max(out.size) + 4
    square = Image.new("RGBA", (side, side))
    square.paste(out, ((side - out.width) // 2, (side - out.height) // 2))
    return square.resize((64, 64), Image.LANCZOS)


def download_icons():
    """Baixa do site oficial os emblemas que faltam, no PC de quem usa (não vão no pacote)."""
    import io
    import urllib.request
    from PIL import Image
    ICONS_DIR.mkdir(exist_ok=True)
    for code in CLASSES:
        f = ICONS_DIR / f"class_{code}.png"
        if f.exists():
            continue
        try:
            req = urllib.request.Request(ICON_URL.format(code), headers={"User-Agent": "Mozilla/5.0"})
            data = urllib.request.urlopen(req, timeout=15).read()
            icon = extract_emblem(Image.open(io.BytesIO(data)))
            if icon:
                icon.save(f)
        except Exception:
            continue  # sem internet ou site mudou: fica o selo com a sigla


def icons_missing():
    return any(not (ICONS_DIR / f"class_{c}.png").exists() for c in CLASSES)


def class_initials(code):
    name = CLASSES.get(code, "?")
    parts = [p for p in re.split(r"[\s-]+", name) if p[:1].isupper()]
    return ("".join(p[0] for p in parts[:2]) if len(parts) > 1 else name[:2]).upper()


def render_badge(d, color, icon_path, code=None):
    """Ícone da classe dentro de um círculo escuro na cor da classe."""
    from PIL import Image, ImageDraw
    base = hex_rgb(color)
    scale = 4  # desenha grande e reduz, para o círculo ficar liso
    size = d * scale
    big = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(big).ellipse((0, 0, size - 1, size - 1),
                                fill=mix(base, (0, 0, 0), 0.22) + (255,),
                                outline=mix(base, (255, 255, 255), 0.6) + (255,), width=scale)
    try:
        # o símbolo é encaixado no tamanho grande e reduzido junto com o círculo, assim o
        # centro não fica meio pixel torto por arredondamento
        alpha = Image.open(icon_path).convert("RGBA").getchannel("A")
        box = alpha.point(lambda v: 255 if v > 40 else 0).getbbox()
        if box:
            alpha = alpha.crop(box)
        k = size * 0.62 / max(alpha.size)  # símbolo com margem dentro do círculo
        w, h = max(1, round(alpha.width * k)), max(1, round(alpha.height * k))
        alpha = alpha.resize((w, h), Image.LANCZOS).point(lambda v: min(255, int(v * 1.8)))
        light = Image.new("RGBA", (w, h), (255, 244, 214, 255))
        light.putalpha(alpha)
        big.alpha_composite(light, ((size - w) // 2, (size - h) // 2))
        return big.resize((d, d), Image.LANCZOS)
    except OSError:  # ícone ainda não baixado: sigla da classe
        out = big.resize((d, d), Image.LANCZOS)
        from PIL import ImageFont
        try:
            font = ImageFont.truetype("segoeuib.ttf", int(d * 0.42))
        except OSError:
            font = ImageFont.load_default()
        ImageDraw.Draw(out).text((d / 2, d / 2), class_initials(code), font=font,
                                 fill=(255, 244, 214, 255), anchor="mm")
    return out


class NoFocus:
    """Controla como a janela convive com o jogo.

    Sempre não ativável (cliques não tiram o teclado do jogo). Travada, também é
    "fantasma": o mouse passa direto para o jogo, como se a janela não existisse."""

    def __init__(self, root):
        import ctypes
        self.user32 = ctypes.windll.user32
        root.update_idletasks()
        self.hwnd = self.user32.GetParent(root.winfo_id()) or root.winfo_id()
        self.previous = None
        self.noactivate = True
        self.locked = True
        self._apply()
        # o Windows só cria o botão da barra de tarefas ao mostrar a janela de novo;
        # SW_SHOWNOACTIVATE mostra sem tirar o foco do jogo
        self.user32.ShowWindow(self.hwnd, SW_HIDE)
        self.user32.ShowWindow(self.hwnd, SW_SHOWNOACTIVATE)
        self.hidden = False

    def set_hidden(self, hidden):
        self.hidden = hidden
        self.user32.ShowWindow(self.hwnd, SW_HIDE if hidden else SW_SHOWNOACTIVATE)

    def _apply(self):
        style = self.user32.GetWindowLongW(self.hwnd, GWL_EXSTYLE)
        style = (style | WS_EX_APPWINDOW | WS_EX_LAYERED) & ~WS_EX_TOOLWINDOW
        style = style | WS_EX_NOACTIVATE if self.noactivate else style & ~WS_EX_NOACTIVATE
        style = style | WS_EX_TRANSPARENT if self.locked else style & ~WS_EX_TRANSPARENT
        self.user32.SetWindowLongW(self.hwnd, GWL_EXSTYLE, style)

    def set_locked(self, locked):
        self.locked = locked
        self._apply()

    def grab_keyboard(self, root):
        """Só quando o usuário escolhe digitar: pega o teclado e lembra quem tinha."""
        self.previous = self.user32.GetForegroundWindow()
        self.noactivate = False
        self._apply()
        root.focus_force()

    def give_back(self):
        self.noactivate = True
        self._apply()
        if self.previous:
            self.user32.SetForegroundWindow(self.previous)
        self.previous = None


class IconButton(tk.Label):
    def __init__(self, parent, icon, command, bg=PANEL, size=9):
        super().__init__(parent, text=icon, font=(ICONS, size), bg=bg, fg=MUTED,
                         padx=6, pady=4, cursor="hand2")
        self.command, self.active = command, False
        self.bind("<Button-1>", lambda e: self.command())
        self.bind("<Enter>", lambda e: self.config(fg=FG))
        self.bind("<Leave>", lambda e: self.config(fg=GOLD if self.active else MUTED))

    def set_active(self, on):
        self.active = on
        self.config(fg=GOLD if on else MUTED)


class MeterWindow:
    ROW_H, ROW_GAP = 28, 3
    ALPHA_MIN, ALPHA_MAX = 0.35, 0.98  # máx. < 1: a janela precisa ficar "em camadas"
    YELLOW = "#ffd36b"

    def __init__(self, session, status_fn):
        self.session = session
        self.status_fn = status_fn
        self.rows = []
        self.colors = {}
        self.bars = {}    # cache das imagens das barras
        self.badges = {}  # cache dos ícones das classes
        self.menu = None
        self.typing = None  # ("nota", None) ou ("nome", ator)
        self.flash = ("", 0.0)
        self.restart_requested = False
        self.view = None  # None (normal), ("resumo", luta, automático?) ou ("historico",)
        self.view_hits = []  # áreas clicáveis do resumo/histórico: (x1, y1, x2, y2, ação)
        self.update_ready = False
        self.banner = None  # faixa clicável no topo (ex.: "update")
        self.mtimes = self.read_mtimes()
        cfg = load_config()
        if cfg.get("acabou_de_atualizar"):
            self.flash = ("meter atualizado!", time.time() + 4)
            save_config(acabou_de_atualizar=False)

        root = self.root = tk.Tk()
        root.title("DPS Meter BDO")
        try:
            root.iconbitmap(default=str(RES_DIR / "bdometer.ico"))
        except tk.TclError:
            pass
        root.overrideredirect(True)
        root.configure(bg=LINE)
        root.attributes("-topmost", True)
        self.alpha = min(self.ALPHA_MAX, float(cfg.get("opacidade", 0.92)))
        root.attributes("-alpha", self.alpha)
        root.geometry(cfg.get("janela", "400x230+40+40"))

        shell = tk.Frame(root, bg=BG)
        shell.pack(fill="both", expand=True, padx=1, pady=1)

        # Barra de título: tempo, nome, tamanho da pt, total e botões
        title = tk.Frame(shell, bg=PANEL)
        title.pack(fill="x")
        self.timer = tk.Label(title, text="00:00", font=(NUM, 10, "bold"), bg=PANEL, fg=MUTED)
        self.timer.pack(side="left", padx=(10, 8), pady=3)
        self.pending = (None, 0.0)  # ação esperando o 2º clique de confirmação
        IconButton(title, ICON_CLOSE,
                   lambda: self.confirm("fechar", "clique de novo para fechar", self.close)
                   ).pack(side="right")
        self.pin_btn = IconButton(title, ICON_PIN, self.toggle_pin)
        self.pin_btn.pack(side="right")
        self.pin_btn.set_active(True)
        IconButton(title, ICON_RESET,
                   lambda: self.confirm("zerar", "clique de novo para zerar", self.reset)
                   ).pack(side="right")
        self.pve_btn = tk.Label(title, text="PVE", font=(UI, 7, "bold"), padx=6, pady=1,
                                cursor="hand2")
        self.pve_btn.pack(side="left", padx=(0, 4))
        self.pve_btn.bind("<Button-1>", lambda e: self.set_mode(False, False))
        self.pvp_btn = tk.Label(title, text="PVP", font=(UI, 7, "bold"), padx=6, pady=1,
                                cursor="hand2")
        self.pvp_btn.pack(side="left", padx=(0, 4))
        self.pvp_btn.bind("<Button-1>", lambda e: self.toggle_pvp())
        self.boss_btn = tk.Label(title, text="BOSS", font=(UI, 7, "bold"), padx=6, pady=1,
                                 cursor="hand2")
        self.boss_btn.pack(side="left", padx=(0, 4))
        self.boss_btn.bind("<Button-1>", lambda e: self.toggle_boss())
        self.guide_btn = tk.Label(title, text="GUIA", font=(UI, 7, "bold"), padx=6, pady=1,
                                  cursor="hand2", bg="#262a33", fg=MUTED)
        self.guide_btn.pack(side="left", padx=(0, 4))
        self.guide_btn.bind("<Button-1>", lambda e: self.toggle_guide())
        self.paint_boss_btn()
        # linha de informações: total, DPS da pt e tamanho da pt (sempre cabe)
        info = tk.Frame(shell, bg=BG)
        info.pack(fill="x", padx=10, pady=(4, 0))
        self.totals = tk.Label(info, font=(NUM, 9), bg=BG, fg=MUTED, anchor="w")
        self.totals.pack(side="left")
        self.pill = tk.Label(info, text="PT", font=(UI, 7, "bold"), bg="#3a2a12", fg=GOLD,
                             padx=5, pady=0)
        self.pill.pack(side="right")
        for w in (title, info, self.timer, self.totals):
            w.bind("<ButtonPress-1>", self.start_move)
            w.bind("<B1-Motion>", self.on_move)
            w.bind("<MouseWheel>", self.on_wheel)

        # Rodapé: status, opacidade, nota, copiar, redimensionar
        footer = tk.Frame(shell, bg=PANEL)
        footer.pack(side="bottom", fill="x")
        grip = tk.Label(footer, text="", font=(ICONS, 8), bg=PANEL, fg=DIM,
                        cursor="size_nw_se")
        grip.pack(side="right", padx=(0, 3))
        grip.bind("<ButtonPress-1>", self.start_resize)
        grip.bind("<B1-Motion>", self.on_resize)
        # no .exe o botão só reinicia o meter; no meter.py também aplica atualização
        self.update_btn = IconButton(
            footer, ICON_UPDATE,
            lambda: self.confirm("reiniciar", "clique de novo para reiniciar o meter",
                                 self.restart_app if FROZEN else self.restart), size=8)
        self.update_btn.pack(side="right")
        IconButton(footer, ICON_COPY, self.copy_ranking, size=8).pack(side="right")
        IconButton(footer, ICON_HISTORY, self.show_history, size=8).pack(side="right")
        IconButton(footer, ICON_NOTE, lambda: self.start_typing("nota"), size=8).pack(side="right")
        self.alpha_label = tk.Label(footer, font=(NUM, 8), bg=PANEL, fg=MUTED, width=4)
        self.alpha_label.pack(side="right")
        self.slider = tk.Canvas(footer, width=70, height=14, bg=PANEL, highlightthickness=0,
                                cursor="hand2")
        self.slider.pack(side="right", padx=(4, 2))
        self.slider.bind("<Button-1>", self.on_slider)
        self.slider.bind("<B1-Motion>", self.on_slider)
        tk.Label(footer, text="Opacidade", font=(UI, 7), bg=PANEL, fg=MUTED).pack(side="right")
        self.status = tk.Label(footer, font=(UI, 7), bg=PANEL, fg=MUTED, anchor="w")
        self.status.pack(side="left", fill="x", expand=True, padx=(8, 4))
        self.draw_slider()

        # Barra de digitação (aparece só ao anotar ou renomear)
        self.type_bar = tk.Frame(shell, bg=PANEL)
        self.type_label = tk.Label(self.type_bar, font=(UI, 8), bg=PANEL, fg=MUTED)
        self.type_label.pack(side="left", padx=(10, 6))
        self.entry = tk.Entry(self.type_bar, bg=TRACK, fg=FG, insertbackground=FG, relief="flat",
                              font=(UI, 9))
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=5, ipady=2)
        self.entry.bind("<Return>", self.finish_typing)
        self.entry.bind("<Escape>", lambda e: self.stop_typing())
        self.entry.bind("<FocusOut>", lambda e: self.typing and self.stop_typing())
        self.footer = footer

        self.canvas = tk.Canvas(shell, bg=BG, highlightthickness=0, height=40)
        self.canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.canvas.bind("<Button-3>", self.open_menu)
        self.canvas.bind("<Button-1>", self.on_canvas_click)
        self.canvas.bind("<MouseWheel>", self.scroll_guide)
        self.guide_max = 0

        self.nofocus = NoFocus(root)
        self.tray_actions = queue.Queue()  # cliques no menu da bandeja (vêm de outra thread)
        self.tray = self.start_tray()
        self.last_use = time.time()
        root.bind_all("<Motion>", lambda e: setattr(self, "last_use", time.time()), add="+")
        root.bind_all("<Button>", lambda e: setattr(self, "last_use", time.time()), add="+")
        self.hotkey = None
        for combo in (cfg.get("atalho", "alt+x"), "ctrl+alt+x", "ctrl+shift+f10"):
            hk = HotKey(combo)
            hk.start()
            hk.ready.wait(1)
            if hk.ok:
                self.hotkey = hk
                break
        # atalhos rápidos (funcionam com a janela travada): zerar e alternar PVE/BOSS
        self.extra_hotkeys = []
        for key, default, action in (("atalho_zerar", "alt+z", self.reset),
                                     ("atalho_modo", "alt+b", self.toggle_pve_boss)):
            hk = HotKey(cfg.get(key, default))
            hk.start()
            hk.ready.wait(1)
            if hk.ok:
                self.extra_hotkeys.append((hk, action))
        self.need_npcap = not npcap_installed()
        self.npcap_state = None  # None, "baixando", "instalando"
        self.set_locked(not self.need_npcap)  # sem Npcap: destravada, para clicar na faixa
        root.after(50, self.poll_hotkey)
        root.after(200, self.refresh)
        root.after(3000, self.save_summary)
        root.after(2000, self.check_update)

    # --- atualização sem fechar e abrir ---
    @staticmethod
    def read_mtimes():
        out = {}
        for f in WATCHED:
            try:
                out[f] = f.stat().st_mtime
            except OSError:
                pass
        return out

    def check_update(self):
        if FROZEN:  # no .exe a versão nova só é instalada quando a pessoa clica no aviso
            return
        if not self.update_ready and self.read_mtimes() != self.mtimes:
            self.update_ready = True
            self.update_btn.set_active(True)
        if self.update_ready:
            idle = time.time() - self.session.combat.last_hit_wall > UPDATE_IDLE
            if idle and not self.typing and self.nofocus.locked:
                self.restart()
                return
        self.root.after(2000, self.check_update)

    def restart(self):
        """Fecha salvando tudo e pede ao meter.bat para abrir a versão nova."""
        try:
            compile(Path(__file__).read_text(encoding="utf-8"), "meter.py", "exec")
        except (SyntaxError, OSError) as e:  # nunca reinicia para uma versão quebrada
            self.flash = (f"atualização com erro, mantendo a versão atual ({e.__class__.__name__})",
                          time.time() + 6)
            self.update_ready = False
            self.mtimes = self.read_mtimes()
            return
        self.restart_requested = True
        save_config(acabou_de_atualizar=True)
        self.close()

    # --- travar / destravar ---
    def hotkey_name(self):
        return self.hotkey.text.upper() if self.hotkey else "?"

    def set_locked(self, locked):
        self.close_menu()
        self.nofocus.set_locked(locked)
        self.root.configure(bg=LINE if locked else GOLD)  # borda dourada = destravado
        self.last_use = time.time()

    def toggle_pve_boss(self):
        self.set_mode(not self.session.combat.boss_mode, False)

    def start_tray(self):
        """Ícone na área de notificação do Windows, com um menu do meter."""
        try:
            import pystray
            from PIL import Image
            image = Image.open(RES_DIR / "bdometer.png")
        except Exception:
            return None
        act = lambda name: (lambda icon, item: self.tray_actions.put(name))
        menu = pystray.Menu(
            pystray.MenuItem("Mostrar / esconder", act("mostrar"), default=True),
            pystray.MenuItem("Destravar a janela", act("destravar")),
            pystray.MenuItem("Zerar a contagem", act("zerar")),
            pystray.MenuItem("Guia", act("guia")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"Fechar (v{VERSION})", act("fechar")),
        )
        icon = pystray.Icon("DPSMeterBDO", image, "DPS Meter BDO", menu)
        threading.Thread(target=icon.run, daemon=True).start()
        return icon

    def run_tray_actions(self):
        while not self.tray_actions.empty():
            name = self.tray_actions.get()
            if name == "mostrar":
                self.nofocus.set_hidden(not self.nofocus.hidden)
            elif name == "destravar":
                self.nofocus.set_hidden(False)
                self.set_locked(False)
            elif name == "zerar":
                self.reset()
            elif name == "guia":
                self.nofocus.set_hidden(False)
                self.view = ("guia", 0, 0)
            elif name == "fechar":
                self.close()
                return True
        return False

    def poll_hotkey(self):
        if self.run_tray_actions():
            return  # fechou pelo menu da bandeja
        for hk, action in self.extra_hotkeys:
            if hk.pressed.is_set():
                hk.pressed.clear()
                action()
        if self.hotkey and self.hotkey.pressed.is_set():
            self.hotkey.pressed.clear()
            if self.typing:
                self.stop_typing()
            self.set_locked(not self.nofocus.locked)
        elif (not self.nofocus.locked and not self.typing and not self.need_npcap
              and time.time() - self.last_use > AUTO_LOCK):
            self.set_locked(True)
        self.root.after(50, self.poll_hotkey)

    # --- mover, redimensionar, opacidade ---
    def start_move(self, e):
        self.close_menu()
        self.drag = (e.x_root - self.root.winfo_x(), e.y_root - self.root.winfo_y())

    def on_move(self, e):
        self.root.geometry(f"+{e.x_root - self.drag[0]}+{e.y_root - self.drag[1]}")

    def start_resize(self, e):
        self.size0 = (e.x_root, e.y_root, self.root.winfo_width(), self.root.winfo_height())

    def on_resize(self, e):
        x0, y0, w0, h0 = self.size0
        self.root.geometry(f"{max(320, w0 + e.x_root - x0)}x{max(120, h0 + e.y_root - y0)}")

    def set_alpha(self, value):
        self.alpha = min(self.ALPHA_MAX, max(self.ALPHA_MIN, value))
        self.root.attributes("-alpha", self.alpha)
        self.draw_slider()

    def on_wheel(self, e):
        self.set_alpha(self.alpha + (0.05 if e.delta > 0 else -0.05))

    def on_slider(self, e):
        frac = min(1.0, max(0.0, (e.x - 5) / 60))
        self.set_alpha(self.ALPHA_MIN + frac * (self.ALPHA_MAX - self.ALPHA_MIN))

    def draw_slider(self):
        c = self.slider
        c.delete("all")
        frac = (self.alpha - self.ALPHA_MIN) / (self.ALPHA_MAX - self.ALPHA_MIN)
        x = 5 + frac * 60
        c.create_line(5, 7, 65, 7, fill=DIM, width=3, capstyle="round")
        c.create_line(5, 7, x, 7, fill=GOLD, width=3, capstyle="round")
        c.create_oval(x - 5, 2, x + 5, 12, fill=FG, outline="")
        self.alpha_label.config(text=f"{self.alpha:.0%}")

    # --- ações ---
    def confirm(self, key, text, action):
        """Zerar, reiniciar e fechar pedem um 2º clique (um clique sem querer não perde nada)."""
        now = time.time()
        if self.pending[0] == key and now < self.pending[1]:
            self.pending = (None, 0.0)
            action()
        else:
            self.pending = (key, now + 3)
            self.flash = (text, now + 3)

    def save_unfinished(self):
        """Guarda no histórico a contagem atual antes de ela ser perdida."""
        try:
            s = self.session.combat.take_unfinished()
            if s:
                self.session.add_history(s)
        except Exception:
            pass

    def reset(self):
        self.save_unfinished()
        self.session.add_note("[zerado]")
        self.session.write_summary()
        self.session.combat.reset()
        self.flash = ("contagem zerada", time.time() + 2)

    def paint_boss_btn(self):
        combat = self.session.combat
        on = combat.boss_mode
        self.boss_btn.config(bg="#5a1f1f" if on else "#262a33", fg="#ff9d8a" if on else MUTED)
        if hasattr(self, "pvp_btn"):
            on = combat.pvp_mode
            self.pvp_btn.config(bg="#1f3a5a" if on else "#262a33", fg="#8ac4ff" if on else MUTED)
        if hasattr(self, "pve_btn"):
            on = not combat.pvp_mode and not combat.boss_mode
            self.pve_btn.config(bg="#1f4a2e" if on else "#262a33", fg="#7fe0a0" if on else MUTED)

    def set_mode(self, boss, pvp):
        """Troca entre grind / boss-dg / pvp e começa a contagem do zero."""
        combat = self.session.combat
        combat.boss_mode, combat.pvp_mode = boss, pvp
        save_config(modo_boss=boss, modo_pvp=pvp)
        name = "pvp" if pvp else "boss" if boss else "grind"
        self.save_unfinished()
        self.session.add_note(f"[modo {name}]")
        self.session.write_summary()
        combat.reset()
        self.paint_boss_btn()
        self.flash = ({"pvp": "MODO PVP: dano entre jogadores perto (contagem zerada)",
                       "boss": "MODO BOSS: tempo = luta inteira (contagem zerada)",
                       "grind": "MODO PVE: monstros normais (contagem zerada)"}[name],
                      time.time() + 3)

    def toggle_boss(self):
        self.set_mode(not self.session.combat.boss_mode, False)

    def toggle_pvp(self):
        self.set_mode(False, not self.session.combat.pvp_mode)

    def toggle_pin(self):
        on = not self.root.attributes("-topmost")
        self.root.attributes("-topmost", on)
        self.pin_btn.set_active(on)

    def close(self):
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
            self.tray = None
        self.save_unfinished()
        save_config(janela=self.root.geometry(), opacidade=round(self.alpha, 2))
        self.root.destroy()

    def ranking_text(self):
        s = self.session.combat.snapshot()
        lines = [f"DPS Meter BDO | {fmt_time(s['tempo'])} | total {fmt(s['total'])} | "
                 f"pt {fmt(s['dps'])}/s"]
        for i, r in enumerate(s["linhas"], 1):
            nums = f"{fmt(r['dano'])} ({r['pct']:.1%}) {fmt(r['dps'])}/s".replace(".", ",")
            lines.append(f"{i}. {self.session.label(r['ator'])}: {nums}")
        return "\n".join(lines)

    def copy_ranking(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.ranking_text())
        self.flash = ("ranking copiado!", time.time() + 2)

    # --- digitação (única hora em que a janela pega o teclado) ---
    def start_typing(self, kind, actor=None):
        self.close_menu()
        self.typing = (kind, actor)
        self.type_label.config(text="Nota:" if kind == "nota" else
                               f"Nome para {self.session.label(actor)}:")
        self.entry.delete(0, "end")
        self.type_bar.pack(side="bottom", fill="x", before=self.footer)
        self.nofocus.grab_keyboard(self.root)
        self.entry.focus_set()

    def finish_typing(self, _=None):
        text = self.entry.get().strip()
        kind, actor = self.typing or (None, None)
        if text and kind == "nota":
            self.session.add_note(text)
            self.flash = ("nota salva!", time.time() + 2)
        elif text and kind == "nome":
            self.session.names[actor] = text
            self.session.add_note(f"nome {actor:08x} = {text}")
        self.stop_typing()

    def stop_typing(self):
        if not self.typing:
            return
        self.typing = None
        self.type_bar.pack_forget()
        self.nofocus.give_back()

    # --- menu de clique direito (desenhado na janela, não rouba foco) ---
    def open_menu(self, e):
        self.close_menu()
        i = int((e.y - getattr(self, "rows_y0", 0)) // (self.ROW_H + self.ROW_GAP))
        if not 0 <= i < len(self.rows):
            return
        actor = self.rows[i]
        me = self.session.is_me(actor)
        options = [("Renomear", lambda: self.start_typing("nome", actor)),
                   ("Não sou eu" if me else "Sou eu", lambda: self.mark_me(actor)),
                   ("Copiar ranking", self.copy_ranking)]
        menu = self.menu = tk.Frame(self.canvas, bg=LINE)
        for text, cmd in options:
            item = tk.Label(menu, text=text, font=(UI, 9), bg=PANEL, fg=FG, anchor="w",
                            padx=12, pady=4, cursor="hand2")
            item.pack(fill="x", padx=1, pady=(1, 0))
            item.bind("<Enter>", lambda ev, w=item: w.config(bg=TRACK))
            item.bind("<Leave>", lambda ev, w=item: w.config(bg=PANEL))
            item.bind("<Button-1>", lambda ev, c=cmd: (self.close_menu(), c()))
        tk.Frame(menu, bg=LINE, height=1).pack(fill="x")
        menu.place(x=min(e.x, max(0, self.canvas.winfo_width() - 130)), y=e.y)

    def on_canvas_click(self, e):
        self.close_menu()
        if self.view:
            for x1, y1, x2, y2, action in self.view_hits:
                if x1 <= e.x <= x2 and y1 <= e.y <= y2:
                    action()
                    return
            return
        if self.need_npcap and e.y < 26 and self.npcap_state is None:
            self.install_npcap()
        elif self.banner == "update" and e.y < 26:
            self.install_update()

    def install_update(self):
        """Clique no aviso de versão nova: fecha, troca os arquivos e abre a versão nova."""
        if not (UPDATER and UPDATER.ready):
            return
        self.flash = (f"atualizando para a versão {UPDATER.ready[0]}...", time.time() + 5)
        try:
            UPDATER.apply()
            self.root.after(800, self.close)
        except Exception:
            import tempfile
            import traceback
            with open(Path(tempfile.gettempdir()) / "DPSMeterBDO_atualizacao.log", "a",
                      encoding="utf-8") as f:
                f.write(traceback.format_exc())
            UPDATER.ready = None  # falhou: segue na versão atual
            self.flash = ("a atualização falhou: baixe a versão nova pelo site", time.time() + 8)

    def install_npcap(self):
        self.npcap_state = "baixando"

        def run():
            ok = download_npcap()
            self.npcap_state = "instalando" if ok else None
            if not ok:
                self.flash = ("abri o site do Npcap: baixe e instale por lá", time.time() + 8)

        threading.Thread(target=run, daemon=True).start()

    def restart_app(self):
        """Abre o meter de novo (depois de instalar o Npcap a captura precisa recomeçar)."""
        if FROZEN:
            import subprocess
            subprocess.Popen([sys.executable, *sys.argv[1:], "--esperar"])
            self.close()
        else:
            self.restart_requested = True
            self.close()

    def close_menu(self):
        if self.menu:
            self.menu.destroy()
            self.menu = None

    def mark_me(self, actor):
        self.session.set_me(actor)
        self.session.add_note(f"eu = {actor:08x}")

    # --- desenho ---
    def color_for(self, actor):
        code = self.session.party_class_code(actor)
        if code in CLASS_COLORS:
            return CLASS_COLORS[code]
        if actor not in self.colors:
            self.colors[actor] = PALETTE[len(self.colors) % len(PALETTE)]
        return self.colors[actor]

    def bar_image(self, w, h, color, frac, outline):
        key = (w, h, color, round(frac, 3), outline)
        if key not in self.bars:
            from PIL import ImageTk
            if len(self.bars) > 300:
                self.bars.clear()
            self.bars[key] = ImageTk.PhotoImage(render_bar(w, h, color, frac, outline),
                                                master=self.root)
        return self.bars[key]

    def badge_image(self, code, color, d):
        path = ICONS_DIR / f"class_{code}.png"
        key = (code, color, d, path.exists())  # troca o selo pelo ícone quando ele chegar
        if key not in self.badges:
            from PIL import ImageTk
            self.badges[key] = ImageTk.PhotoImage(render_badge(d, color, path, code),
                                                  master=self.root)
        return self.badges[key]

    def text(self, x, y, text, fill, font, anchor="w"):
        """Texto com contorno escuro, para ler bem em cima de qualquer cor."""
        for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1), (1, 1)):
            self.canvas.create_text(x + dx, y + dy, text=text, fill="#0b0c10", font=font,
                                    anchor=anchor)
        return self.canvas.create_text(x, y, text=text, fill=fill, font=font, anchor=anchor)

    def refresh(self):
        combat = self.session.combat
        while combat.finished:
            item = self.session.add_history(combat.finished.pop(0))
            self.view = ("resumo", item, True)
            self.flash = ("boss derrotado! tempo pausado", time.time() + 4)
        s = combat.snapshot()
        if self.view and self.view[0] == "resumo" and self.view[2] and s.get("luta") == "active":
            self.view = None  # luta nova começou: volta para a tela normal
        self.timer.config(text=fmt_time(s["tempo"]), fg=GREEN if s["ativo"] else MUTED)
        extra = ""
        if s.get("boss") and s.get("luta") == "paused":
            extra = "   ·   PAUSADO"
        elif s.get("boss") and s.get("boss_pct") is not None:
            extra = f"   ·   Boss {s['boss_pct']:.0%}"
            if s.get("eta") is not None:
                extra += f" ~{fmt_time(s['eta'])}"
        self.totals.config(text=(f"Total {fmt(s['total'])}   ·   DPS {fmt(s['dps'])}/s" + extra)
                           if s["total"] else "Total -")
        with self.session.combat.lock:
            party_size = len(self.session.combat.party)
            # membro que entrou com o meter fechado: a ficha (nome/classe) não chegou
            unnamed = any(not v[0] for a, v in self.session.combat.party.items()
                          if a not in self.session.names)
        self.pill.config(text=f"PT {party_size}" if party_size else "SEM PT")

        c = self.canvas
        c.delete("all")
        w, h = max(c.winfo_width(), 200), max(c.winfo_height(), 40)
        step = self.ROW_H + self.ROW_GAP
        top = max(1, s["linhas"][0]["dano"]) if s["linhas"] else 1
        self.rows = []
        # faixa de aviso quando faltam nomes (ex.: meter aberto com a pt já formada)
        self.rows_y0 = 0
        self.banner = None
        if self.need_npcap and npcap_installed():
            self.need_npcap = False
            self.flash = ("Npcap instalado! reiniciando o meter...", time.time() + 5)
            self.root.after(1500, self.restart_app)
        if self.need_npcap:
            msg = {None: "Npcap não instalado: CLIQUE AQUI para instalar",
                   "baixando": "baixando o instalador do Npcap...",
                   "instalando": "siga o instalador do Npcap (Next / Install)"}[self.npcap_state]
            c.create_image(0, 0, anchor="nw", image=self.bar_image(w, 24, "#6b4d12", 1.0, GOLD))
            self.text(w / 2, 12, msg, GOLD, (UI, 8, "bold"), anchor="center")
            self.rows_y0 = 24 + self.ROW_GAP
        elif UPDATER and UPDATER.ready:
            self.banner = "update"
            msg = (f"versão {UPDATER.ready[0]} disponível: clique aqui para atualizar"
                   if not self.nofocus.locked else
                   f"versão {UPDATER.ready[0]} disponível: {self.hotkey_name()} e clique aqui")
            c.create_image(0, 0, anchor="nw", image=self.bar_image(w, 24, "#1f4a2e", 1.0, GREEN))
            self.text(w / 2, 12, msg, "#7fe0a0", (UI, 8, "bold"), anchor="center")
            self.rows_y0 = 24 + self.ROW_GAP
        elif not s["pvp"] and unnamed and party_size:
            c.create_image(0, 0, anchor="nw", image=self.bar_image(w, 24, "#6b4d12", 1.0, GOLD))
            self.text(w / 2, 12, "Para ver nomes e classes: saia e entre na pt com o meter aberto",
                      GOLD, (UI, 8, "bold"), anchor="center")
            self.rows_y0 = 24 + self.ROW_GAP
        visible = max(1, int((h - self.rows_y0 + self.ROW_GAP) // step))
        for i, r in enumerate(s["linhas"][:visible]):
            y0 = self.rows_y0 + i * step
            yc = y0 + self.ROW_H / 2
            actor = r["ator"]
            self.rows.append(actor)
            mine = self.session.is_me(actor)
            idle = r["dano"] == 0 and not r.get("recebido")
            color = self.color_for(actor)
            frac = 0 if idle else r["dano"] / top
            c.create_image(0, y0, anchor="nw",
                           image=self.bar_image(w, self.ROW_H, color, frac, GOLD if mine else None))
            code = self.session.party_class_code(actor)
            x_name = 10
            if code is not None:
                c.create_image(4, yc, anchor="w", image=self.badge_image(code, color, self.ROW_H - 6))
                x_name = self.ROW_H + 4
            name_font = ("Segoe UI Semibold", 9)
            t = self.text(x_name, yc, self.session.label(actor), MUTED if idle else FG, name_font)
            if r.get("mortes"):
                n = r["mortes"]
                self.text(c.bbox(t)[2] + 6, yc, f"{n} morte" + ("s" if n > 1 else ""),
                          "#ff8a7a", (UI, 7, "bold"))
            if idle:
                self.text(w - 10, yc, "sem dano", MUTED, (UI, 8, "italic"), anchor="e")
                continue
            if s["pvp"]:
                x = w - 10
                if r["abates"] or r["mortes"]:
                    t = self.text(x, yc, f"{r['abates']}/{r['mortes']}", FG,
                                  ("Bahnschrift SemiBold", 9), "e")
                    x = c.bbox(t)[0] - 8
                if r["recebido"]:
                    t = self.text(x, yc, f"-{fmt(r['recebido'])}", "#ff8a7a",
                                  ("Bahnschrift SemiBold", 8), "e")
                    x = c.bbox(t)[0] - 8
            else:
                t = self.text(w - 10, yc, f"{r['pct']:.1%}".replace(".", ","), FG,
                              ("Bahnschrift SemiBold", 9), "e")
                x = c.bbox(t)[0] - 10
            t = self.text(x, yc, fmt(r["dano"]), "#dfe2e6", ("Bahnschrift SemiBold", 8), "e")
            x = c.bbox(t)[0] - 8
            self.text(x, yc, f"{fmt(r['dps'])}/s", self.YELLOW, (NUM, 10, "bold"), "e")
        if not s["linhas"]:
            title, sub = (("Modo PVP", "o dano entre jogadores perto de você aparece aqui")
                          if s["pvp"] else
                          ("Esperando combate...", "o dano aparece aqui assim que alguém da pt bater")
                          if party_size else
                          ("Sem pt", "entre numa pt com o meter aberto para ver o dano"))
            yc = self.rows_y0 + (h - self.rows_y0) / 2
            c.create_text(w / 2, yc - 8, text=title, fill=MUTED, font=(UI, 10))
            c.create_text(w / 2, yc + 12, text=sub, fill=DIM, font=(UI, 8))
        if self.view:
            self.draw_view(c, w, h)
        if self.menu:
            self.menu.lift()

        text, until = self.flash
        if not self.hotkey:
            status, color = "atalho indisponível: troque \"atalho\" no config.json", GOLD
        elif time.time() < until:
            status, color = text, GOLD
        elif not self.nofocus.locked and not self.typing:
            status, color = f"DESTRAVADO · {self.hotkey_name()} trava", GOLD
        elif self.status_fn():
            status, color = self.status_fn(), GOLD
        elif self.update_ready:
            status, color = "atualização pronta: instala sozinha fora de combate", GOLD
        elif UPDATER and UPDATER.status:
            status, color = UPDATER.status, MUTED
        else:
            status, color = f"v{VERSION} · {self.hotkey_name()} destrava", MUTED
        self.status.config(text=status, fg=color)
        self.root.after(400, self.refresh)

    def save_summary(self):
        self.session.write_summary()
        self.root.after(3000, self.save_summary)

    # --- resumo e histórico das lutas de boss ---
    def show_history(self):
        self.view = ("historico",)

    GUIDE = [
        ("Atalhos", [
            ("ALT+X", "Destrava a janela para clicar nela. Trava sozinha depois de 15 s."),
            ("ALT+Z", "Zera a contagem."),
            ("ALT+B", "Alterna entre os modos PVE e BOSS."),
            ("Mover", "Arraste pela barra de cima. O canto de baixo muda o tamanho."),
            ("Botões", "Zerar, reiniciar e fechar pedem dois cliques."),
            ("Bandeja", "O ícone perto do relógio do Windows mostra, esconde e fecha o meter."),
        ]),
        ("Modos", [
            ("PVE", "Monstros normais. Pausas de mais de 5 s sem golpes não contam."),
            ("BOSS", "Só boss e sub-boss (3M+ de vida). O tempo é a luta inteira."),
            ("Fim", "Quando o boss morre, o tempo pausa e aparece um resumo."),
            ("PVP", "Dano entre jogadores perto de você, recebido, abates e mortes."),
        ]),
        ("Dicas", [
            ("Nomes", "Entre na pt ou troque de canal com o meter aberto."),
            ("Você", "Contorno dourado. Errou? Botão direito no nome e \"Sou eu\"."),
            ("Histórico", "Botão de relógio. Zerar, trocar de modo ou fechar guarda a luta."),
            ("Copiar", "Botão do rodapé copia o ranking para o chat ou Discord."),
            ("Versão", "Aparece no rodapé. Versão nova vem num aviso verde: clique nele."),
        ]),
    ]

    def toggle_guide(self):
        self.view = None if self.view and self.view[0] == "guia" else ("guia", 0, 0)

    def scroll_guide(self, e):
        if self.view and self.view[0] == "guia":
            step = -24 if e.delta > 0 else 24
            self.view = ("guia", self.view[1], max(0, min(self.guide_max, self.view[2] + step)))
            self.refresh_now()

    def refresh_now(self):
        """Redesenha já (sem esperar o próximo ciclo), mantendo um só ciclo agendado."""
        if self.view:
            c = self.canvas
            w, h = max(c.winfo_width(), 200), max(c.winfo_height(), 40)
            c.delete("all")
            self.draw_view(c, w, h)

    def draw_guide(self, c, w, h):
        _, page, offset = self.view
        top = 30
        # conteúdo primeiro (com rolagem); o cabeçalho é desenhado por cima
        key_w = 70
        y = top + 6 - offset
        for key, text in self.GUIDE[page][1]:
            t = c.create_text(key_w + 8, y, anchor="nw", fill=FG, font=(UI, 8), text=text,
                              width=w - key_w - 14)
            y2 = c.bbox(t)[3]
            c.tag_lower(rounded(c, 0, y - 5, w, y2 + 5, 6, fill=TRACK, outline=""), t)
            c.create_text(8, y, anchor="nw", fill=self.YELLOW, font=(UI, 8, "bold"), text=key)
            y = y2 + 12
        self.guide_max = max(0, y + offset - h)
        c.create_rectangle(0, 0, w, top, fill=BG, outline="")
        # abas do guia
        x = 4
        for i, (name, _) in enumerate(self.GUIDE):
            on = i == page
            t = c.create_text(x + 8, 13, anchor="w", text=name, font=(UI, 8, "bold"),
                              fill=GOLD if on else MUTED)
            x1, _, x2, _ = c.bbox(t)
            r = c.create_rectangle(x1 - 8, 3, x2 + 8, 23, fill="#3a2a12" if on else "#262a33",
                                   outline=GOLD if on else LINE)
            c.tag_lower(r, t)
            self.view_hits.append((x1 - 8, 3, x2 + 8, 23,
                                   lambda i=i: setattr(self, "view", ("guia", i, 0))))
            x = x2 + 14
        self.button(w, 13, "Voltar", self.close_view)
        if self.guide_max and offset < self.guide_max:
            c.create_rectangle(0, h - 16, w, h, fill=BG, outline="")
            c.create_text(w / 2, h - 8, fill=MUTED, font=(UI, 7),
                          text="role o mouse para ver mais  ▾")

    def close_view(self):
        self.view = None

    def summary_text(self, item):
        lines = [f"DPS Meter BDO | {item.get('tipo', 'boss')} {item['quando']} | tempo {fmt_time(item['tempo'])} | "
                 f"total {fmt(item['total'])} | pt {fmt(item['dps'])}/s"]
        if item.get("recorde_tempo") is not None:
            lines[0] += f" | recorde {fmt_time(item['recorde_tempo'])}"
        for i, row in enumerate(item["linhas"], 1):
            name, dano, dps, pct = row[:4]
            mortes = row[7] if len(row) >= 8 else 0
            extra = f" | {mortes} morte" + ("s" if mortes > 1 else "") if mortes else ""
            nums = f"{fmt(dano)} ({pct:.1%}) {fmt(dps)}/s".replace(".", ",")
            lines.append(f"{i}. {name}: {nums}{extra}")
        return "\n".join(lines)

    def copy_summary(self, item):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.summary_text(item))
        self.flash = ("resumo copiado!", time.time() + 2)

    def button(self, x2, y, text, action):
        """Botão desenhado no canvas (alinhado à direita em x2); devolve a borda esquerda."""
        c = self.canvas
        t = c.create_text(x2 - 8, y, text=text, anchor="e", fill=FG, font=(UI, 8, "bold"))
        x1 = c.bbox(t)[0] - 8
        r = c.create_rectangle(x1, y - 10, x2, y + 10, fill="#262a33", outline=LINE)
        c.tag_lower(r, t)
        self.view_hits.append((x1, y - 10, x2, y + 10, action))
        return x1

    def draw_view(self, c, w, h):
        self.view_hits = []
        c.create_rectangle(0, 0, w, h, fill=BG, outline="")
        if self.view[0] == "guia":
            self.draw_guide(c, w, h)
            return
        if self.view[0] == "historico":
            hist = list(reversed(self.session.load_history()))
            c.create_text(4, 12, text="Histórico de lutas", anchor="w", fill=GOLD,
                          font=(UI, 10, "bold"))
            self.button(w, 12, "Voltar", self.close_view)
            if not hist:
                c.create_text(w / 2, h / 2, text="nenhuma luta de boss ainda", fill=MUTED,
                              font=(UI, 9))
            y = 36
            for item in hist[:max(1, int((h - 36) // 22))]:
                top = item["linhas"][0][0] if item["linhas"] else "-"
                r = c.create_rectangle(0, y - 10, w, y + 10, fill=TRACK, outline="")
                c.create_text(6, y, anchor="w", fill=FG, font=(NUM, 9),
                              text=f"{item['quando']}   {fmt_time(item['tempo'])}   "
                                   f"pt {fmt(item['dps'])}/s"
                                   + ("" if item.get("tipo", "boss") == "boss"
                                      else f"   ({item['tipo']})"))
                c.create_text(w - 6, y, anchor="e", fill=MUTED, font=(UI, 8), text=f"1º {top}")
                self.view_hits.append((0, y - 10, w, y + 10,
                                       lambda it=item: setattr(self, "view", ("resumo", it, False))))
                y += 22
            return
        item = self.view[1]
        c.create_text(4, 12, text="Boss derrotado" if self.view[2] else
                           f"{item.get('tipo', 'boss').capitalize()} de {item['quando']}",
                      anchor="w", fill=GOLD, font=(UI, 10, "bold"))
        x = self.button(w, 12, "Voltar", self.close_view)
        self.button(x - 6, 12, "Copiar", lambda: self.copy_summary(item))
        c.create_text(4, 34, anchor="w", fill=FG, font=(NUM, 9),
                      text=f"Tempo {fmt_time(item['tempo'])}   ·   Total {fmt(item['total'])}   ·   "
                           f"DPS pt {fmt(item['dps'])}/s")
        rec = item.get("recorde_tempo")
        if rec is None:
            rec_text, rec_color = "primeira luta registrada contra este boss", MUTED
        elif item["tempo"] < rec:
            rec_text, rec_color = f"NOVO RECORDE! (antes {fmt_time(rec)})", GOLD
        else:
            rec_text, rec_color = f"Recorde {fmt_time(rec)}   ·   esta run +{fmt_time(item['tempo'] - rec)}", MUTED
        c.create_text(4, 52, anchor="w", fill=rec_color, font=(UI, 8, "bold"), text=rec_text)
        y = 74
        rows = item["linhas"][:max(1, int((h - 74) // 22))]
        for i, row in enumerate(rows):
            name, dano, dps, pct, code, me = row[:6]
            taken, mortes = (row[6], row[7]) if len(row) >= 8 else (0, 0)
            color = self.color_for_class(code)
            rounded(c, 0, y - 10, w, y + 10, 6, fill=blend(color, TRACK, 0.35 if i else 0.6),
                    outline=GOLD if me else "")
            c.create_text(8, y, anchor="w", fill=GOLD if i == 0 else MUTED, font=(NUM, 9, "bold"),
                          text=str(i + 1))
            t = c.create_text(24, y, anchor="w", fill=FG, font=("Segoe UI Semibold", 9), text=name)
            x = c.bbox(t)[2] + 6
            if name in item.get("recordes_dps", []):
                t = c.create_text(x, y, anchor="w", fill=GOLD, font=(UI, 7, "bold"), text="recorde")
                x = c.bbox(t)[2] + 6
            if mortes:
                c.create_text(x, y, anchor="w", fill="#ff8a7a", font=(UI, 7, "bold"),
                              text=f"{mortes} morte" + ("s" if mortes > 1 else ""))
            t = c.create_text(w - 8, y, anchor="e", fill=FG, font=(NUM, 9),
                              text=f"{pct:.1%}".replace(".", ","))
            if taken:
                t = c.create_text(c.bbox(t)[0] - 8, y, anchor="e", fill="#ff8a7a", font=(NUM, 8),
                                  text=f"-{fmt(taken)}")
            t = c.create_text(c.bbox(t)[0] - 10, y, anchor="e", fill="#dfe2e6", font=(NUM, 8),
                              text=fmt(dano))
            c.create_text(c.bbox(t)[0] - 8, y, anchor="e", fill=self.YELLOW, font=(NUM, 9, "bold"),
                          text=f"{fmt(dps)}/s")
            y += 22

    def color_for_class(self, code):
        return CLASS_COLORS.get(code, PALETTE[(code or 0) % len(PALETTE)])

    def run(self):
        self.root.mainloop()


NPCAP_SITE = "https://npcap.com/"


def download_npcap():
    """Baixa o instalador oficial do npcap.com e abre (a pessoa clica em Next/Install).

    A licença gratuita não permite embutir o instalador nem instalar sem a pessoa ver,
    então o meter só busca a versão mais nova no site oficial e abre o instalador."""
    import os
    import tempfile
    import urllib.request
    import webbrowser
    try:
        req = urllib.request.Request(NPCAP_SITE, headers={"User-Agent": "Mozilla/5.0"})
        page = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
        name = re.search(r"dist/(npcap-[\d.]+\.exe)", page).group(1)
        dest = Path(tempfile.gettempdir()) / name
        req = urllib.request.Request(NPCAP_SITE + "dist/" + name,
                                     headers={"User-Agent": "Mozilla/5.0"})
        dest.write_bytes(urllib.request.urlopen(req, timeout=120).read())
        os.startfile(dest)  # o Windows pede permissão e o instalador abre
        return True
    except Exception:
        webbrowser.open(NPCAP_SITE + "#download")
        return False


def parse_version(text):
    return tuple(int(x) for x in re.findall(r"\d+", text or "")[:3])


class AutoUpdater(threading.Thread):
    """No .exe: procura uma versão nova no GitHub, baixa e deixa pronta para instalar.

    A instalação troca só os arquivos do programa; config, nomes, histórico, ícones e
    capturas ficam como estão (eles nem vêm no .zip)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.ready = None  # (versão, pasta com os arquivos novos)
        self.status = None

    def run(self):
        while self.ready is None:
            try:
                self.check()
            except Exception:
                pass  # sem internet ou GitHub fora: tenta de novo mais tarde
            time.sleep(UPDATE_CHECK_EVERY)

    def check(self):
        import tempfile
        import urllib.request
        import zipfile
        headers = {"User-Agent": "DPSMeterBDO", "Accept": "application/vnd.github+json"}
        req = urllib.request.Request(f"https://api.github.com/repos/{UPDATE_REPO}/releases/latest",
                                     headers=headers)
        rel = json.loads(urllib.request.urlopen(req, timeout=20).read())
        tag = rel.get("tag_name", "")
        if parse_version(tag) <= parse_version(VERSION):
            return
        asset = next((a for a in rel.get("assets", []) if a.get("name") == UPDATE_ASSET), None)
        if not asset:
            return
        self.status = f"baixando a versão {tag}..."
        work = Path(tempfile.gettempdir()) / f"DPSMeterBDO_update_{tag}"
        zpath = work.parent / (work.name + ".zip")
        req = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "DPSMeterBDO"})
        zpath.write_bytes(urllib.request.urlopen(req, timeout=300).read())
        if work.exists():
            import shutil
            shutil.rmtree(work, ignore_errors=True)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(work)
        exe = next(work.rglob("DPSMeterBDO.exe"), None)
        if exe is None:
            self.status = None
            return
        self.ready = (tag, exe.parent)
        self.status = None

    def apply(self):
        """Fecha o meter e deixa um script trocar os arquivos e abrir a versão nova."""
        import os
        import subprocess
        import tempfile
        tag, src = self.ready
        app_dir = Path(sys.executable).parent
        exe_name = Path(sys.executable).name
        tmp = Path(tempfile.gettempdir())
        bat = tmp / "DPSMeterBDO_atualizar.bat"
        log = tmp / "DPSMeterBDO_atualizacao.log"  # registro, para investigar se algo falhar

        def note(text):
            with open(log, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now():%d/%m %H:%M:%S} {text}\n")

        note(f"atualizando {VERSION} -> {tag} em {app_dir}")
        # Sem tasklist/find (travam quando o script roda sem janela): o próprio robocopy
        # tenta de novo a cada segundo enquanto os arquivos do meter ainda estão em uso.
        lines = [
            "@echo off",
            f'echo %date% %time% script iniciado >> "{log}"',
            "ping -n 4 127.0.0.1 >nul",  # dá tempo do meter fechar
            f'robocopy "{src}" "{app_dir}" /E /R:120 /W:1 /NFL /NDL /NJH /NJS /NP >nul',
            f'echo %date% %time% robocopy terminou (codigo %errorlevel%) >> "{log}"',
            f'start "" "{app_dir / exe_name}"',
            'del "%~f0"',
        ]
        # grava em bytes, para o Windows não dobrar as quebras de linha
        bat.write_bytes(("\r\n".join(lines) + "\r\n").encode("mbcs", errors="replace"))
        # processo separado do meter (sobrevive quando o meter fecha) e sem janela
        detached, new_group, no_window, breakaway = 0x08, 0x200, 0x08000000, 0x01000000
        for flags in (no_window | new_group | breakaway, no_window | new_group,
                      detached | new_group):
            try:
                subprocess.Popen(["cmd", "/c", str(bat)], creationflags=flags, close_fds=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                note(f"script iniciado (flags {flags:#x})")
                break
            except OSError as e:
                note(f"falhou com flags {flags:#x}: {e}")


UPDATER = None  # criado no main quando é o .exe


def npcap_installed():
    import os
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    return (system32 / "Npcap").exists() or (system32 / "wpcap.dll").exists()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--replay", type=Path, help="pasta de uma captura gravada")
    ap.add_argument("--velocidade", type=float, default=None,
                    help="no replay, velocidade em relação ao tempo real (ex.: 10)")
    ap.add_argument("--sem-janela", action="store_true", help="só gera o resumo")
    ap.add_argument("--esperar", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--testar-atualizacao", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--processo", action="append",
                    help="nome do executável do jogo, se for diferente de BlackDesert64.exe")
    args = ap.parse_args()
    if args.esperar:  # a instância anterior ainda está fechando (e soltando o Alt+X)
        time.sleep(2)

    base = APP_DIR / "capturas"
    out_dir = base / ("meter_" + datetime.now().strftime("%Y-%m-%d_%H%M%S"))
    out_dir.mkdir(parents=True)
    combat = Combat(out_dir / "golpes.csv")
    session = Session(out_dir, combat)
    stop = threading.Event()

    if args.replay:
        status = lambda: None
        worker = threading.Thread(target=replay, args=(args.replay, combat, args.velocidade, stop),
                                  daemon=True)
        worker.start()
        cap = None
    else:
        names = ({n.lower() for n in args.processo} if args.processo
                 else {"blackdesert64.exe", "blackdesert32.exe", "blackdesert.exe"})
        # captura.pcap (tráfego bruto) só serve para análise: ligado aqui, desligado no .exe
        record = load_config().get("gravar_pcap", not FROZEN)
        cap = MeterCapture(out_dir, names, combat, record=record)
        state = {"alerta": "procurando o jogo: abra o BDO e entre no personagem"}
        if not npcap_installed():
            state["alerta"] = "falta o Npcap: clique na faixa dourada"

        def connect():
            if not npcap_installed():
                return
            try:
                cap.wait_for_game()
                cap.start()
                write_info(out_dir, cap, session.started)
                state["alerta"] = None
                print(f"Meter rodando. Arquivos em: {out_dir}")
            except Exception as e:
                state["alerta"] = f"erro ao capturar: {e}"[:90]

        threading.Thread(target=connect, daemon=True).start()
        status = lambda: state["alerta"]
        worker = None

    if icons_missing():
        threading.Thread(target=download_icons, daemon=True).start()
    global UPDATER
    if FROZEN and (not args.replay or args.testar_atualizacao)             and load_config().get("atualizar_sozinho", True):
        UPDATER = AutoUpdater()
        UPDATER.start()

    restart = False
    try:
        if args.sem_janela:
            if worker:
                worker.join()
            else:
                while True:
                    time.sleep(1)
        else:
            window = MeterWindow(session, status)
            window.run()
            restart = window.restart_requested
    except KeyboardInterrupt:
        pass
    finally:
        # Primeiro o que mais importa (resumo); cada etapa isolada para uma falha
        # não impedir as outras
        stop.set()
        steps = [session.close]
        if cap:
            steps += [lambda: write_info(out_dir, cap, session.started), cap.stop]
        for step in steps:
            try:
                step()
            except Exception as e:
                print(f"Aviso ao encerrar: {e}")
        print(f"Resumo salvo em: {out_dir / 'resumo.txt'}")
    if restart:
        print("Atualizando o meter...")
        sys.exit(RESTART_CODE)


if __name__ == "__main__":
    main()
