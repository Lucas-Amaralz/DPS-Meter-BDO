"""
Primeiro diagnóstico de uma captura feita com capture.py.

Uso:
    python analyze.py capturas/2026-10-19_203000

Responde três perguntas:
  1. O conteúdo parece cifrado? (entropia e compressibilidade)
  2. Dá para separar as mensagens? (procura um campo de tamanho no início)
  3. O tráfego reage às ações marcadas no roteiro?
"""
import bisect
import csv
import math
import re
import struct
import sys
import zlib
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import IP, TCP, UDP, PcapReader


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def compress_ratio(data):
    return len(zlib.compress(data, 9)) / len(data) if data else 1.0


def verdict(h, ratio):
    if h > 7.9 and ratio > 0.98:
        return "parece CIFRADO ou comprimido (ruído uniforme)"
    if h > 7.5:
        return "muito aleatório; provavelmente cifrado, talvez com partes legíveis"
    return "tem padrões; provavelmente NÃO está totalmente cifrado"


def load(cap_dir):
    servers = {}  # ip -> portas
    for line in (cap_dir / "info.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"servidor: (\S+) portas \[(.*)\]", line)
        if m:
            servers[m.group(1)] = {int(p) for p in m.group(2).split(",") if p.strip()}

    def from_server(ip, port):
        # No proxy local (127.0.0.1) os dois lados têm o mesmo IP, então vale a porta
        return ip in servers and (not ip.startswith("127.") or port in servers[ip])

    markers = []
    mfile = cap_dir / "marcadores.csv"
    if mfile.exists():
        with open(mfile, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                markers.append((float(row["timestamp"]), row["fase"], row["evento"]))

    packets = []  # (tempo, direção, fluxo, seq, payload)
    for pkt in PcapReader(str(cap_dir / "captura.pcap")):
        if IP not in pkt:
            continue
        ip = pkt[IP]
        direction = "S->C" if from_server(ip.src, getattr(pkt, "sport", None)) else "C->S"
        if TCP in pkt:
            l4, proto, seq = pkt[TCP], "tcp", pkt[TCP].seq
        elif UDP in pkt:
            l4, proto, seq = pkt[UDP], "udp", None
        else:
            continue
        payload = bytes(l4.payload)
        if not payload:
            continue
        flow = (proto, ip.src, l4.sport, ip.dst, l4.dport)
        packets.append((float(pkt.time), direction, flow, seq, payload))
    return servers, markers, packets


def reassemble(packets):
    """Junta os pedaços TCP de cada fluxo em ordem, descartando retransmissões."""
    streams = defaultdict(dict)
    for _, _, flow, seq, payload in packets:
        if seq is None:
            continue
        streams[flow].setdefault(seq, payload)
    return {flow: b"".join(segs[s] for s in sorted(segs)) for flow, segs in streams.items()}


def try_framing(stream):
    """Testa se o fluxo é uma sequência de mensagens com tamanho de 2 ou 4 bytes no início."""
    results = []
    for size, order in ((2, "little"), (2, "big"), (4, "little"), (4, "big")):
        for includes_header in (True, False):
            pos, msgs = 0, 0
            while pos + size <= len(stream):
                n = int.from_bytes(stream[pos:pos + size], order)
                total = n if includes_header else n + size
                if total < size + 1 or total > 65536:
                    break
                pos += total
                msgs += 1
            covered = min(pos, len(stream)) / len(stream) if stream else 0
            results.append((covered, msgs, size, order, includes_header))
    return max(results)


def split_messages(stream, size, order, includes_header):
    pos, out = 0, []
    while pos + size <= len(stream):
        n = int.from_bytes(stream[pos:pos + size], order)
        total = n if includes_header else n + size
        if total < size + 1 or pos + total > len(stream):
            break
        out.append(stream[pos:pos + total])
        pos += total
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    cap_dir = Path(sys.argv[1])
    servers, markers, packets = load(cap_dir)
    if not packets:
        print("Nenhum pacote com conteúdo na captura.")
        return

    print(f"Servidores: {', '.join(f'{ip} {sorted(ps)}' for ip, ps in sorted(servers.items()))}")
    print(f"Pacotes com conteúdo: {len(packets)}\n")

    # 1. Cifrado?
    print("=== 1. O conteúdo parece cifrado? ===")
    print("(entropia vai de 0 a 8 bits/byte; perto de 8 = ruído. compressão perto de 1.0 = não comprime)")
    for d in ("C->S", "S->C"):
        data = b"".join(p[4] for p in packets if p[1] == d)
        if not data:
            continue
        h, r = entropy(data), compress_ratio(data)
        print(f"  {d}: {len(data):>9} bytes  entropia {h:.3f}  compressão {r:.3f}  -> {verdict(h, r)}")

    # 2. Mensagens separáveis?
    print("\n=== 2. Dá para separar as mensagens? ===")
    streams = reassemble(packets)
    flow_dir = {p[2]: p[1] for p in packets}
    for flow, stream in sorted(streams.items(), key=lambda kv: -len(kv[1])):
        if len(stream) < 200:
            continue
        proto, src, sport, dst, dport = flow
        d = flow_dir[flow]
        covered, msgs, size, order, incl = try_framing(stream)
        print(f"  {d} {src}:{sport} -> {dst}:{dport}  ({len(stream)} bytes)")
        if covered > 0.95 and msgs > 20:
            desc = f"{size} bytes {order}-endian, {'inclui' if incl else 'não inclui'} o cabeçalho"
            print(f"    Campo de tamanho encontrado: {desc}; {msgs} mensagens, {covered:.0%} do fluxo")
            msgs_list = split_messages(stream, size, order, incl)
            heads = b"".join(m[size:size + 4] for m in msgs_list)
            bodies = b"".join(m[size + 4:] for m in msgs_list)
            print(f"    Entropia logo após o tamanho: {entropy(heads):.2f}  | resto: {entropy(bodies):.2f}")
            common = Counter(m[size:size + 3].hex(" ") for m in msgs_list).most_common(8)
            print("    Bytes mais comuns logo após o tamanho (possível tipo de mensagem):")
            for h, c in common:
                print(f"      {h}  x{c}")
            sizes = Counter(len(m) for m in msgs_list).most_common(8)
            print(f"    Tamanhos de mensagem mais comuns: {', '.join(f'{s}B x{c}' for s, c in sizes)}")
        else:
            print(f"    Sem campo de tamanho claro (melhor tentativa: {msgs} mensagens, {covered:.0%} do fluxo)")
            print(f"    Primeiros bytes: {stream[:32].hex(' ')}")

    # 3. Reação às ações
    print("\n=== 3. O tráfego reage às ações? ===")
    if not any(f != "nota" for _, f, _ in markers):
        print("  Sem roteiro nesta captura.")
    else:
        reaction(markers, packets)

    # 4. Dano
    damage_report(packets, markers)


def reaction(markers, packets):
    phases = {}
    for t, fase, ev in markers:
        phases.setdefault(fase, {})[ev] = t
    base = phases.get("parado", {})
    if "inicio" in base and "fim" in base:
        dur = base["fim"] - base["inicio"]
        for d in ("C->S", "S->C"):
            n = sum(1 for p in packets if p[1] == d and base["inicio"] <= p[0] < base["fim"])
            print(f"  Parado, {d}: {n / dur:.1f} pacotes/s (linha de base)")
    window = 1.5
    for fase in ("skill", "basico"):
        acts = [t for t, f, ev in markers if f == fase and ev.startswith("acao_")]
        if not acts:
            continue
        print(f"\n  Fase '{fase}': pacotes nos {window}s após cada bipe")
        for d in ("C->S", "S->C"):
            counts, sizes = [], Counter()
            for t in acts:
                hits = [p for p in packets if p[1] == d and t <= p[0] < t + window]
                counts.append(len(hits))
                sizes.update(len(p[4]) for p in hits)
            print(f"    {d}: {counts}")
            print(f"         tamanhos mais comuns: {', '.join(f'{s}B x{c}' for s, c in sizes.most_common(6))}")



# --- Dano (formato descoberto na captura de 2026-10-19) ---
# Mensagem: [u16 tamanho, inclui cabeçalho][u8 0=aberta 1=cifrada][u16 tipo][corpo]
# Tipo 0x0f4e, corpo: +0 i64 origem, +8 f32, +12 f32 valor novo, +16 u32 quem causou,
#                     +24 u32 alvo, +36 f32 valor máximo, +40 u32 contador de golpes do alvo
OP_HP = 0x0F4E
ORIGEM_VIDA_MONSTRO = -112372


def server_messages(packets):
    """Mensagens abertas vindas do servidor, com o horário em que chegaram."""
    segs = defaultdict(dict)
    for t, d, flow, seq, payload in packets:
        if d == "S->C" and seq is not None:
            segs[flow].setdefault(seq, (t, payload))
    out = []
    for flow, s in segs.items():
        buf, ends, times = b"", [], []
        for seq in sorted(s):
            t, pl = s[seq]
            buf += pl
            ends.append(len(buf))
            times.append(t)
        pos = 0
        while pos + 5 <= len(buf):
            n = int.from_bytes(buf[pos:pos + 2], "little")
            if n < 5 or pos + n > len(buf):
                break
            i = bisect.bisect_left(ends, pos + n)
            out.append((times[i], buf[pos:pos + n]))
            pos += n
    out.sort(key=lambda x: x[0])
    return out


def damage_report(packets, markers):
    print("\n=== 4. Dano (mensagem 0x0f4e) ===")
    hits = []  # (tempo, quem, alvo, dano)
    origins = Counter()
    hp = {}
    for t, m in server_messages(packets):
        if m[2] != 0 or int.from_bytes(m[3:5], "little") != OP_HP or len(m) < 5 + 40:
            continue
        b = m[5:]
        origin = struct.unpack_from("<q", b, 0)[0]
        origins[origin] += 1
        if origin != ORIGEM_VIDA_MONSTRO:
            continue
        value = struct.unpack_from("<f", b, 12)[0]
        who, target = struct.unpack_from("<I", b, 16)[0], struct.unpack_from("<I", b, 24)[0]
        max_hp = struct.unpack_from("<f", b, 36)[0]
        seq = struct.unpack_from("<I", b, 40)[0]  # contador de golpes do alvo
        # Alvo visto pela 1ª vez: se é o 1º golpe dele, parte da vida máxima;
        # senão ele já apanhou antes da captura e não dá para saber esse dano.
        prev = hp.get(target, max_hp if seq == 1 else None)
        hp[target] = value
        if prev is not None and prev > value:
            hits.append((t, who, target, prev - value))
    print(f"  Origens vistas nessa mensagem: {origins.most_common(6)}")
    if not hits:
        print("  Nenhum golpe encontrado.")
        return

    def summary(sel, indent="  "):
        by_who = defaultdict(list)
        for t, who, target, d in sel:
            by_who[who].append(d)
        dur = max(sel[-1][0] - sel[0][0], 1)
        total = sum(d for *_, d in sel)
        for who, ds in sorted(by_who.items(), key=lambda kv: -sum(kv[1])):
            s = sum(ds)
            print(f"{indent}quem {who:>10}: {s:>14,.0f} dano  {s / total:6.1%}  "
                  f"{len(ds):>5} golpes  {s / dur:>12,.0f} DPS")

    print(f"  {len(hits)} golpes em {len({h[2] for h in hits})} alvos. Captura inteira:")
    summary(hits)
    notes = [(t, ev) for t, f, ev in markers if f == "nota"]
    if notes:
        print("\n  Entre as notas:")
        bounds = [(hits[0][0] - 1, "(início)")] + notes + [(hits[-1][0] + 1, "(fim)")]
        for (a, na), (b, nb) in zip(bounds, bounds[1:]):
            sel = [h for h in hits if a <= h[0] < b]
            print(f"  -- de \"{na}\" até \"{nb}\"")
            if sel:
                summary(sel, "     ")
            else:
                print("     nenhum golpe")


if __name__ == "__main__":
    main()
