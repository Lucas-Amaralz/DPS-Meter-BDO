"""
Captura o tráfego de rede do Black Desert para análise.

Não toca no processo do jogo: só consulta a tabela de conexões do Windows
(a mesma que o `netstat` mostra) para saber com quais servidores o jogo fala,
e grava cópias dos pacotes que passam pela placa de rede (via Npcap).

Uso:
    python capture.py                 # sessão guiada por bipes (recomendado)
    python capture.py --sem-roteiro   # grava até apertar Ctrl+C
"""
import argparse
import csv
import logging
import sys
import threading
import time
import winsound
from datetime import datetime
from pathlib import Path

import psutil
from scapy.all import IP, AsyncSniffer, PcapWriter, conf

LINKTYPE_RAW = 101  # pacotes gravados a partir do IP, sem a camada de placa de rede

# Gravamos o loopback e a placa de rede no mesmo arquivo como LINKTYPE_RAW; o
# scapy avisa "Inconsistent linktypes" por engano nesse caso.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

GAME_PROCESSES = {"blackdesert64.exe", "blackdesert32.exe", "blackdesert.exe"}

# (id, instrução, repetições, intervalo em segundos)
# repetições=None -> fase contínua com duração = intervalo
ROTEIRO = [
    ("parado", "Fique PARADO, sem apertar nada", None, 30),
    ("andar", "ANDE em linha reta (só andar, sem atacar)", None, 15),
    ("skill", "Use a MESMA SKILL no alvo a cada bip", 10, 6),
    ("basico", "ATAQUE BÁSICO (um clique) a cada bip", 10, 4),
    ("livre", "Combate LIVRE: mate monstros normalmente", None, 60),
    ("parado_final", "Fique PARADO de novo", None, 15),
]


def bip_acao():
    winsound.Beep(1200, 120)


def bip_fase():
    for freq in (600, 900, 1200):
        winsound.Beep(freq, 150)


def game_pids(names):
    return {
        p.pid
        for p in psutil.process_iter(["name"])
        if (p.info["name"] or "").lower() in names
    }


def game_remote_ips(pids):
    ips = {}
    for c in psutil.net_connections(kind="inet"):
        if c.pid in pids and c.raddr:
            ips.setdefault(c.raddr.ip, set()).add(c.raddr.port)
    return ips


def is_local(ip):
    return ip.startswith("127.")


def describe(ip):
    # Com ExitLag (ou outro redutor de ping) o jogo conecta num proxy dentro do próprio PC
    return "proxy local (ExitLag?)" if is_local(ip) else "servidor"


class Capture:
    def __init__(self, out_dir, process_names):
        self.out_dir = out_dir
        self.process_names = process_names
        # ip -> portas remotas vistas. Para servidores externos basta o IP; para o
        # proxy local (127.0.0.1) é preciso casar a porta, senão entraria o tráfego
        # local de qualquer outro programa.
        self.remote = {}
        self.lock = threading.Lock()
        self.writer = PcapWriter(
            str(out_dir / "captura.pcap"), linktype=LINKTYPE_RAW, sync=True
        )
        self.count = 0
        self.stop_event = threading.Event()
        self.sniffer = None
        self.ifaces = set()

    def refresh_endpoints(self):
        pids = game_pids(self.process_names)
        found = game_remote_ips(pids) if pids else {}
        new = []
        with self.lock:
            for ip, ports in found.items():
                known = self.remote.setdefault(ip, set())
                new += [(ip, p) for p in ports - known]
                known.update(ports)
        return pids, found, new

    def wait_for_game(self):
        print("Procurando o jogo e as conexões dele...")
        while True:
            pids, found, _ = self.refresh_endpoints()
            if found:
                print(f"  Jogo encontrado (PID {', '.join(map(str, pids))}).")
                for ip, ports in found.items():
                    print(f"  {describe(ip).capitalize()} {ip} portas {sorted(ports)}")
                return
            msg = "processo não encontrado" if not pids else "sem conexões ainda"
            print(f"  ...{msg}, tentando de novo (abra o jogo e entre no personagem)")
            time.sleep(3)

    def _keep(self, pkt):
        if IP not in pkt:
            return False
        src, dst = pkt[IP].src, pkt[IP].dst
        sport = getattr(pkt, "sport", None)
        dport = getattr(pkt, "dport", None)
        with self.lock:
            for ip, port in ((src, sport), (dst, dport)):
                ports = self.remote.get(ip)
                if ports is not None and (not is_local(ip) or port in ports):
                    return True
        return False

    def _store(self, pkt):
        # Loopback e placa de rede têm cabeçalhos diferentes; guardamos só do IP em diante
        ip = pkt[IP]
        ip.time = pkt.time
        self.writer.write(ip)
        self.count += 1

    def _iface_for(self, ip):
        return conf.route.route(ip)[0]

    def _refresh_loop(self):
        while not self.stop_event.wait(1):
            _, _, new = self.refresh_endpoints()
            for ip, port in new:
                print(f"\n  [nova conexão do jogo: {describe(ip)} {ip}:{port}]")
                if self._iface_for(ip) not in self.ifaces:
                    print("  [AVISO: essa conexão passa por outra placa de rede e não está"
                          " sendo gravada. Reinicie a captura.]")

    def start(self):
        with self.lock:
            self.ifaces = {self._iface_for(ip) for ip in self.remote}
        self.sniffer = AsyncSniffer(
            iface=sorted(self.ifaces), filter="ip", lfilter=self._keep,
            prn=self._store, store=False,
        )
        self.sniffer.start()
        threading.Thread(target=self._refresh_loop, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        if self.sniffer:
            self.sniffer.stop()
        self.writer.close()


class MarkerLog:
    """Lista de marcadores que grava cada linha no CSV assim que é adicionada."""

    def __init__(self, path):
        self.f = open(path, "w", newline="", encoding="utf-8")
        self.w = csv.writer(self.f)
        self.w.writerow(["timestamp", "fase", "evento"])
        self.f.flush()

    def append(self, row):
        self.w.writerow(row)
        self.f.flush()

    def close(self):
        self.f.close()


def write_info(out_dir, cap, t0):
    with cap.lock:
        remote = {ip: sorted(ports) for ip, ports in cap.remote.items()}
    with open(out_dir / "info.txt", "w", encoding="utf-8") as f:
        f.write(f"inicio: {datetime.fromtimestamp(t0).isoformat()}\n")
        f.write(f"duracao_s: {time.time() - t0:.1f}\n")
        for iface in sorted(cap.ifaces):
            f.write(f"interface: {iface}\n")
        f.write(f"pacotes: {cap.count}\n")
        for ip, ports in remote.items():
            f.write(f"servidor: {ip} portas {ports}\n")


def run_roteiro(markers):
    print("\nRoteiro:")
    for i, (_, instr, reps, intervalo) in enumerate(ROTEIRO, 1):
        dur = f"{reps}x, a cada {intervalo}s" if reps else f"{intervalo}s"
        print(f"  {i}. {instr} ({dur})")
    print("\nBipe triplo = começa uma fase nova. Bipe curto = faça a ação.")
    print("Deixe o personagem perto de um alvo (boneco de treino ou monstro).")
    print("\nVolte para o jogo! Começando em 10 segundos...")
    for s in range(10, 0, -1):
        print(f"  {s}", end="\r")
        time.sleep(1)

    for fase, instr, reps, intervalo in ROTEIRO:
        bip_fase()
        markers.append((time.time(), fase, "inicio"))
        print(f"\n>> {instr}")
        if reps is None:
            time.sleep(intervalo)
        else:
            time.sleep(3)  # tempo para se posicionar
            for n in range(1, reps + 1):
                bip_acao()
                markers.append((time.time(), fase, f"acao_{n}"))
                print(f"   ação {n}/{reps}", end="\r")
                time.sleep(intervalo)
        markers.append((time.time(), fase, "fim"))
    bip_fase()
    print("\n\nRoteiro concluído!")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sem-roteiro", action="store_true", help="grava até Ctrl+C")
    ap.add_argument(
        "--processo",
        action="append",
        help="nome do executável do jogo, se for diferente de BlackDesert64.exe",
    )
    args = ap.parse_args()

    names = {n.lower() for n in args.processo} if args.processo else GAME_PROCESSES
    out_dir = Path(__file__).parent / "capturas" / datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_dir.mkdir(parents=True)

    cap = Capture(out_dir, names)
    cap.wait_for_game()
    cap.start()
    print(f"Gravando em: {', '.join(sorted(cap.ifaces))}")

    # Tudo é salvo na hora: se a janela for fechada no X, nada se perde
    t0 = time.time()
    markers = MarkerLog(out_dir / "marcadores.csv")
    write_info(out_dir, cap, t0)
    try:
        if args.sem_roteiro:
            print("Gravando... aperte Ctrl+C para parar.")
            print("Para anotar um momento, digite uma nota aqui e aperte Enter")
            print('(ex.: "só eu batendo", "agora só o amigo", "boss morreu").')
            while True:
                nota = input("> ").strip() or "marca"
                markers.append((time.time(), "nota", nota))
                write_info(out_dir, cap, t0)
                print(f"  anotado ({cap.count} pacotes até agora)")
        else:
            run_roteiro(markers)
    except (KeyboardInterrupt, EOFError):
        print("\nInterrompido.")
    finally:
        cap.stop()
        markers.close()
        write_info(out_dir, cap, t0)

    print(f"\n{cap.count} pacotes gravados em:\n  {out_dir}")
    if cap.count == 0:
        print("Nenhum pacote capturado. Tente rodar como administrador.")
        sys.exit(1)


if __name__ == "__main__":
    main()
