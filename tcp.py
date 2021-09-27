import asyncio
import random
from os import urandom
from sys import byteorder
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            sequencia_serv = random.randint(0, 0xFFFF)
            ack_no = ack_no +  seq_no + 1
            segmento_serv = make_header(dst_port, src_port, sequencia_serv, ack_no, FLAGS_SYN | FLAGS_ACK)
            self.rede.enviar(fix_checksum(segmento_serv, dst_addr, src_addr), src_addr)
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no + 1)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, sequencia, ultima_seq):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.sequencia = sequencia + 1
        self.send = sequencia
        self.ultima_seq = ultima_seq
        self.ligado = True
        self.t_ligado = False
        self.concat = []
        self.timer = None 
        self.buffer = b''

    def _exemplo_timer(self):
        self.timer = None
        dados = self.concat.pop(0)
        self.concat.insert(0, dados)
        self.servidor.rede.enviar(dados, self.id_conexao[2])
        if self.timer:
            self.timer.cancel()
            self.timer = None
            self.t_ligado = False
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if (self.ligado):
            if (seq_no == self.sequencia and payload):
                if (seq_no > self.send) and ((flags & FLAGS_ACK) == FLAGS_ACK):
                    if len(self.concat) > 0:
                        self.concat.pop(0)
                        if len(self.concat) == 0:
                            if self.timer:
                                self.timer.cancel()
                                self.timer = None
                                self.t_ligado = False
                        else:
                            if self.timer:
                                self.timer.cancel()
                                self.timer = None
                                self.t_ligado = False
                            self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)

                self.timer = None
                self.callback(self, payload)
                self.sequencia = self.sequencia + len(payload)
                self.ultima_seq = ack_no
                if len(payload) > 0:
                    condensador = make_header(self.id_conexao[1], self.id_conexao[3], ack_no, self.sequencia, FLAGS_ACK)
                    self.servidor.rede.enviar(fix_checksum(condensador, self.id_conexao[0], self.id_conexao[2]), self.id_conexao[2])
            else:
                if (seq_no > self.send) and ((flags & FLAGS_ACK) == FLAGS_ACK):
                    if len(self.concat) > 0:
                        self.concat.pop(0)
                        if len(self.concat) == 0:
                            print("timer cancelado")
                            if self.timer:
                                self.timer.cancel()
                                self.timer = None
                                self.t_ligado = False
                        else:
                            if self.timer:
                                self.timer.cancel()
                                self.timer = None
                                self.t_ligado = False
                            self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)
                self.ultima_seq = ack_no

            if (flags & FLAGS_FIN) == FLAGS_FIN:
                self.callback(self, b'')
                self.sequencia = self.sequencia + 1
                self.ultima_seq = ack_no
                condensador2 = make_header(self.id_conexao[1], self.id_conexao[3], self.ultima_seq, self.sequencia, FLAGS_ACK)
                self.servidor.rede.enviar(fix_checksum(condensador2, self.id_conexao[0], self.id_conexao[2]), self.id_conexao[2])
                self.ligado = False

    
    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        buffers = self.buffer
        aux = len(dados)
        if aux <= MSS:
            dados = make_header(self.id_conexao[1], self.id_conexao[3], self.ultima_seq, self.sequencia, FLAGS_ACK) + dados
        else:
            buffers = dados[MSS:]
            dados = make_header(self.id_conexao[1], self.id_conexao[3], self.ultima_seq, self.sequencia, FLAGS_ACK) + dados[:MSS]

        dados = fix_checksum(dados, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(dados, self.id_conexao[2])
        self.concat.append(dados)
        aux = len(dados)
        self.ultima_seq = self.ultima_seq + aux - 20

        if not self.t_ligado:
            if self.timer:
                self.timer.cancel()
                self.timer = None
                self.t_ligado = False
            self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)

        if len(buffers) != 0:
            self.enviar(buffers)

    def fechar(self):
        condensador3 = make_header(self.id_conexao[1], self.id_conexao[3], self.ultima_seq, self.sequencia, FLAGS_ACK | FLAGS_FIN)
        self.servidor.rede.enviar(fix_checksum(condensador3, self.id_conexao[0], self.id_conexao[2]), self.id_conexao[2])
