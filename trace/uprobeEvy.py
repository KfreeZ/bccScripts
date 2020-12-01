#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF

bpf_text = '''
#include <bcc/proto.h>

int trace_0() {
    bpf_trace_printk("0-Envoy::Server::ConnectionHandlerImpl::ActiveTcpSocket::newConnection\\n");
    return 0;

}

int trace_1() {
    bpf_trace_printk("1-Envoy::Server::ConnectionHandlerImpl::ActiveTcpListener::newConnection\\n");
    return 0;

}

int trace_2() {
    bpf_trace_printk("2-Envoy::Tcp::ConnPoolImpl::newConnection::ConnectionPool::Callback\\n");
    return 0;

}

int trace_3() {
    bpf_trace_printk("3-altEnvoy::Tcp::ConnPoolImpl::newConnection::ConnectionPool::Callback\\n");
    return 0;

}

int trace_4() {
    bpf_trace_printk("4-Envoy::Tcp::OriginalConnPoolImpl::newConnection::ConnectionPool::Callback\\n");
    return 0;

}

int trace_5() {
    bpf_trace_printk("5-Envoy::Extension::TransportSockets::Tls::NotReadySslSocket::doRead\\n");
    return 0;

}

int trace_6() {
    bpf_trace_printk("6-Envoy::Extension::TransportSockets::SslSocket::doRead\\n");
    return 0;

}

int trace_7() {
    bpf_trace_printk("7-Envoy::Extension::TransportSockets::Alts::TsiSocket::doRead\\n");
    return 0;

}

int trace_8() {
    bpf_trace_printk("8-Envoy::Extension::TransportSockets::Tap::TapSocket::doRead\\n");
    return 0;

}

int trace_9() {
    bpf_trace_printk("9-Envoy::Network::RawBufferSocket::doRead\\n");
    return 0;
}


int trace_10() {
    bpf_trace_printk("11-Envoy::Http::Http::StreamEncoderImp::encodeData\\n");
    return 0;

}

int trace_11() {
    bpf_trace_printk("12-altEnvoy::Http::Http::StreamEncoderImp::encodeData\\n");
    return 0;

}
'''
b = BPF(text=bpf_text)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy6Server21ConnectionHandlerImpl15ActiveTcpSocket13newConnectionEv", fn_name="trace_0", pid=70985)
#b.attach_uprobe(name="/usr/local/bin/envoy", sym=" _ZN5Envoy6Server21ConnectionHandlerImpl17ActiveTcpListener13newConnectionEONSt3__110unique_ptrINS_7Network16ConnectionSocketENS3_14default_deleteIS6_EEEERKN5envoy6config4core2v38MetadataE", fn_name="trace_1", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy3Tcp12ConnPoolImpl13newConnectionERNS0_14ConnectionPool9CallbacksE", fn_name="trace_2", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZThn232_N5Envoy3Tcp12ConnPoolImpl13newConnectionERNS0_14ConnectionPool9CallbacksE", fn_name="trace_3", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy3Tcp20OriginalConnPoolImpl13newConnectionERNS0_14ConnectionPool9CallbacksE", fn_name="trace_4", pid=70985)

b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy10Extensions16TransportSockets3Tls12_GLOBAL__N_117NotReadySslSocket6doReadERNS_6Buffer8InstanceE", fn_name="trace_5", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy10Extensions16TransportSockets3Tls9SslSocket6doReadERNS_6Buffer8InstanceE", fn_name="trace_6", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy10Extensions16TransportSockets4Alts9TsiSocket6doReadERNS_6Buffer8InstanceE", fn_name="trace_7", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy10Extensions16TransportSockets3Tap9TapSocket6doReadERNS_6Buffer8InstanceE", fn_name="trace_8", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy7Network15RawBufferSocket6doReadERNS_6Buffer8InstanceE", fn_name="trace_9", pid=70985)

b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZN5Envoy4Http5Http117StreamEncoderImpl10encodeDataERNS_6Buffer8InstanceEb", fn_name="trace_10", pid=70985)
b.attach_uprobe(name="/usr/local/bin/envoy", sym="_ZTv0_n32_N5Envoy4Http5Http117StreamEncoderImpl10encodeDataERNS_6Buffer8InstanceEb", fn_name="trace_11", pid=70985)

while 1:
    # blocking waiting for events
    #b.perf_buffer_poll()
    line = b.trace_readline()
    print(line)
