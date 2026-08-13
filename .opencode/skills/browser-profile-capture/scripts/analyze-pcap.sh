#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s <capture.pcapng> <output-directory> <client-ip> <client-port> <server-ip> <server-port> <server-name> <tcp-stream> [tls-keylog]\n' "$0" >&2
}

if (( $# < 8 || $# > 9 )); then
  usage
  exit 64
fi

pcap=$1
output_dir=$2
client_ip=$3
client_port=$4
server_ip=$5
server_port=$6
server_name=$7
tcp_stream=$8
tls_keylog=${9-}

for tool in tshark jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'error: %s is not installed or not on PATH\n' "$tool" >&2
    exit 69
  fi
done

if [[ ! -r $pcap ]]; then
  printf 'error: capture is not readable: %s\n' "$pcap" >&2
  exit 66
fi

if [[ ! -d $output_dir ]]; then
  printf 'error: output directory does not exist: %s\n' "$output_dir" >&2
  exit 72
fi

if [[ ! $client_ip =~ ^[0-9A-Fa-f:.]+$ || ! $server_ip =~ ^[0-9A-Fa-f:.]+$ ]]; then
  printf 'error: client-ip and server-ip must be IPv4 or IPv6 literals\n' >&2
  exit 64
fi

if [[ ! $client_port =~ ^[1-9][0-9]{0,4}$ || $client_port -gt 65535 || ! $server_port =~ ^[1-9][0-9]{0,4}$ || $server_port -gt 65535 ]]; then
  printf 'error: client-port and server-port must be integers from 1 to 65535\n' >&2
  exit 64
fi

if [[ ! $server_name =~ ^[A-Za-z0-9.-]+$ ]]; then
  printf 'error: server-name must be a simple DNS name\n' >&2
  exit 64
fi

if [[ ! $tcp_stream =~ ^[0-9]+$ ]]; then
  printf 'error: tcp-stream must be a non-negative integer\n' >&2
  exit 64
fi

if [[ -n $tls_keylog && ! -r $tls_keylog ]]; then
  printf 'error: TLS key log is not readable: %s\n' "$tls_keylog" >&2
  exit 66
fi

if [[ $client_ip == *:* ]]; then
  client_src_filter="ipv6.src == $client_ip"
else
  client_src_filter="ip.src == $client_ip"
fi

if [[ $server_ip == *:* ]]; then
  server_dst_filter="ipv6.dst == $server_ip"
else
  server_dst_filter="ip.dst == $server_ip"
fi
flow_filter="tcp.stream == $tcp_stream && $client_src_filter && tcp.srcport == $client_port && $server_dst_filter && tcp.dstport == $server_port"
client_hello_filter="$flow_filter && tls.handshake.type == 1 && tls.handshake.extensions_server_name == \"$server_name\""
client_settings_filter="$flow_filter && http2.type == 4 && http2.streamid == 0 && !http2.flags.ack.settings"

tshark_args=(-r "$pcap")
if [[ -n $tls_keylog ]]; then
  tshark_args+=(-o "tls.keylog_file:$tls_keylog")
fi

summary_temp=''
client_hello_temp=''
http2_settings_temp=''
cleanup() {
  [[ -z $summary_temp ]] || rm -f -- "$summary_temp"
  [[ -z $client_hello_temp ]] || rm -f -- "$client_hello_temp"
  [[ -z $http2_settings_temp ]] || rm -f -- "$http2_settings_temp"
}
trap cleanup EXIT

for output in capture-summary.json client-hello.tsv http2-settings.tsv; do
  if [[ -e $output_dir/$output ]]; then
    printf 'error: refusing to overwrite existing artifact: %s\n' "$output_dir/$output" >&2
    exit 73
  fi
done

client_hellos=$(tshark "${tshark_args[@]}" -Y "$client_hello_filter" -T fields -e frame.number | wc -l | tr -d ' ')
http2_settings=$(tshark "${tshark_args[@]}" -Y "$client_settings_filter" -T fields -e frame.number | wc -l | tr -d ' ')
tls_keylog_used=false
if [[ -n $tls_keylog ]]; then
  tls_keylog_used=true
fi

if [[ $client_hellos -lt 1 ]]; then
  printf 'error: no matching ClientHello for the supplied client/server/SNI/TCP flow\n' >&2
  exit 65
fi

summary_temp=$(mktemp "$output_dir/.capture-summary.json.XXXXXX")
client_hello_temp=$(mktemp "$output_dir/.client-hello.tsv.XXXXXX")
http2_settings_temp=$(mktemp "$output_dir/.http2-settings.tsv.XXXXXX")

jq -n \
  --arg pcap "$pcap" \
  --arg client_ip "$client_ip" \
  --argjson client_port "$client_port" \
  --arg server_ip "$server_ip" \
  --argjson server_port "$server_port" \
  --arg server_name "$server_name" \
  --argjson tcp_stream "$tcp_stream" \
  --argjson client_hellos "$client_hellos" \
  --argjson http2_settings "$http2_settings" \
  --argjson tls_keylog_used "$tls_keylog_used" \
  '{schema_version:"2", pcap:$pcap, scoped_flow:{client_ip:$client_ip,client_port:$client_port,server_ip:$server_ip,server_port:$server_port,server_name:$server_name,tcp_stream:$tcp_stream}, tls_keylog_used:$tls_keylog_used, counts:{client_hellos:$client_hellos,client_http2_settings:$http2_settings}}' \
  > "$summary_temp"

tshark "${tshark_args[@]}" -Y "$client_hello_filter" -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e tcp.stream \
  -e ip.src \
  -e ipv6.src \
  -e tcp.srcport \
  -e ip.dst \
  -e ipv6.dst \
  -e tcp.dstport \
  -e tls.handshake.ciphersuite \
  -e tls.handshake.extension.type \
  -e tls.handshake.extensions_supported_group \
  -e tls.handshake.sig_hash_alg \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.extensions_server_name \
  -E header=y -E separator=/t -E quote=d -E occurrence=a \
  > "$client_hello_temp"

tshark "${tshark_args[@]}" -Y "$client_settings_filter" -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e tcp.stream \
  -e ip.src \
  -e ipv6.src \
  -e ip.dst \
  -e ipv6.dst \
  -e http2.streamid \
  -e http2.flags.ack.settings \
  -e http2.settings.id \
  -e http2.settings.header_table_size \
  -e http2.settings.enable_push \
  -e http2.settings.max_concurrent_streams \
  -e http2.settings.initial_window_size \
  -e http2.settings.max_frame_size \
  -e http2.settings.max_header_list_size \
  -e http2.settings.extended_connect \
  -e http2.settings.no_rfc7540_priorities \
  -E header=y -E separator=/t -E quote=d -E occurrence=a \
  > "$http2_settings_temp"

mv "$summary_temp" "$output_dir/capture-summary.json"
mv "$client_hello_temp" "$output_dir/client-hello.tsv"
mv "$http2_settings_temp" "$output_dir/http2-settings.tsv"
summary_temp=''
client_hello_temp=''
http2_settings_temp=''
