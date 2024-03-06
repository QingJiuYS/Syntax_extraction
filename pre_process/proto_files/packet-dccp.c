#include "config.h"
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/dccpservicecodes.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/follow.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/exported_pdu.h>
#include <epan/tap.h>
#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include "packet-dccp.h"
#define DCCP_GEN_HDR_LEN_NO_X 12
#define DCCP_GEN_HDR_LEN_X    16
#define DCCP_HDR_LEN 16
#define DCCP_HDR_LEN_MIN 12
#define DCCP_HDR_PKT_TYPES_LEN_MAX 12
#define DCCP_OPT_LEN_MAX 1008#define DCCP_HDR_LEN_MAX (DCCP_HDR_LEN + DCCP_HDR_PKT_TYPES_LEN_MAX + \DCCP_OPT_LEN_MAX)#define DCCP_S_BASE_SEQ_SET 0x01
void proto_register_dccp(void);
void proto_reg_handoff_dccp(void);
static dissector_handle_t dccp_handle;
static const value_string dccp_packet_type_vals[] = {
{0x0, "Request" },{0x1, "Response"},{0x2, "Data"    },{0x3, "Ack"     },{0x4, "DataAck" },{0x5, "CloseReq"},{0x6, "Close"   },{0x7, "Reset"   },{0x8, "Sync"    },{0x9, "SyncAck" },{0xA, "Listen"  },{0xB, "Reserved"},{0xC, "Reserved"},{0xD, "Reserved"},{0xE, "Reserved"},{0xF, "Reserved"},{0,   NULL      }};
static const value_string dccp_service_code_vals[] = {
{ NOT_SPECIFIED_SERVICE_CODE, "not specified" },{ LTP_SERVICE_CODE,           "LTP: Licklider Transmission Protocol" },{ DISC_SERVICE_CODE,          "DISC: Discard" },{ RTCP_SERVICE_CODE,          "RTCP: RTCP connection, separate from the corresponding RTP" },{ RTPA_SERVICE_CODE,          "RTPA: RTP session conveying audio data (and associated RTCP)" },{ RTPO_SERVICE_CODE,          "RTPO: RTP session conveying other media (and associated RTCP)" },{ RTPT_SERVICE_CODE,          "RTPT: RTP session conveying text media (and associated RTCP)" },{ RTPV_SERVICE_CODE,          "RTPV: RTP session conveying video data (and associated RTCP)" },{ SYLG_SERVICE_CODE,          "SYLG: Syslog Protocol" },{ BUNDLES_SERVICE_CODE,       "Bundle Protocol" },{ NPMP_SERVICE_CODE,          "NPMP: NetPerfMeter Data" },{ RESERVED_SERVICE_CODE,      "Reserved (Invalid)" },{ 0,                          NULL } };
static const value_string dccp_reset_code_vals[] = {
{0x00, "Unspecified"       },{0x01, "Closed"            },{0x02, "Aborted"           },{0x03, "No Connection"     },{0x04, "Packet Error"      },{0x05, "Option Error"      },{0x06, "Mandatory Error"   },{0x07, "Connection Refused"},{0x08, "Bad Service Code"  },{0x09, "Too Busy"          },{0x0A, "Bad Init Cookie"   },{0x0B, "Aggression Penalty"},{0x0C, "Reserved"          },{0,    NULL                }};
static const range_string dccp_options_rvals[] = {
{0x00, 0x00, "Padding" },{0x01, 0x01, "Mandatory" },{0x02, 0x02, "Slow Receiver" },{0x03, 0x1F, "Reserved"},{0x20, 0x20, "Change L" },{0x21, 0x21, "Confirm L"},{0x22, 0x22, "Change R" },{0x23, 0x23, "Confirm R"},{0x24, 0x24, "Init Cookie"},{0x25, 0x25, "NDP Count"},{0x26, 0x26, "Ack Vector [Nonce 0]"},{0x27, 0x27, "Ack Vector [Nonce 1]"},{0x28, 0x28, "Data Dropped"},{0x29, 0x29, "Timestamp"},{0x2A, 0x2A, "Timestamp Echo"},{0x2B, 0x2B, "Elapsed Time"},{0x2C, 0x2C, "Data checksum"},{0x2D, 0x2D, "Quick-Start Response"},{0x2E, 0x2E, "Multipath"},{0x2F, 0x7F, "Reserved"},{0x80, 0xBF, "CCID option"},{0xC0, 0xC0, "CCID3 Loss Event Rate"},{0xC1, 0xC1, "CCID3 Loss Intervals"},{0xC2, 0xC2, "CCID3 Receive Rate"},{0xC3, 0xFF, "CCID option"},{0, 0,   NULL}};
static const range_string dccp_feature_numbers_rvals[] = {
{0x00, 0x00, "Reserved" },{0x01, 0x01, "Congestion Control ID (CCID)" },{0x02, 0x02, "Allow Short Seqnums" },{0x03, 0x03, "Sequence Window" },{0x04, 0x04, "ECN Incapable" },{0x05, 0x05, "Ack Ratio" },{0x06, 0x06, "Send Ack Vector" },{0x07, 0x07, "Send NDP Count" },{0x08, 0x08, "Minimum Checksum Coverage" },{0x09, 0x09, "Check Data Checksum" },{0x0A, 0x0A, "MP_CAPABLE" },{0x03, 0x7F, "Reserved"},{0xC0, 0xC0, "Send Loss Event Rate"},{0xC1, 0xFF, "CCID-specific feature"},{0, 0,   NULL}};
static const unit_name_string units_bytes_sec = { "bytes/sec", NULL };
static int proto_dccp = -1;
static int dccp_tap = -1;
static int dccp_follow_tap = -1;
static int hf_dccp_srcport = -1;
static int hf_dccp_dstport = -1;
static int hf_dccp_port = -1;
static int hf_dccp_stream = -1;
static int hf_dccp_data_offset = -1;
static int hf_dccp_ccval = -1;
static int hf_dccp_cscov = -1;
static int hf_dccp_checksum = -1;
static int hf_dccp_checksum_status = -1;
static int hf_dccp_res1 = -1;
static int hf_dccp_type = -1;
static int hf_dccp_x = -1;
static int hf_dccp_res2 = -1;
static int hf_dccp_seq = -1;
static int hf_dccp_seq_abs = -1;
static int hf_dccp_ack_res = -1;
static int hf_dccp_ack = -1;
static int hf_dccp_ack_abs = -1;
static int hf_dccp_service_code = -1;
static int hf_dccp_reset_code = -1;
static int hf_dccp_data1 = -1;
static int hf_dccp_data2 = -1;
static int hf_dccp_data3 = -1;
static int hf_dccp_options = -1;
static int hf_dccp_option_type = -1;
static int hf_dccp_feature_number = -1;
static int hf_dccp_ndp_count = -1;
static int hf_dccp_timestamp = -1;
static int hf_dccp_timestamp_echo = -1;
static int hf_dccp_elapsed_time = -1;
static int hf_dccp_data_checksum = -1;
static int hf_mpdccp_confirm = -1;
static int hf_mpdccp_version = -1;
static int hf_mpdccp_join = -1;
static int hf_mpdccp_join_id = -1;
static int hf_mpdccp_join_token = -1;
static int hf_mpdccp_join_nonce = -1;
static int hf_mpdccp_fast_close = -1;
static int hf_mpdccp_key = -1;
static int hf_mpdccp_key_type = -1;
static int hf_mpdccp_key_key = -1;
static int hf_mpdccp_seq = -1;
static int hf_mpdccp_hmac = -1;
static int hf_mpdccp_hmac_sha = -1;
static int hf_mpdccp_rtt = -1;
static int hf_mpdccp_rtt_type = -1;
static int hf_mpdccp_rtt_value = -1;
static int hf_mpdccp_rtt_age = -1;
static int hf_mpdccp_addaddr = -1;
static int hf_mpdccp_addrid = -1;
static int hf_mpdccp_addr_dec=-1;
static int hf_mpdccp_addr_hex=-1;
static int hf_mpdccp_addrport=-1;
static int hf_mpdccp_removeaddr = -1;
static int hf_mpdccp_prio = -1;
static int hf_mpdccp_prio_value = -1;
static int hf_mpdccp_close = -1;
static int hf_mpdccp_close_key = -1;
static int hf_mpdccp_exp=-1;
static int hf_dccp_option_data = -1;
static int hf_dccp_padding = -1;
static int hf_dccp_mandatory = -1;
static int hf_dccp_slow_receiver = -1;
static int hf_dccp_init_cookie = -1;
static int hf_dccp_ack_vector_nonce_0 = -1;
static int hf_dccp_ack_vector_nonce_1 = -1;
static int hf_dccp_data_dropped = -1;
static int hf_dccp_ccid3_loss_event_rate = -1;
static int hf_dccp_ccid3_loss_intervals = -1;
static int hf_dccp_ccid3_receive_rate = -1;
static int hf_dccp_option_reserved = -1;
static int hf_dccp_ccid_option_data = -1;
static int hf_dccp_option_unknown = -1;
static gint ett_dccp = -1;
static gint ett_dccp_options = -1;
static gint ett_dccp_options_item = -1;
static gint ett_dccp_feature = -1;
static expert_field ei_dccp_option_len_bad = EI_INIT;
static expert_field ei_dccp_advertised_header_length_bad = EI_INIT;
static expert_field ei_dccp_packet_type_reserved = EI_INIT;
static expert_field ei_dccp_checksum = EI_INIT;
static dissector_table_t dccp_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static gboolean dccp_summary_in_tree = TRUE;
static gboolean try_heuristic_first  = FALSE;
static gboolean dccp_check_checksum  = TRUE;
static gboolean dccp_relative_seq    = TRUE;
static guint32  dccp_stream_count;
static void
decode_dccp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,proto_tree *tree, int sport, int dport){
tvbuff_t *next_tvb;
int       low_port, high_port;
heur_dtbl_entry_t *hdtbl_entry;
next_tvb = tvb_new_subset_remaining(tvb, offset);
if (have_tap_listener(dccp_follow_tap)) {
tap_queue_packet(dccp_follow_tap, pinfo, next_tvb);
}
if (try_conversation_dissector(&pinfo->src, &pinfo->dst, CONVERSATION_DCCP, sport,dport, next_tvb, pinfo, tree, NULL, 0)) {
return;
}
if (try_heuristic_first) {
if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo,tree, &hdtbl_entry, NULL)) {
return;
}
}
if (sport > dport) {
low_port  = dport;
high_port = sport;
}
else {
low_port  = sport;
high_port = dport;
}
if (low_port != 0 &&dissector_try_uint(dccp_subdissector_table, low_port,next_tvb, pinfo, tree)) {
return;
}
if (high_port != 0 &&dissector_try_uint(dccp_subdissector_table, high_port,next_tvb, pinfo, tree)) {
return;
}
if (!try_heuristic_first) {
if (dissector_try_heuristic(heur_subdissector_list, next_tvb,pinfo, tree, &hdtbl_entry, NULL)) {
return;
}
}
call_data_dissector(next_tvb, pinfo, tree);
}
static struct dccp_analysis *
init_dccp_conversation_data(packet_info *pinfo)
{
struct dccp_analysis *dccpd;
dccpd = wmem_new0(wmem_file_scope(), struct dccp_analysis);
dccpd->flow1.static_flags = 0;
dccpd->flow1.base_seq     = 0;
dccpd->flow2.static_flags = 0;
dccpd->flow2.base_seq     = 0;
dccpd->stream   = dccp_stream_count++;
dccpd->ts_first = pinfo->abs_ts;
dccpd->ts_prev  = pinfo->abs_ts;
return dccpd;
}
static struct dccp_analysis *
get_dccp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
int direction;
struct dccp_analysis *dccpd;
dccpd=(struct dccp_analysis *)conversation_get_proto_data(conv, proto_dccp);
if (!dccpd) {
dccpd = init_dccp_conversation_data(pinfo);
conversation_add_proto_data(conv, proto_dccp, dccpd);
}
direction=cmp_address(&pinfo->src, &pinfo->dst);
if (direction == 0) {
direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
}
if (direction >= 0) {
dccpd->fwd=&(dccpd->flow1);
dccpd->rev=&(dccpd->flow2);
}
else {
dccpd->fwd=&(dccpd->flow2);
dccpd->rev=&(dccpd->flow1);
}
return dccpd;
}
static const char* dccp_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
if (filter == CONV_FT_SRC_PORT) {
return "dccp.srcport";
}
if (filter == CONV_FT_DST_PORT) {
return "dccp.dstport";
}
if (filter == CONV_FT_ANY_PORT) {
return "dccp.port";
}
if(!conv) {
return CONV_FILTER_INVALID;
}
if (filter == CONV_FT_SRC_ADDRESS) {
if (conv->src_address.type == AT_IPv4) {
return "ip.src";
}
if (conv->src_address.type == AT_IPv6) {
return "ipv6.src";
}
}
if (filter == CONV_FT_DST_ADDRESS) {
if (conv->dst_address.type == AT_IPv4) {
return "ip.dst";
}
if (conv->dst_address.type == AT_IPv6) {
return "ipv6.dst";
}
}
if (filter == CONV_FT_ANY_ADDRESS) {
if (conv->src_address.type == AT_IPv4) {
return "ip.addr";
}
if (conv->src_address.type == AT_IPv6) {
return "ipv6.addr";
}
}
return CONV_FILTER_INVALID;
}
static ct_dissector_info_t dccp_ct_dissector_info = {&dccp_conv_get_filter_type};
static tap_packet_status
dccpip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
conv_hash_t *hash = (conv_hash_t*) pct;
hash->flags = flags;
const e_dccphdr *dccphdr=(const e_dccphdr *)vip;
add_conversation_table_data_with_conv_id(hash, &dccphdr->ip_src, &dccphdr->ip_dst, dccphdr->sport, dccphdr->dport, (conv_id_t) dccphdr->stream, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &dccp_ct_dissector_info, CONVERSATION_DCCP);
return TAP_PACKET_REDRAW;
}
static const char* dccp_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
if (filter == CONV_FT_SRC_PORT) {
return "dccp.srcport";
}
if (filter == CONV_FT_DST_PORT) {
return "dccp.dstport";
}
if (filter == CONV_FT_ANY_PORT) {
return "dccp.port";
}
if(!endpoint) {
return CONV_FILTER_INVALID;
}
if (filter == CONV_FT_SRC_ADDRESS) {
if (endpoint->myaddress.type == AT_IPv4) {
return "ip.src";
}
if (endpoint->myaddress.type == AT_IPv6) {
return "ipv6.src";
}
}
if (filter == CONV_FT_DST_ADDRESS) {
if (endpoint->myaddress.type == AT_IPv4) {
return "ip.dst";
}
if (endpoint->myaddress.type == AT_IPv6) {
return "ipv6.dst";
}
}
if (filter == CONV_FT_ANY_ADDRESS) {
if (endpoint->myaddress.type == AT_IPv4) {
return "ip.addr";
}
if (endpoint->myaddress.type == AT_IPv6) {
return "ipv6.addr";
}
}
return CONV_FILTER_INVALID;
}
static et_dissector_info_t dccp_endpoint_dissector_info = {&dccp_endpoint_get_filter_type};
static tap_packet_status
dccpip_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags )
{
conv_hash_t *hash = (conv_hash_t*) pit;
hash->flags = flags;
const e_dccphdr *dccphdr=(const e_dccphdr *)vip;
add_endpoint_table_data(hash, &dccphdr->ip_src, dccphdr->sport, TRUE, 1, pinfo->fd->pkt_len, &dccp_endpoint_dissector_info, ENDPOINT_DCCP);
add_endpoint_table_data(hash, &dccphdr->ip_dst, dccphdr->dport, FALSE, 1, pinfo->fd->pkt_len, &dccp_endpoint_dissector_info, ENDPOINT_DCCP);
return TAP_PACKET_REDRAW;
}
guint32 get_dccp_stream_count(void)
{
return dccp_stream_count;
}
static gboolean
dccp_filter_valid(packet_info *pinfo, void *user_data _U_)
{
return proto_is_frame_protocol(pinfo->layers, "dccp");
}
static gchar*
dccp_build_filter(packet_info *pinfo, void *user_data _U_)
{
if( pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4 ) {
return ws_strdup_printf("(ip.addr eq %s and ip.addr eq %s) and (dccp.port eq %d and dccp.port eq %d)",address_to_str(pinfo->pool, &pinfo->net_src),address_to_str(pinfo->pool, &pinfo->net_dst),pinfo->srcport, pinfo->destport );
}
if( pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6 ) {
return ws_strdup_printf("(ipv6.addr eq %s and ipv6.addr eq %s) and (dccp.port eq %d and dccp.port eq %d)",address_to_str(pinfo->pool, &pinfo->net_src),address_to_str(pinfo->pool, &pinfo->net_dst),pinfo->srcport, pinfo->destport );
}
return NULL;
}
static gchar *dccp_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo, guint *stream, guint *sub_stream _U_)
{
conversation_t *conv;
struct dccp_analysis *dccpd;
if (((pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) ||(pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6))&& (pinfo->ptype == PT_DCCP) &&(conv=find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst, CONVERSATION_DCCP, pinfo->srcport, pinfo->destport, 0)) != NULL){
dccpd = get_dccp_conversation_data(conv, pinfo);
*stream = dccpd->stream;
return ws_strdup_printf("dccp.stream eq %u", dccpd->stream);
}
return NULL;
}
static gchar *dccp_follow_index_filter(guint stream, guint sub_stream _U_)
{
return ws_strdup_printf("dccp.stream eq %u", stream);
}
static gchar *dccp_follow_address_filter(address *src_addr, address *dst_addr, int src_port, int dst_port)
{
const gchar  *ip_version = src_addr->type == AT_IPv6 ? "v6" : "";
gchar         src_addr_str[WS_INET6_ADDRSTRLEN];
gchar         dst_addr_str[WS_INET6_ADDRSTRLEN];
address_to_str_buf(src_addr, src_addr_str, sizeof(src_addr_str));
address_to_str_buf(dst_addr, dst_addr_str, sizeof(dst_addr_str));
return ws_strdup_printf("((ip%s.src eq %s and dccp.srcport eq %d) and "
"(ip%s.dst eq %s and dccp.dstport eq %d))"
" or "
"((ip%s.src eq %s and dccp.srcport eq %d) and "
"(ip%s.dst eq %s and dccp.dstport eq %d))",ip_version, src_addr_str, src_port,ip_version, dst_addr_str, dst_port,ip_version, dst_addr_str, dst_port,ip_version, src_addr_str, src_port);
}
static guint64
dccp_ntoh_var(tvbuff_t *tvb, gint offset, guint nbytes)
{
guint64       value = 0;
switch (nbytes)
{
case 5:
value = tvb_get_ntoh40(tvb, offset);
break;
case 4:
value = tvb_get_ntohl(tvb, offset);
break;
case 3:
value = tvb_get_ntoh24(tvb, offset);
break;
case 2:
value = tvb_get_ntohs(tvb, offset);
break;
case 1:
value = tvb_get_guint8(tvb, offset);
break;
case 0:
break;
case 6:
default:
value = tvb_get_ntoh48(tvb, offset);
break;
}
return value;
}
static void
dissect_feature_options(proto_tree *dccp_options_tree, tvbuff_t *tvb,int offset, guint8 option_len){
guint8      feature_number = tvb_get_guint8(tvb, offset);
proto_item *dccp_item;
proto_tree *feature_tree;
int         i;
feature_tree =proto_tree_add_subtree_format(dccp_options_tree, tvb, offset, option_len,ett_dccp_feature, &dccp_item, "%s(",rval_to_str_const(feature_number, dccp_feature_numbers_rvals, "Unknown feature number"));
if (feature_number != 10) {
proto_tree_add_uint(feature_tree, hf_dccp_feature_number, tvb,offset, 1, feature_number);
}
else {
proto_tree_add_item(feature_tree, hf_mpdccp_version, tvb,offset, option_len, ENC_BIG_ENDIAN);
}
offset++;
option_len--;
switch (feature_number) {
case 1:
case 2:
case 4:
case 6:
case 7:
case 8:
case 9:
case 192:
for (i = 0; i < option_len; i++) {
proto_item_append_text(dccp_item, "%s %d", i ? "," : "",tvb_get_guint8(tvb,offset + i));
}
break;
case 3:
case 5:
if (option_len > 0) {
proto_item_append_text(dccp_item, " %" PRIu64,dccp_ntoh_var(tvb, offset, option_len));
}
break;
case 10:
for (i = 0; i < option_len; i++) {
proto_item_append_text(dccp_item, "%s %d", i ? "," : "", feature_number);
}
break;
default:
proto_item_append_text(dccp_item, "%d", feature_number);
break;
}
proto_item_append_text(dccp_item, ")");
}
static void
dissect_options(tvbuff_t *tvb, packet_info *pinfo,proto_tree *dccp_options_tree, proto_tree *tree _U_,e_dccphdr *dccph _U_,int offset_start,int offset_end){
int         offset      = offset_start;
guint8      option_type = 0;
guint8      option_len  = 0;
guint32     p;
guint8      mp_option_type = 0;
proto_item *option_item;
proto_tree *option_tree;
proto_item *mp_option_sub_item;
proto_tree *mp_option_sub_tree;
while (offset < offset_end) {
option_type = tvb_get_guint8(tvb, offset);
option_item =proto_tree_add_uint(dccp_options_tree, hf_dccp_option_type, tvb,offset,1,option_type);
if (option_type >= 32) {
option_len = tvb_get_guint8(tvb, offset+1);
if (option_len < 2) {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Option length incorrect, must be >= 2");
return;
}
proto_item_set_len(option_item, option_len);
offset += 2;
option_len -= 2;
}
else {
option_len = 1;
}
option_tree = proto_item_add_subtree(option_item, ett_dccp_options_item);
switch (option_type) {
case 0:
proto_tree_add_item(option_tree, hf_dccp_padding, tvb, offset, option_len, ENC_NA);
break;
case 1:
proto_tree_add_item(option_tree, hf_dccp_mandatory, tvb, offset, option_len, ENC_NA);
break;
case 2:
proto_tree_add_item(option_tree, hf_dccp_slow_receiver, tvb, offset, option_len, ENC_NA);
break;
case 32:
case 33:
case 34:
case 35:
dissect_feature_options(option_tree, tvb, offset, option_len);
break;
case 36:
proto_tree_add_item(option_tree, hf_dccp_init_cookie, tvb, offset, option_len, ENC_NA);
break;
case 37:
if (option_len > 6) {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"NDP Count too long (max 6 bytes)");
}
else {
proto_tree_add_item(option_tree, hf_dccp_ndp_count, tvb, offset, option_len, ENC_BIG_ENDIAN);
}
break;
case 38:
proto_tree_add_item(option_tree, hf_dccp_ack_vector_nonce_0, tvb, offset, option_len, ENC_NA);
break;
case 39:
proto_tree_add_item(option_tree, hf_dccp_ack_vector_nonce_1, tvb, offset, option_len, ENC_NA);
break;
case 40:
proto_tree_add_item(option_tree, hf_dccp_data_dropped, tvb, offset, option_len, ENC_NA);
break;
case 41:
if (option_len == 4) {
proto_tree_add_item(option_tree, hf_dccp_timestamp, tvb,offset, 4, ENC_BIG_ENDIAN);
}
else {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Timestamp too long [%u != 4]", option_len);
}
break;
case 42:
if (option_len == 4) {
proto_tree_add_item(option_tree, hf_dccp_timestamp_echo,tvb, offset, 4, ENC_BIG_ENDIAN);
}
else if (option_len == 6) {
proto_tree_add_item(option_tree, hf_dccp_timestamp_echo,tvb, offset, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset + 4, 2, ENC_BIG_ENDIAN);
}
else if (option_len == 8) {
proto_tree_add_item(option_tree, hf_dccp_timestamp_echo,tvb, offset, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset + 4, 4, ENC_BIG_ENDIAN);
}
else {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong Timestamp Echo length");
}
break;
case 43:
if (option_len == 2) {
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset, 2, ENC_BIG_ENDIAN);
}
else if (option_len == 4) {
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset, 4, ENC_BIG_ENDIAN);
}
else {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong Elapsed Time length");
}
break;
case 44:
if (option_len == 4) {
proto_tree_add_item(option_tree, hf_dccp_data_checksum,tvb, offset, 4, ENC_BIG_ENDIAN);
}
else {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong Data checksum length");
}
break;
case 46:
mp_option_type = tvb_get_guint8(tvb, offset);
option_len -= 1;
switch (mp_option_type) {
case 0:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_confirm, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
dissect_options(tvb, pinfo, mp_option_sub_tree, tree, dccph, offset, offset + option_len);
break;
case 1:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_join, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
if (option_len == 9) {
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_join_id, tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_join_token, tvb, offset+1, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_join_nonce, tvb, offset+5, 4, ENC_BIG_ENDIAN);
}
else {
mp_option_sub_item = proto_tree_add_item(option_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 9]", option_len);
}
break;
case 2:
proto_tree_add_item(option_tree, hf_mpdccp_fast_close, tvb, offset, option_len, ENC_NA);
break;
case 3:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_key, tvb, offset, 1, ENC_NA);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
if (option_len > 8 && option_len < 69) {
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_key_type, tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_key_key, tvb, offset+1, option_len-1, ENC_NA);
}
else {
mp_option_sub_item = proto_tree_add_item(mp_option_sub_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [8 < %u < 69]", option_len);
}
break;
case 4:
if (option_len == 6) {
offset += 1;
proto_tree_add_item(option_tree, hf_mpdccp_seq, tvb, offset, 6, ENC_BIG_ENDIAN);
}
else  {
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_seq, tvb, offset, option_len, ENC_BIG_ENDIAN);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 6]", option_len);
}
break;
case 5:
if (option_len == 20) {
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_hmac, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_hmac_sha, tvb, offset, 20, ENC_NA);
}
else {
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_hmac, tvb, offset, option_len, ENC_BIG_ENDIAN);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 20]", option_len);
}
break;
case 6:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_rtt, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
if (option_len == 9) {
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_rtt_type,tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_rtt_value,tvb, offset+1, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_rtt_age,tvb, offset+5, 4, ENC_BIG_ENDIAN);
}
else {
mp_option_sub_item = proto_tree_add_item(mp_option_sub_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 9]", option_len);
}
break;
case 7:
mp_option_sub_item=proto_tree_add_item(option_tree,hf_mpdccp_addaddr,tvb,offset,1,ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
switch (option_len) {
case 5:
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrid,tvb,offset,1,ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addr_dec,tvb,offset+1,4,ENC_LITTLE_ENDIAN);
break;
case 7:
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrid,tvb,offset,1,ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addr_dec,tvb,offset+1,4,ENC_LITTLE_ENDIAN);
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrport,tvb,offset+5,2,ENC_BIG_ENDIAN);
break;
case 17:
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrid,tvb,offset,1,ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addr_hex,tvb,offset+1,16,ENC_NA);
break;
case 19:
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrid,tvb,offset,1,ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addr_hex,tvb,offset+1,16,ENC_NA);
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrport,tvb,offset+17,2,ENC_BIG_ENDIAN);
break;
default:
mp_option_sub_item = proto_tree_add_item(mp_option_sub_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 5 || 7 || 17 || 19]", option_len);
break;
}
break;
case 8:
if (option_len == 1) {
mp_option_sub_item=proto_tree_add_item(option_tree,hf_mpdccp_removeaddr,tvb,offset,1,ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrid,tvb,offset,1,ENC_BIG_ENDIAN);
}
else {
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_removeaddr, tvb, offset, option_len, ENC_BIG_ENDIAN);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 1]", option_len);
}
break;
case 9:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
if (option_len == 1) {
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_prio_value, tvb, offset, 1, ENC_BIG_ENDIAN);
}
else {
mp_option_sub_item = proto_tree_add_item(mp_option_sub_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 1]", option_len);
}
break;
case 10:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_close,tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_close_key, tvb, offset, option_len, ENC_BIG_ENDIAN);
break;
case 11:
proto_tree_add_item(option_tree, hf_mpdccp_exp, tvb, offset, option_len, ENC_NA);
break;
default:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"MP-DCCP option [%u] not defined, [len: %u ]", mp_option_type, option_len);
break;
}
break;
case 192:
if (option_len == 4) {
p = tvb_get_ntohl(tvb, offset);
if (p == 0xFFFFFFFF) {
proto_tree_add_uint_format_value(option_tree, hf_dccp_ccid3_loss_event_rate, tvb, offset,option_len, p, "0 (or max)");
}
else {
proto_tree_add_uint(option_tree, hf_dccp_ccid3_loss_event_rate, tvb, offset, option_len, p);
}
}
else {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong CCID3 Loss Event Rate length");
}
break;
case 193:
proto_tree_add_item(dccp_options_tree, hf_dccp_ccid3_loss_intervals, tvb, offset, option_len, ENC_NA);
break;
case 194:
if (option_len == 4) {
proto_tree_add_uint_format_value(option_tree, hf_dccp_ccid3_receive_rate, tvb, offset, option_len,tvb_get_ntohl(tvb, offset), "%u bytes/sec",tvb_get_ntohl(tvb, offset));
}
else {
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong CCID3 Receive Rate length");
}
break;
default:
if (((option_type >= 47) && (option_type <= 127)) ||((option_type >= 3) && (option_type <= 31))) {
proto_tree_add_item(option_tree, hf_dccp_option_reserved, tvb, offset, option_len, ENC_NA);
break;
}
if (option_type >= 128) {
proto_tree_add_bytes_format(option_tree, hf_dccp_ccid_option_data, tvb, offset, option_len,NULL, "CCID option %d", option_type);
break;
}
proto_tree_add_item(option_tree, hf_dccp_option_unknown, tvb, offset, option_len, ENC_NA);
break;
}
offset += option_len;
}
}
static inline guint
dccp_csum_coverage(const e_dccphdr *dccph, guint len)
{
guint cov;
if (dccph->cscov == 0) {
return len;
}
cov = (dccph->data_offset + dccph->cscov - 1) * (guint)sizeof (guint32);
return (cov > len) ? len : cov;
}
static int
dissect_dccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
proto_tree *dccp_tree;
proto_item *item;
proto_tree *dccp_options_tree = NULL;
proto_item *dccp_item         = NULL;
proto_item *hidden_item, *offset_item;
vec_t      cksum_vec[4];
guint32    phdr[2];
guint      offset                     = 0;
guint      len                        = 0;
guint      reported_len               = 0;
guint      csum_coverage_len;
guint      advertised_dccp_header_len = 0;
guint      options_len                = 0;
guint64    seq;
guint64    ack;
e_dccphdr *dccph;
conversation_t *conv = NULL;
struct dccp_analysis *dccpd;
dccph = wmem_new0(pinfo->pool, e_dccphdr);
dccph->sport = tvb_get_ntohs(tvb, offset);
dccph->dport = tvb_get_ntohs(tvb, offset + 2);
copy_address_shallow(&dccph->ip_src, &pinfo->src);
copy_address_shallow(&dccph->ip_dst, &pinfo->dst);
col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCCP");
col_clear(pinfo->cinfo, COL_INFO);
col_append_ports(pinfo->cinfo, COL_INFO, PT_DCCP, dccph->sport, dccph->dport);
dccp_item = proto_tree_add_item(tree, proto_dccp, tvb, offset, -1, ENC_NA);
if (dccp_summary_in_tree) {
proto_item_append_text(dccp_item, ", Src Port: %s, Dst Port: %s",port_with_resolution_to_str(pinfo->pool, PT_DCCP, dccph->sport),port_with_resolution_to_str(pinfo->pool, PT_DCCP, dccph->dport));
}
dccp_tree = proto_item_add_subtree(dccp_item, ett_dccp);
proto_tree_add_item(dccp_tree, hf_dccp_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
hidden_item = proto_tree_add_item(dccp_tree, hf_dccp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
proto_item_set_hidden(hidden_item);
offset += 2;
proto_tree_add_item(dccp_tree, hf_dccp_dstport, tvb, offset, 2, ENC_BIG_ENDIAN);
hidden_item = proto_tree_add_item(dccp_tree, hf_dccp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
proto_item_set_hidden(hidden_item);
offset += 2;
pinfo->ptype = PT_DCCP;
pinfo->srcport = dccph->sport;
pinfo->destport = dccph->dport;
conv = find_or_create_conversation(pinfo);
dccpd = get_dccp_conversation_data(conv, pinfo);
item = proto_tree_add_uint(dccp_tree, hf_dccp_stream, tvb, offset, 0, dccpd->stream);
proto_item_set_generated(item);
dccph->stream = dccpd->stream;
dccph->data_offset = tvb_get_guint8(tvb, offset);
advertised_dccp_header_len = dccph->data_offset * 4;
offset_item = proto_tree_add_uint(dccp_tree, hf_dccp_data_offset, tvb, offset, 1,dccph->data_offset);
offset += 1;
dccph->cscov = tvb_get_guint8(tvb, offset) & 0x0F;
dccph->ccval = tvb_get_guint8(tvb, offset) & 0xF0;
dccph->ccval >>= 4;
proto_tree_add_uint(dccp_tree, hf_dccp_ccval, tvb, offset, 1,dccph->ccval);
proto_tree_add_uint(dccp_tree, hf_dccp_cscov, tvb, offset, 1,dccph->cscov);
offset += 1;
dccph->checksum = tvb_get_ntohs(tvb, offset);
reported_len = tvb_reported_length(tvb);
len = tvb_captured_length(tvb);
csum_coverage_len = dccp_csum_coverage(dccph, reported_len);
if (dccp_check_checksum && !pinfo->fragmented && len >= csum_coverage_len) {
SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data, pinfo->src.len);
SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data, pinfo->dst.len);
switch (pinfo->src.type) {
case AT_IPv4:
phdr[0] = g_htonl((IP_PROTO_DCCP << 16) + reported_len);
SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *) &phdr, 4);
break;
case AT_IPv6:
phdr[0] = g_htonl(reported_len);
phdr[1] = g_htonl(IP_PROTO_DCCP);
SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *) &phdr, 8);
break;
default:
DISSECTOR_ASSERT_NOT_REACHED();
break;
}
SET_CKSUM_VEC_TVB(cksum_vec[3], tvb, 0, csum_coverage_len);
proto_tree_add_checksum(dccp_tree, tvb, offset, hf_dccp_checksum, hf_dccp_checksum_status, &ei_dccp_checksum, pinfo, in_cksum(&cksum_vec[0], 4),ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
}
else {
proto_tree_add_checksum(dccp_tree, tvb, offset, hf_dccp_checksum, hf_dccp_checksum_status, &ei_dccp_checksum, pinfo, 0,ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
}
offset += 2;
dccph->reserved1 = tvb_get_guint8(tvb, offset) & 0xE0;
dccph->reserved1 >>= 5;
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_res1, tvb, offset, 1,dccph->reserved1);
proto_item_set_hidden(hidden_item);
dccph->type = tvb_get_guint8(tvb, offset) & 0x1E;
dccph->type >>= 1;
proto_tree_add_uint(dccp_tree, hf_dccp_type, tvb, offset, 1,dccph->type);
if (dccp_summary_in_tree) {
proto_item_append_text(dccp_item, " [%s]",val_to_str_const(dccph->type, dccp_packet_type_vals,"Unknown Type"));
}
col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]",val_to_str_const(dccph->type, dccp_packet_type_vals,"Unknown Type"));
dccph->x = tvb_get_guint8(tvb, offset) & 0x01;
proto_tree_add_boolean(dccp_tree, hf_dccp_x, tvb, offset, 1,dccph->x);
offset += 1;
if (dccph->x) {
if (advertised_dccp_header_len < DCCP_GEN_HDR_LEN_X) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u)",advertised_dccp_header_len, DCCP_GEN_HDR_LEN_X);
return tvb_reported_length(tvb);
}
dccph->reserved2 = tvb_get_guint8(tvb, offset);
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_res2, tvb, offset, 1,dccph->reserved2);
proto_item_set_hidden(hidden_item);
offset += 1;
dccph->seq = tvb_get_ntoh48(tvb, offset);
if((dccp_relative_seq) && (dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET)) {
seq = dccph->seq - dccpd->fwd->base_seq;
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_seq, tvb, offset, 6,seq, "%" PRIu64 "    (relative sequence number)", seq);
}
else {
seq = dccph->seq;
}
proto_tree_add_uint64(dccp_tree, hf_dccp_seq_abs, tvb, offset, 6, dccph->seq);
offset += 6;
}
else {
if (advertised_dccp_header_len < DCCP_GEN_HDR_LEN_NO_X) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u)",advertised_dccp_header_len, DCCP_GEN_HDR_LEN_NO_X);
return tvb_reported_length(tvb);
}
dccph->seq = tvb_get_ntoh24(tvb, offset);
proto_tree_add_uint64(dccp_tree, hf_dccp_seq, tvb, offset, 3, dccph->seq);
if((dccp_relative_seq) && (dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET)) {
seq = (dccph->seq - dccpd->fwd->base_seq) & 0xffffff;
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_seq, tvb, offset, 3,seq, "%" PRIu64 "    (relative sequence number)", seq);
}
else {
seq = dccph->seq;
}
offset += 3;
}
if (dccp_summary_in_tree) {
proto_item_append_text(dccp_item, " Seq=%" PRIu64, seq);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%" PRIu64, seq);
switch (dccph->type) {
case 0x0:
case 0xA:
if (advertised_dccp_header_len < offset + 4) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 4,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
dccph->service_code = tvb_get_ntohl(tvb, offset);
if (tree) {
proto_tree_add_uint(dccp_tree, hf_dccp_service_code, tvb, offset, 4,dccph->service_code);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%s)",val_to_str(dccph->service_code, dccp_service_code_vals, "Unknown (%u)"));
offset += 4;
if( !(dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET) ) {
dccpd->fwd->base_seq = dccph->seq;
dccpd->fwd->static_flags |= DCCP_S_BASE_SEQ_SET;
}
break;
case 0x1:
if (advertised_dccp_header_len < offset + 12) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for Response",advertised_dccp_header_len, offset + 12);
return tvb_reported_length(tvb);
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree) {
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
ack = dccph->ack - dccpd->rev->base_seq;
}
else {
ack = dccph->ack;
}
if (tree) {
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6, ack);
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 2, 6, dccph->ack);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
dccph->service_code = tvb_get_ntohl(tvb, offset);
if (tree) {
proto_tree_add_uint(dccp_tree, hf_dccp_service_code, tvb, offset, 4,dccph->service_code);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%s)",val_to_str(dccph->service_code, dccp_service_code_vals, "Unknown (%u)"));
offset += 4;
if( !(dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET) ) {
dccpd->fwd->base_seq = dccph->seq;
dccpd->fwd->static_flags |= DCCP_S_BASE_SEQ_SET;
}
break;
case 0x2:
break;
case 0x3:
case 0x4:
if (dccph->x) {
if (advertised_dccp_header_len < offset + 8) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 8,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree) {
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset,2, dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
ack = dccph->ack - dccpd->rev->base_seq;
}
else {
ack = dccph->ack;
}
if (tree) {
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 2, 6, dccph->ack);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
}
else {
if (advertised_dccp_header_len < offset + 4) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 4,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
dccph->ack_reserved = tvb_get_guint8(tvb, offset);
if (tree) {
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset,1, dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
dccph->ack = tvb_get_guint8(tvb, offset + 1);
dccph->ack <<= 16;
dccph->ack += tvb_get_ntohs(tvb, offset + 2);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
ack = (dccph->ack - dccpd->rev->base_seq) & 0xffffff;
}
else {
ack = dccph->ack;
}
if (tree) {
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 1, 3,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 1, 3, dccph->ack);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 4;
}
break;
case 0x7:
if (advertised_dccp_header_len < offset + 4) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for Reset",advertised_dccp_header_len, offset + 4);
return tvb_reported_length(tvb);
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree) {
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
ack = (dccph->ack - dccpd->rev->base_seq) & 0xffffff;
}
else {
ack = dccph->ack;
}
if (tree) {
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 1, 3,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 1, 3, dccph->ack);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
dccph->reset_code = tvb_get_guint8(tvb, offset);
dccph->data1 = tvb_get_guint8(tvb, offset + 1);
dccph->data2 = tvb_get_guint8(tvb, offset + 2);
dccph->data3 = tvb_get_guint8(tvb, offset + 3);
if (tree) {
proto_tree_add_uint(dccp_tree, hf_dccp_reset_code, tvb, offset, 1,dccph->reset_code);
proto_tree_add_uint(dccp_tree, hf_dccp_data1, tvb, offset + 1, 1,dccph->data1);
proto_tree_add_uint(dccp_tree, hf_dccp_data2, tvb, offset + 2, 1,dccph->data2);
proto_tree_add_uint(dccp_tree, hf_dccp_data3, tvb, offset + 3, 1,dccph->data3);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (code=%s)",val_to_str_const(dccph->reset_code, dccp_reset_code_vals,"Unknown"));
offset += 4;
break;
case 0x5:
case 0x6:
case 0x8:
case 0x9:
if (advertised_dccp_header_len < offset + 8) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 8,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree) {
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
ack = (dccph->ack - dccpd->rev->base_seq) & 0xffffff;
}
else {
ack = dccph->ack;
}
if (tree) {
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET)) {
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 1, 3,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 1, 3, dccph->ack);
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
break;
default:
expert_add_info(pinfo, dccp_item, &ei_dccp_packet_type_reserved);
return tvb_reported_length(tvb);
}
if (advertised_dccp_header_len > DCCP_HDR_LEN_MAX) {
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is larger than the maximum (%u)",advertised_dccp_header_len, DCCP_HDR_LEN_MAX);
return tvb_reported_length(tvb);
}
if (advertised_dccp_header_len > offset) {
options_len = advertised_dccp_header_len - offset;
if (dccp_tree) {
dccp_item =proto_tree_add_none_format(dccp_tree, hf_dccp_options, tvb,offset,options_len, "Options: (%u byte%s)",options_len,plurality(options_len, "", "s"));
dccp_options_tree = proto_item_add_subtree(dccp_item,ett_dccp_options);
}
dissect_options(tvb, pinfo, dccp_options_tree, tree, dccph, offset,offset + options_len);
}
offset += options_len;
proto_item_set_end(dccp_item, tvb, offset);
tap_queue_packet(dccp_tap, pinfo, dccph);
if (!pinfo->flags.in_error_pkt || tvb_reported_length_remaining(tvb, offset) > 0) {
decode_dccp_ports(tvb, offset, pinfo, tree, dccph->sport, dccph->dport);
}
return tvb_reported_length(tvb);
}
static void
dccp_init(void)
{
dccp_stream_count = 0;
}
void
proto_register_dccp(void)
{
module_t *dccp_module;
static hf_register_info hf[] = {
{
&hf_dccp_srcport,{
"Source Port", "dccp.srcport",FT_UINT16, BASE_PT_DCCP, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_dstport,{
"Destination Port", "dccp.dstport",FT_UINT16, BASE_PT_DCCP, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_port,{
"Source or Destination Port", "dccp.port",FT_UINT16, BASE_PT_DCCP, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_stream,{
"Stream index", "dccp.stream",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_data_offset,{
"Data Offset", "dccp.data_offset",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_ccval,{
"CCVal", "dccp.ccval",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_cscov,{
"Checksum Coverage", "dccp.cscov",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_checksum_status,{
"Checksum Status", "dccp.checksum.status",FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,NULL, HFILL}},{
&hf_dccp_checksum,{
"Checksum", "dccp.checksum",FT_UINT16, BASE_HEX, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_res1,{
"Reserved", "dccp.res1",FT_UINT8, BASE_HEX, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_res2,{
"Reserved", "dccp.res2",FT_UINT8, BASE_HEX, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_type,{
"Type", "dccp.type",FT_UINT8, BASE_DEC, VALS(dccp_packet_type_vals), 0x0,NULL, HFILL}},{
&hf_dccp_x,{
"Extended Sequence Numbers", "dccp.x",FT_BOOLEAN, BASE_NONE, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_seq,{
"Sequence Number", "dccp.seq",FT_UINT64, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_seq_abs,{
"Sequence Number (raw)", "dccp.seq_raw",FT_UINT64, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_ack_res,{
"Reserved", "dccp.ack_res",FT_UINT16, BASE_HEX, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_ack,{
"Acknowledgement Number", "dccp.ack",FT_UINT64, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_ack_abs,{
"Acknowledgement Number (raw)", "dccp.ack_raw",FT_UINT64, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_service_code,{
"Service Code", "dccp.service_code",FT_UINT32, BASE_DEC, VALS(dccp_service_code_vals), 0x0,NULL, HFILL}},{
&hf_dccp_reset_code,{
"Reset Code", "dccp.reset_code",FT_UINT8, BASE_DEC, VALS(dccp_reset_code_vals), 0x0,NULL, HFILL}},{
&hf_dccp_data1,{
"Data 1", "dccp.data1",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_data2,{
"Data 2", "dccp.data2",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_data3,{
"Data 3", "dccp.data3",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_option_type,{
"Option Type", "dccp.option_type",FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dccp_options_rvals), 0x0,NULL, HFILL}},{
&hf_dccp_feature_number,{
"Feature Number", "dccp.feature_number",FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dccp_feature_numbers_rvals), 0x0,NULL, HFILL}},{
&hf_dccp_ndp_count,{
"NDP Count", "dccp.ndp_count",FT_UINT64, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_timestamp,{
"Timestamp", "dccp.timestamp",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_timestamp_echo,{
"Timestamp Echo", "dccp.timestamp_echo",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_elapsed_time,{
"Elapsed Time", "dccp.elapsed_time",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL}},{
&hf_dccp_data_checksum,{
"Data Checksum", "dccp.checksum_data",FT_UINT32, BASE_HEX, NULL, 0x0,NULL, HFILL}},{&hf_mpdccp_confirm,{"MP_CONFIRM", "dccp.mp_confirm",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_version,{"version", "dccp.mp_version",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_join,{"MP_JOIN", "dccp.mp_join",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_join_id,{"Address ID", "dccp.mp_joinid",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_join_token,{"Path Token", "dccp.mp_path_token",FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_join_nonce,{"Nonce", "dccp.mp_nonce",FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_fast_close,{"MP_FAST_CLOSE", "dccp.mp_fast_close",FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_key,{"MP_KEY", "dccp.mp_key",FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_key_type,{"Key Type", "dccp.mp_key_type",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_key_key,{"Key Data", "dccp.mp_key_hash",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_seq,{"Sequence Number", "dccp.mp_seq",FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_hmac,{"MP_HMAC", "dccp.mp_hmac",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_hmac_sha,{"HMAC-SHA256", "dccp.mp_hmac_sha",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_rtt,{"MP_RTT", "dccp.mp_rtt",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_rtt_type,{"RTT_Type", "dccp.mp_rtt_type",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_rtt_value,{"RTT", "dccp.mp_rtt_value",FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_rtt_age,{"Age", "dccp.mp_rtt_age",FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_addaddr,{"MP_ADDADDR", "dccp.mp_addaddr",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_addrid,{"Address ID", "dccp.mp_addrid",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_addr_dec,{"Address", "dccp.mp_ipv4addr",FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_addr_hex,{"Address", "dccp.mp_ipv6addr",FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_addrport,{"Port", "dccp.mp_addrport",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_removeaddr,{"MP_REMOVEADDR", "dccp.mp_removeaddr",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_prio,{"MP_PRIO", "dccp.mp_prio",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_prio_value,{"Priority", "dccp.mp_prioval",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_close,{"MP_CLOSE", "dccp.mp_close",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_close_key,{"Key Data", "dccp.mp_close_key",FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},{&hf_mpdccp_exp,{"MP_EXP", "dccp.mp_exp",FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},{&hf_dccp_option_data,{"Option data", "dccp.mp_option",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},{
&hf_dccp_options,{
"Options", "dccp.options",FT_NONE, BASE_NONE, NULL, 0x0,"DCCP Options fields", HFILL}},{ &hf_dccp_padding, { "Padding", "dccp.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_mandatory, { "Mandatory", "dccp.mandatory", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_slow_receiver, { "Slow Receiver", "dccp.slow_receiver", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_init_cookie, { "Init Cookie", "dccp.init_cookie", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_ack_vector_nonce_0, { "Ack Vector [Nonce 0]", "dccp.ack_vector.nonce_0", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_ack_vector_nonce_1, { "Ack Vector [Nonce 1]", "dccp.ack_vector.nonce_1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_data_dropped, { "Data Dropped", "dccp.data_dropped", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_ccid3_loss_event_rate, { "CCID3 Loss Event Rate", "dccp.ccid3_loss_event_rate", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_ccid3_loss_intervals, { "CCID3 Loss Intervals", "dccp.ccid3_loss_intervals", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_ccid3_receive_rate, { "CCID3 Receive Rate", "dccp.ccid3_receive_rate", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_bytes_sec, 0x0, NULL, HFILL }},{ &hf_dccp_option_reserved, { "Reserved", "dccp.option_reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_ccid_option_data, { "CCID option", "dccp.ccid_option_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},{ &hf_dccp_option_unknown, { "Unknown", "dccp.option_unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},};
static gint *ett[] = {
&ett_dccp,&ett_dccp_options,&ett_dccp_options_item,&ett_dccp_feature};
static ei_register_info ei[] = {
{ &ei_dccp_option_len_bad, { "dccp.option.len.bad", PI_PROTOCOL, PI_WARN, "Bad option length", EXPFILL }},{ &ei_dccp_advertised_header_length_bad, { "dccp.advertised_header_length.bad", PI_MALFORMED, PI_ERROR, "Advertised header length bad", EXPFILL }},{ &ei_dccp_packet_type_reserved, { "dccp.packet_type.reserved", PI_PROTOCOL, PI_WARN, "Reserved packet type: unable to dissect further", EXPFILL }},{ &ei_dccp_checksum, { "dccp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},};
expert_module_t* expert_dccp;
proto_dccp =proto_register_protocol("Datagram Congestion Control Protocol", "DCCP","dccp");
dccp_handle = register_dissector("dccp", dissect_dccp, proto_dccp);
proto_register_field_array(proto_dccp, hf, array_length(hf));
proto_register_subtree_array(ett, array_length(ett));
expert_dccp = expert_register_protocol(proto_dccp);
expert_register_field_array(expert_dccp, ei, array_length(ei));
dccp_subdissector_table =register_dissector_table("dccp.port", "DCCP port", proto_dccp, FT_UINT16,BASE_DEC);
heur_subdissector_list = register_heur_dissector_list("dccp", proto_dccp);
dccp_module = prefs_register_protocol(proto_dccp, NULL);
prefs_register_module_alias("dcp", dccp_module);
prefs_register_bool_preference(
dccp_module, "summary_in_tree","Show DCCP summary in protocol tree","Whether the DCCP summary line should be shown in the protocol tree",&dccp_summary_in_tree);
prefs_register_bool_preference(
dccp_module, "try_heuristic_first","Try heuristic sub-dissectors first","Try to decode a packet using an heuristic sub-dissector before ""using a sub-dissector ""registered to a specific port",&try_heuristic_first);
prefs_register_bool_preference(
dccp_module, "check_checksum","Check the validity of the DCCP checksum when possible","Whether to check the validity of the DCCP checksum",&dccp_check_checksum);
prefs_register_bool_preference(
dccp_module, "relative_sequence_numbers","Relative sequence numbers","Make the DCCP dissector use relative sequence numbers instead of absolute ones.",&dccp_relative_seq);
register_conversation_table(proto_dccp, FALSE, dccpip_conversation_packet, dccpip_endpoint_packet);
register_conversation_filter("dccp", "DCCP", dccp_filter_valid, dccp_build_filter, NULL);
register_follow_stream(proto_dccp, "dccp_follow", dccp_follow_conv_filter, dccp_follow_index_filter, dccp_follow_address_filter,dccp_port_to_display, follow_tvb_tap_listener, get_dccp_stream_count, NULL);
register_init_routine(dccp_init);
}
void
proto_reg_handoff_dccp(void)
{
dissector_add_uint("ip.proto", IP_PROTO_DCCP, dccp_handle);
dccp_tap    = register_tap("dccp");
dccp_follow_tap = register_tap("dccp_follow");
}
