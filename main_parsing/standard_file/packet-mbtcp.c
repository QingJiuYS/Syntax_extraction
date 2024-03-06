dissect_mbtcp_pdu_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto, range_t *ports)
{
proto_item    *mi;
proto_tree    *mbtcp_tree;
int           offset;
tvbuff_t      *next_tvb;
const char    *func_string = "";
const char    *pkt_type_str = "";
const char    *err_str = "";
guint16       transaction_id, protocol_id, len;
guint8        unit_id, function_code, exception_code, subfunction_code;
modbus_data_t modbus_data;
transaction_id = tvb_get_ntohs(tvb, 0);
protocol_id = tvb_get_ntohs(tvb, 2);
len = tvb_get_ntohs(tvb, 4);
unit_id = tvb_get_guint8(tvb, 6);
function_code = tvb_get_guint8(tvb, 7) & 0x7F;
offset = 0;
modbus_data.packet_type = classify_mbtcp_packet(pinfo, ports);
modbus_data.mbtcp_transid = transaction_id;
modbus_data.unit_id = unit_id;
switch ( modbus_data.packet_type )
{
case QUERY_PACKET :
pkt_type_str="Query";
break;
case RESPONSE_PACKET :
pkt_type_str="Response";
break;
case CANNOT_CLASSIFY :
err_str="Unable to classify as query or response.";
pkt_type_str="unknown";
break;
default :
break;
}
if (tvb_get_guint8(tvb, 7) & 0x80)
{
exception_code = tvb_get_guint8(tvb, offset + 8);
}
else
{
exception_code = 0;
}
if ((function_code == ENCAP_INTERFACE_TRANSP) && (exception_code == 0))
{
func_string = val_to_str_const(tvb_get_guint8(tvb, offset + 8), encap_interface_code_vals, "Encapsulated Interface Transport");
subfunction_code = 1;
}
else if ((function_code == DIAGNOSTICS) && (exception_code == 0))
{
func_string = val_to_str_const(tvb_get_ntohs(tvb, offset + 8), diagnostic_code_vals, "Diagnostics");
subfunction_code = 1;
}
else
{
func_string = val_to_str(function_code, function_code_vals, "Unknown function (%d)");
subfunction_code = 0;
}
if ( exception_code != 0 )
{
err_str="Exception returned ";
}
else
{
}
if (subfunction_code == 0)
{
if (strlen(err_str) > 0)
{
col_add_fstr(pinfo->cinfo, COL_INFO,"%8s: Trans: %5u; Unit: %3u, Func: %3u: %s. %s",pkt_type_str, transaction_id, unit_id,function_code, func_string, err_str);
}
else
{
col_add_fstr(pinfo->cinfo, COL_INFO,"%8s: Trans: %5u; Unit: %3u, Func: %3u: %s",pkt_type_str, transaction_id, unit_id,function_code, func_string);
}
}
else
{
if (strlen(err_str) > 0)
{
col_add_fstr(pinfo->cinfo, COL_INFO,"%8s: Trans: %5u; Unit: %3u, Func: %3u/%3u: %s. %s",pkt_type_str, transaction_id, unit_id,function_code, subfunction_code, func_string, err_str);
}
else
{
col_add_fstr(pinfo->cinfo, COL_INFO,"%8s: Trans: %5u; Unit: %3u, Func: %3u/%3u: %s",pkt_type_str, transaction_id, unit_id,function_code, subfunction_code, func_string);
}
}
mi = proto_tree_add_item(tree, proto, tvb, offset, len+6, ENC_NA);
mbtcp_tree = proto_item_add_subtree(mi, ett_mbtcp);
if (modbus_data.packet_type == CANNOT_CLASSIFY)
{
expert_add_info(pinfo, mi, &ei_mbtcp_cannot_classify);
}
else
{
}
proto_tree_add_uint(mbtcp_tree, hf_mbtcp_transid, tvb, offset, 2, transaction_id);
proto_tree_add_uint(mbtcp_tree, hf_mbtcp_protid, tvb, offset + 2, 2, protocol_id);
proto_tree_add_uint(mbtcp_tree, hf_mbtcp_len, tvb, offset + 4, 2, len);
proto_tree_add_uint(mbtcp_tree, hf_mbtcp_unitid, tvb, offset + 6, 1, unit_id);
next_tvb = tvb_new_subset_length( tvb, offset+7, len-1);
if( tvb_reported_length_remaining(tvb, offset) > 0 )
{
call_dissector_with_data(modbus_handle, next_tvb, pinfo, tree, &modbus_data);
dissect_modbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
proto_tree          *modbus_tree;
proto_item          *mi;
int                 offset = 0;
modbus_data_t       *modbus_data = (modbus_data_t*)data;
gint                payload_start, payload_len, len;
guint8              function_code, exception_code;
modbus_pkt_info_t   *pkt_info;
guint32             conv_key;
if (modbus_data == NULL)
{
return 0;
}
else
{
}
len = tvb_captured_length(tvb);
if (len == 0)
{
return 0;
}
else
{
}
mi = proto_tree_add_protocol_format(tree, proto_modbus, tvb, offset, len, "Modbus");
modbus_tree = proto_item_add_subtree(mi, ett_modbus_hdr);
function_code = tvb_get_guint8(tvb, offset) & 0x7F;
proto_tree_add_item(modbus_tree, hf_modbus_functioncode, tvb, offset, 1, ENC_BIG_ENDIAN);
conv_key = (guint32)modbus_data->mbtcp_transid | ((guint32)modbus_data->unit_id << 16);
if (!pinfo->fd->visited)
{
conversation_t       *conversation = NULL;
modbus_conversation  *modbus_conv_data = NULL;
conversation = find_or_create_conversation(pinfo);
modbus_conv_data = (modbus_conversation *)conversation_get_proto_data(conversation, proto_modbus);
pkt_info = wmem_new0(wmem_file_scope(), modbus_pkt_info_t);
if (modbus_conv_data == NULL)
{
modbus_conv_data = wmem_new(wmem_file_scope(), modbus_conversation);
modbus_conv_data->modbus_request_frame_data = wmem_list_new(wmem_file_scope());
modbus_conv_data->register_format = global_mbus_register_format;
conversation_add_proto_data(conversation, proto_modbus, (void *)modbus_conv_data);
}
else
{
}
pkt_info->register_format = modbus_conv_data->register_format;
if (modbus_data->packet_type == QUERY_PACKET)
{
modbus_request_info_t    *frame_ptr = wmem_new0(wmem_file_scope(), modbus_request_info_t);
gint captured_length = tvb_captured_length(tvb);
frame_ptr->fnum = pinfo->num;
frame_ptr->function_code = function_code;
frame_ptr->mbtcp_transid = modbus_data->mbtcp_transid;
frame_ptr->unit_id = modbus_data->unit_id;
if (captured_length >= 3)
{
pkt_info->reg_base = frame_ptr->base_address = tvb_get_ntohs(tvb, 1);
if (captured_length >= 5)
{
pkt_info->num_reg = frame_ptr->num_reg = tvb_get_ntohs(tvb, 3);
}
else
{
}
}
else
{
}
frame_ptr->req_time = pinfo->abs_ts;
wmem_list_prepend(modbus_conv_data->modbus_request_frame_data, frame_ptr);
}
else if (modbus_data->packet_type == RESPONSE_PACKET)
{
guint8                req_function_code;
guint16               req_transaction_id;
guint8                req_unit_id;
guint32               req_frame_num;
modbus_request_info_t *request_data;
wmem_list_frame_t *frame = wmem_list_head(modbus_conv_data->modbus_request_frame_data);
while (frame && !pkt_info->request_found)
{
request_data = (modbus_request_info_t *)wmem_list_frame_data(frame);
req_frame_num = request_data->fnum;
req_function_code = request_data->function_code;
req_transaction_id = request_data->mbtcp_transid;
req_unit_id = request_data->unit_id;
if ((pinfo->num > req_frame_num) && (req_function_code == function_code) &&(req_transaction_id == modbus_data->mbtcp_transid) && (req_unit_id == modbus_data->unit_id))
{
pkt_info->reg_base = request_data->base_address;
pkt_info->num_reg = request_data->num_reg;
pkt_info->request_found = TRUE;
pkt_info->req_frame_num = req_frame_num;
pkt_info->req_time = request_data->req_time;
}
else
{
}
frame = wmem_list_frame_next(frame);
}
}
else
{
}
p_add_proto_data(wmem_file_scope(), pinfo, proto_modbus, conv_key, pkt_info);
}
else
{
pkt_info = (modbus_pkt_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_modbus, conv_key);
}
if (tvb_get_guint8(tvb, offset) & 0x80 )
{
exception_code = tvb_get_guint8(tvb, offset+1);
}
else
{
exception_code = 0;
}
payload_start = offset + 1;
payload_len = len - 1;
if (exception_code != 0)
{
proto_item_set_text(mi, "Function %u:  %s.  Exception: %s",function_code,val_to_str_const(function_code, function_code_vals, "Unknown Function"),val_to_str(exception_code,exception_code_vals,"Unknown Exception Code (%u)"));
proto_tree_add_uint(modbus_tree, hf_modbus_exceptioncode, tvb, payload_start, 1,exception_code);
}
else
{
if (modbus_data->packet_type == QUERY_PACKET)
{
dissect_modbus_request(tvb, pinfo, modbus_tree, function_code, payload_start, payload_len, pkt_info);
dissect_modbus_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *modbus_tree, guint8 function_code, gint payload_start, gint payload_len, modbus_pkt_info_t *pkt_info)
{
proto_tree    *group_tree;
gint          byte_cnt, group_offset, ii;
guint8        mei_code;
guint16       reg_base=0, diagnostic_code;
guint32       group_byte_cnt, group_word_cnt;
if (!pkt_info)
{
return 0;
}
else
{
}
switch (function_code)
{
case READ_COILS:
case READ_DISCRETE_INPUTS:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, ENC_BIG_ENDIAN);
break;
case READ_HOLDING_REGS:
case READ_INPUT_REGS:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, ENC_BIG_ENDIAN);
break;
case WRITE_SINGLE_COIL:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start + 2, 1, pkt_info->register_format, reg_base, 0);
dissect_modbus_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 function_code,gint payload_start, gint payload_len, gint register_format, guint16 reg_base, guint16 num_reg)
{
gint reported_len, data_offset;
guint8   data8, ii;
gboolean data_bool;
gint16  data16s;
gint32  data32s;
guint16 data16, modflt_lo, modflt_hi, reg_num=reg_base;
guint32 data32, modflt_comb;
gfloat data_float, modfloat;
proto_tree    *bit_tree = NULL;
proto_item    *bitnum_ti = NULL;
proto_item    *register_item = NULL;
proto_tree    *register_tree = NULL;
tvbuff_t *next_tvb;
reported_len = tvb_reported_length_remaining(tvb, payload_start);
data_offset = 0;
if ( payload_start < 0 || ( payload_len + payload_start ) == 0 )
{
return;
}
else
{
}
if ( payload_len != reported_len )
{
proto_tree_add_item(tree, hf_modbus_data, tvb, payload_start, reported_len, ENC_NA);
return;
}
else
{
}
if ((function_code == READ_HOLDING_REGS) || (function_code == READ_INPUT_REGS) || (function_code == WRITE_MULT_REGS))
{
if ((payload_len % 4 != 0) && ( (register_format == MODBUS_PREF_REGISTER_FORMAT_UINT32) ||(register_format == MODBUS_PREF_REGISTER_FORMAT_IEEE_FLOAT) ||(register_format == MODBUS_PREF_REGISTER_FORMAT_MODICON_FLOAT) ) )
{
register_item = proto_tree_add_item(tree, hf_modbus_data, tvb, payload_start, payload_len, ENC_NA);
expert_add_info(pinfo, register_item, &ei_modbus_data_decode);
return;
}
else
{
}
}
else
{
}
next_tvb = tvb_new_subset_length_caplen(tvb, payload_start, payload_len, reported_len);
switch ( function_code )
{
case READ_COILS:
case READ_DISCRETE_INPUTS:
while (data_offset < payload_len)
{
data8 = tvb_get_guint8(next_tvb, data_offset);
for (ii = 0; ii < 8; ii++)
{
data_bool = (data8 & (1 << ii)) > 0;
bit_tree = proto_tree_add_subtree_format(tree, next_tvb, data_offset, 1,ett_bit, NULL, "Bit %u : %u", reg_num, data_bool);
bitnum_ti = proto_tree_add_uint(bit_tree, hf_modbus_bitnum, next_tvb, data_offset, 1, reg_num);
proto_item_set_generated(bitnum_ti);
proto_tree_add_boolean(bit_tree, hf_modbus_bitval, next_tvb, data_offset, 1, data_bool);
reg_num++;
if ((reg_num - reg_base) >= num_reg)
{
break;
}
else
{
}
}
data_offset++;
}
break;
case READ_HOLDING_REGS:
case READ_INPUT_REGS:
case WRITE_MULT_REGS:
while (data_offset < payload_len)
{
switch (register_format)
{
case MODBUS_PREF_REGISTER_FORMAT_UINT16:
data16 = tvb_get_ntohs(next_tvb, data_offset);
register_tree = proto_tree_add_subtree_format( tree, next_tvb, data_offset, 2,ett_register, NULL, "Register %u (UINT16): %u", reg_num, data16);
proto_tree_add_uint(register_tree, hf_modbus_regnum16, next_tvb, data_offset, 2, reg_num);
proto_tree_add_uint(register_tree, hf_modbus_regval_uint16, next_tvb, data_offset, 2, data16);
data_offset += 2;
reg_num += 1;
break;
case MODBUS_PREF_REGISTER_FORMAT_INT16:
data16s = tvb_get_ntohs(next_tvb, data_offset);
register_tree = proto_tree_add_subtree_format( tree, next_tvb, data_offset, 2,ett_register, NULL, "Register %u (INT16): %d", reg_num, data16s);
proto_tree_add_uint(register_tree, hf_modbus_regnum16, next_tvb, data_offset, 2, reg_num);
proto_tree_add_int(register_tree, hf_modbus_regval_int16, next_tvb, data_offset, 2, data16s);
data_offset += 2;
reg_num += 1;
break;
case MODBUS_PREF_REGISTER_FORMAT_UINT32:
data32 = tvb_get_ntohl(next_tvb, data_offset);
register_tree = proto_tree_add_subtree_format( tree, next_tvb, data_offset, 4,ett_register, NULL, "Register %u (UINT32): %u", reg_num, data32);
proto_tree_add_uint(register_tree, hf_modbus_regnum32, next_tvb, data_offset, 4, reg_num);
proto_tree_add_uint(register_tree, hf_modbus_regval_uint32, next_tvb, data_offset, 4, data32);
data_offset += 4;
reg_num += 2;
break;
case MODBUS_PREF_REGISTER_FORMAT_INT32:
data32s = tvb_get_ntohl(next_tvb, data_offset);
register_tree = proto_tree_add_subtree_format( tree, next_tvb, data_offset, 4,ett_register, NULL, "Register %u (INT32): %d", reg_num, data32s);
proto_tree_add_uint(register_tree, hf_modbus_regnum32, next_tvb, data_offset, 4, reg_num);
proto_tree_add_int(register_tree, hf_modbus_regval_int32, next_tvb, data_offset, 4, data32s);
data_offset += 4;
reg_num += 2;
break;
case MODBUS_PREF_REGISTER_FORMAT_IEEE_FLOAT:
data_float = tvb_get_ntohieee_float(next_tvb, data_offset);
register_tree = proto_tree_add_subtree_format( tree, next_tvb, data_offset, 4,ett_register, NULL, "Register %u (IEEE Float): %f", reg_num, data_float);
proto_tree_add_uint(register_tree, hf_modbus_regnum32, next_tvb, data_offset, 4, reg_num);
proto_tree_add_float(register_tree, hf_modbus_regval_ieee_float, next_tvb, data_offset, 4, data_float);
data_offset += 4;
reg_num += 2;
break;
case MODBUS_PREF_REGISTER_FORMAT_MODICON_FLOAT:
modflt_lo = tvb_get_ntohs(next_tvb, data_offset);
modflt_hi = tvb_get_ntohs(next_tvb, data_offset+2);
modflt_comb = (guint32)(modflt_hi<<16) | modflt_lo;
memcpy(&modfloat, &modflt_comb, 4);
register_tree = proto_tree_add_subtree_format( tree, next_tvb, data_offset, 4,ett_register, NULL, "Register %u (Modicon Float): %f", reg_num, modfloat);
proto_tree_add_uint(register_tree, hf_modbus_regnum32, next_tvb, data_offset, 4, reg_num);
proto_tree_add_float(register_tree, hf_modbus_regval_modicon_float, next_tvb, data_offset, 4, modfloat);
data_offset += 4;
reg_num += 2;
break;
default:
data_offset = payload_len;
break;
}
}
break;
default:
if ( ! dissector_try_string(modbus_data_dissector_table, "data", next_tvb, pinfo, tree, NULL) )
{
proto_tree_add_item(tree, hf_modbus_data, tvb, payload_start, payload_len, ENC_NA);
}
else
{
}
break;
}
}
proto_tree_add_item(modbus_tree, hf_modbus_padding, tvb, payload_start + 3, 1, ENC_NA);
break;
case WRITE_SINGLE_REG:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start + 2, 2, pkt_info->register_format, reg_base, 0);
break;
case READ_EXCEPT_STAT:
break;
case DIAGNOSTICS:
diagnostic_code = tvb_get_ntohs(tvb, payload_start);
proto_tree_add_uint(modbus_tree, hf_modbus_diag_sf, tvb, payload_start, 2, diagnostic_code);
switch(diagnostic_code)
{
case RETURN_QUERY_DATA:
if (payload_len > 2)
{
proto_tree_add_item(modbus_tree, hf_modbus_diag_return_query_data_request, tvb, payload_start+2, payload_len-2, ENC_NA);
}
else
{
}
break;
case RESTART_COMMUNICATION_OPTION:
proto_tree_add_item(modbus_tree, hf_modbus_diag_restart_communication_option, tvb, payload_start+2, 2, ENC_BIG_ENDIAN);
break;
case CHANGE_ASCII_INPUT_DELIMITER:
proto_tree_add_item(modbus_tree, hf_modbus_diag_ascii_input_delimiter, tvb, payload_start+2, 1, ENC_BIG_ENDIAN);
break;
case RETURN_DIAGNOSTIC_REGISTER:
case FORCE_LISTEN_ONLY_MODE:
case CLEAR_COUNTERS_AND_DIAG_REG:
case RETURN_BUS_MESSAGE_COUNT:
case RETURN_BUS_COMM_ERROR_COUNT:
case RETURN_BUS_EXCEPTION_ERROR_COUNT:
case RETURN_SLAVE_MESSAGE_COUNT:
case RETURN_SLAVE_NO_RESPONSE_COUNT:
case RETURN_SLAVE_NAK_COUNT:
case RETURN_SLAVE_BUSY_COUNT:
case RETURN_BUS_CHAR_OVERRUN_COUNT:
case CLEAR_OVERRUN_COUNTER_AND_FLAG:
default:
if (payload_len > 2)
{
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start+2, payload_len-2, pkt_info->register_format, reg_base, 0);
}
else
{
}
break;
}
break;
case WRITE_MULT_COILS:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, ENC_BIG_ENDIAN);
byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 4);
proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 4, 1, byte_cnt);
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start + 5, byte_cnt, pkt_info->register_format, reg_base, 0);
break;
case WRITE_MULT_REGS:
reg_base = tvb_get_ntohs(tvb, payload_start);
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, ENC_BIG_ENDIAN);
byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 4);
proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 4, 1, byte_cnt);
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start + 5, byte_cnt, pkt_info->register_format, reg_base, 0);
break;
case READ_FILE_RECORD:
byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1,byte_cnt);
group_offset = payload_start + 1;
for (ii = 0; ii < byte_cnt / 7; ii++)
{
group_tree = proto_tree_add_subtree_format( modbus_tree, tvb, group_offset, 7,ett_group_hdr, NULL, "Group %u", ii);
proto_tree_add_item(group_tree, hf_modbus_reftype, tvb, group_offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(group_tree, hf_modbus_lreference, tvb, group_offset + 1, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(group_tree, hf_modbus_wordcnt, tvb, group_offset + 5, 2, ENC_BIG_ENDIAN);
group_offset += 7;
}
break;
case WRITE_FILE_RECORD:
byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1, byte_cnt);
group_offset = payload_start + 1;
ii = 0;
while (byte_cnt > 0)
{
group_word_cnt = tvb_get_ntohs(tvb, group_offset + 5);
group_byte_cnt = (2 * group_word_cnt) + 7;
group_tree = proto_tree_add_subtree_format( modbus_tree, tvb, group_offset,group_byte_cnt, ett_group_hdr, NULL, "Group %u", ii);
proto_tree_add_item(group_tree, hf_modbus_reftype, tvb, group_offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(group_tree, hf_modbus_lreference, tvb, group_offset + 1, 4, ENC_BIG_ENDIAN);
proto_tree_add_uint(group_tree, hf_modbus_wordcnt, tvb, group_offset + 5, 2, group_word_cnt);
dissect_modbus_data(tvb, pinfo, group_tree, function_code, group_offset + 7, group_byte_cnt - 7, pkt_info->register_format, reg_base, 0);
group_offset += group_byte_cnt;
byte_cnt -= group_byte_cnt;
ii++;
}
break;
case MASK_WRITE_REG:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_andmask, tvb, payload_start + 2, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_ormask, tvb, payload_start + 4, 2, ENC_BIG_ENDIAN);
break;
case READ_WRITE_REG:
proto_tree_add_item(modbus_tree, hf_modbus_readref, tvb, payload_start, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_readwordcnt, tvb, payload_start + 2, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_writeref, tvb, payload_start + 4, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_writewordcnt, tvb, payload_start + 6, 2, ENC_BIG_ENDIAN);
byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 8);
proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 8, 1, byte_cnt);
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start + 9, byte_cnt, pkt_info->register_format, reg_base, 0);
break;
case READ_FIFO_QUEUE:
proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, ENC_BIG_ENDIAN);
break;
case ENCAP_INTERFACE_TRANSP:
proto_tree_add_item(modbus_tree, hf_modbus_mei, tvb, payload_start, 1, ENC_BIG_ENDIAN);
mei_code = tvb_get_guint8(tvb, payload_start);
switch (mei_code)
{
case READ_DEVICE_ID:
proto_tree_add_item(modbus_tree, hf_modbus_read_device_id, tvb, payload_start+1, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(modbus_tree, hf_modbus_object_id, tvb, payload_start+2, 1, ENC_BIG_ENDIAN);
break;
case CANOPEN_REQ_RESP:
default:
if (payload_len > 1)
{
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start, payload_len-1, pkt_info->register_format, reg_base, 0);
}
else
{
}
break;
}
break;
case REPORT_SLAVE_ID:
default:
if (payload_len > 0)
{
dissect_modbus_data(tvb, pinfo, modbus_tree, function_code, payload_start, payload_len, pkt_info->register_format, reg_base, 0);
}
else
{
}
break;
}
return tvb_captured_length(tvb);
}
}
else if (modbus_data->packet_type == RESPONSE_PACKET)
{
dissect_modbus_response(tvb, pinfo, modbus_tree, function_code, payload_start, payload_len, pkt_info);
}
else
{
}
}
return tvb_captured_length(tvb);
}
}
else
{
}
return tvb_captured_length(tvb);
}
