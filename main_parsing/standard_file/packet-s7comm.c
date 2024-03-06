dissect_s7comm(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,void *data _U_)
{
proto_item *s7comm_item = NULL;
proto_item *s7comm_sub_item = NULL;
proto_tree *s7comm_tree = NULL;
proto_tree *s7comm_header_tree = NULL;
guint32 offset = 0;
guint8 rosctr = 0;
guint8 hlength = 10;
guint16 plength = 0;
guint16 dlength = 0;
guint16 errorcode = 0;
if(tvb_captured_length(tvb) < S7COMM_MIN_TELEGRAM_LENGTH)
{
return FALSE;
}
else
{
}
if (tvb_get_guint8(tvb, 0) != S7COMM_PROT_ID)
{
return FALSE;
}
else
{
}
if (tvb_get_guint8(tvb, 1) < 0x01 || tvb_get_guint8(tvb, 1) > 0x07)
{
return FALSE;
}
else
{
}
col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_S7COMM);
col_clear(pinfo->cinfo, COL_INFO);
col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");
rosctr = tvb_get_guint8(tvb, 1);
if (rosctr == 2 || rosctr == 3)
{
hlength = 12;
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, "ROSCTR:[%-8s]", val_to_str(rosctr, rosctr_names, "Unknown: 0x%02x"));
s7comm_item = proto_tree_add_item(tree, proto_s7comm, tvb, 0, -1, ENC_NA);
s7comm_tree = proto_item_add_subtree(s7comm_item, ett_s7comm);
s7comm_sub_item = proto_tree_add_item(s7comm_tree, hf_s7comm_header,tvb, offset, hlength, ENC_NA);
s7comm_header_tree = proto_item_add_subtree(s7comm_sub_item, ett_s7comm_header);
proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_protid, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_rosctr, tvb, offset, 1, rosctr);
proto_item_append_text(s7comm_header_tree, ": (%s)", val_to_str(rosctr, rosctr_names, "Unknown ROSCTR: 0x%02x"));
offset += 1;
proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_redid, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_pduref, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
plength = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_parlg, tvb, offset, 2, plength);
offset += 2;
dlength = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_datlg, tvb, offset, 2, dlength);
offset += 2;
if (hlength == 12)
{
errorcode = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcls, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcod, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (errorcode > 0)
{
s7comm_item = proto_tree_add_item(s7comm_header_tree, hf_s7comm_param_errcod, tvb, offset-2, 2, ENC_BIG_ENDIAN);
proto_item_set_generated (s7comm_item);
}
else
{
}
}
else
{
}
switch (rosctr)
{
case S7COMM_ROSCTR_JOB:
case S7COMM_ROSCTR_ACK_DATA:
s7comm_decode_req_resp(tvb, pinfo, s7comm_tree, plength, dlength, offset, rosctr);
s7comm_decode_req_resp(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,guint16 plength,guint16 dlength,guint32 offset,guint8 rosctr)
{
proto_item *item = NULL;
proto_tree *param_tree = NULL;
proto_tree *data_tree = NULL;
guint8 function = 0;
guint8 item_count = 0;
guint8 i;
guint32 offset_old;
guint32 len;
if (plength > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_param, tvb, offset, plength, ENC_NA);
param_tree = proto_item_add_subtree(item, ett_s7comm_param);
function = tvb_get_guint8(tvb, offset);
col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s]", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
proto_tree_add_uint(param_tree, hf_s7comm_param_service, tvb, offset, 1, function);
proto_item_append_text(param_tree, ": (%s)", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
offset += 1;
if (rosctr == S7COMM_ROSCTR_JOB)
{
switch (function)
{
case S7COMM_SERV_READVAR:
case S7COMM_SERV_WRITEVAR:
item_count = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
offset += 1;
for (i = 0; i < item_count; i++)
{
offset_old = offset;
offset = s7comm_decode_param_item(tvb, offset, param_tree, i);
s7comm_decode_param_item(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint8 item_no)
{
proto_item *item = NULL;
proto_tree *item_tree = NULL;
guint8 var_spec_type = 0;
guint8 var_spec_length = 0;
guint8 var_spec_syntax_id = 0;
var_spec_type = tvb_get_guint8(tvb, offset);
var_spec_length = tvb_get_guint8(tvb, offset + 1);
var_spec_syntax_id = tvb_get_guint8(tvb, offset + 2);
item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, var_spec_length + 2, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
proto_item_append_text(item, " [%d]:", item_no + 1);
proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_S7ANY)
{
offset = s7comm_syntaxid_s7any(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length >= 7 && var_spec_syntax_id == S7COMM_SYNTAXID_DBREAD)
{
offset = s7comm_syntaxid_dbread(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length >= 14 && var_spec_syntax_id == S7COMM_SYNTAXID_1200SYM)
{
offset = s7comm_syntaxid_1200sym(tvb, offset, item_tree, var_spec_length);
}
else if (var_spec_type == 0x12 && var_spec_length == 8&& ((var_spec_syntax_id == S7COMM_SYNTAXID_NCK)|| (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_METRIC)|| (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_INCH)))
{
offset = s7comm_syntaxid_nck(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_DRIVEESANY)
{
offset = s7comm_syntaxid_driveesany(tvb, offset, item_tree);
}
else
{
offset += var_spec_length - 1;
proto_item_append_text(item_tree, " Unknown variable specification");
}
return offset;
}
len = offset - offset_old;
if ((len % 2) && (i < (item_count-1)))
{
offset += 1;
}
else
{
}
}
if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0))
{
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
}
else
{
}
break;
case S7COMM_SERV_SETUPCOMM:
offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, offset);
s7comm_decode_pdu_setup_communication(tvbuff_t *tvb,proto_tree *tree,guint32 offset)
{
proto_tree_add_item(tree, hf_s7comm_param_setup_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(tree, hf_s7comm_param_maxamq_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tree, hf_s7comm_param_maxamq_called, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tree, hf_s7comm_param_neg_pdu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
return offset;
}
break;
case S7COMM_FUNCREQUESTDOWNLOAD:
case S7COMM_FUNCDOWNLOADBLOCK:
case S7COMM_FUNCDOWNLOADENDED:
case S7COMM_FUNCSTARTUPLOAD:
case S7COMM_FUNCUPLOAD:
case S7COMM_FUNCENDUPLOAD:
offset = s7comm_decode_plc_controls_updownload(tvb, pinfo, tree, param_tree, plength, dlength, offset -1, rosctr);
s7comm_decode_plc_controls_updownload(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,proto_tree *param_tree,guint16 plength,guint16 dlength,guint32 offset,guint8 rosctr)
{
guint8 len;
guint8 function;
guint32 errorcode;
const gchar *errorcode_text;
proto_item *item = NULL;
proto_tree *data_tree = NULL;
function = tvb_get_guint8(tvb, offset);
offset += 1;
errorcode = 0;
switch (function)
{
case S7COMM_FUNCREQUESTDOWNLOAD:
if (rosctr == S7COMM_ROSCTR_JOB)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
offset += 4;
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
if (plength > 18)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_part2_len, tvb, offset, 1, len);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_part2_unknown, tvb, offset, 1, ENC_ASCII);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_loadmem_len, tvb, offset, 6, ENC_ASCII);
offset += 6;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_mc7code_len, tvb, offset, 6, ENC_ASCII);
offset += 6;
}
else
{
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
break;
case S7COMM_FUNCSTARTUPLOAD:
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
offset += 4;
if (rosctr == S7COMM_ROSCTR_JOB)
{
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength > 8)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_upl_lenstring_len, tvb, offset, 1, len);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_upl_lenstring, tvb, offset, len, ENC_ASCII);
offset += len;
}
else
{
}
}
else
{
}
break;
case S7COMM_FUNCUPLOAD:
case S7COMM_FUNCDOWNLOADBLOCK:
if (rosctr == S7COMM_ROSCTR_JOB)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
if (function == S7COMM_FUNCUPLOAD)
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
offset += 4;
}
else
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
offset += 4;
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (dlength > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
proto_tree_add_item(data_tree, hf_s7comm_data_length, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength - 4, ENC_NA);
offset += dlength - 4;
}
else
{
}
}
else
{
}
break;
case S7COMM_FUNCENDUPLOAD:
case S7COMM_FUNCDOWNLOADENDED:
if (rosctr == S7COMM_ROSCTR_JOB)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
item = proto_tree_add_item_ret_uint(param_tree, hf_s7comm_data_blockcontrol_errorcode, tvb, offset, 2, ENC_BIG_ENDIAN, &errorcode);
if ((errorcode_text = try_val_to_str_ext(errorcode, &param_errcode_names_ext)))
{
proto_item_append_text(item, " (%s)", errorcode_text);
}
else
{
}
offset += 2;
if (function == S7COMM_FUNCENDUPLOAD)
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
offset += 4;
}
else
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
offset += 4;
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
break;
}
if (errorcode > 0)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
}
else
{
}
return offset;
}
break;
case S7COMM_FUNCPISERVICE:
offset = s7comm_decode_pi_service(tvb, pinfo, param_tree, plength, offset -1);
s7comm_decode_pi_service(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,guint16 plength,guint32 offset)
{
guint16 len, paramlen;
guint32 startoffset;
guint32 paramoffset;
guint8 count;
guint8 i;
const guint8 *servicename;
const guint8 *str;
const guint8 *str1;
guint16 blocktype;
guint hf[13];
int pi_servicename_idx;
const gchar *pi_servicename_descr;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *param_tree = NULL;
proto_tree *file_tree = NULL;
gint32 num = -1;
gboolean num_valid;
startoffset = offset;
offset += 1;
proto_tree_add_item(tree, hf_s7comm_piservice_unknown1, tvb, offset, 7, ENC_NA);
offset += 7;
if (offset - startoffset >= plength)
{
return offset;
}
else
{
}
paramlen = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_piservice_parameterblock_len, tvb, offset, 2, paramlen);
offset += 2;
paramoffset = offset;
item = proto_tree_add_item(tree, hf_s7comm_piservice_parameterblock, tvb, offset, paramlen, ENC_NA);
param_tree = proto_item_add_subtree(item, ett_s7comm_piservice_parameterblock);
offset += paramlen;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_piservice_string_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item_ret_string(tree, hf_s7comm_piservice_servicename, tvb, offset, len, ENC_ASCII|ENC_NA, pinfo->pool, &servicename);
offset += len;
pi_servicename_descr = try_str_to_str_idx((const gchar*)servicename, pi_service_names, &pi_servicename_idx);
if (pi_servicename_idx < 0)
{
pi_servicename_idx = S7COMM_PI_UNKNOWN;
pi_servicename_descr = "Unknown PI Service";
}
else
{
}
proto_item_append_text(item, " [%s]", pi_servicename_descr);
switch (pi_servicename_idx)
{
case S7COMM_PI_INSE:
case S7COMM_PI_INS2:
case S7COMM_PI_DELE:
count = tvb_get_guint8(tvb, paramoffset);
proto_tree_add_uint(param_tree, hf_s7comm_data_plccontrol_block_cnt, tvb, paramoffset, 1, count);
paramoffset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_pi_inse_unknown, tvb, paramoffset, 1, ENC_BIG_ENDIAN);
paramoffset += 1;
col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s(", servicename);
for (i = 0; i < count; i++)
{
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, paramoffset, 8, ENC_ASCII);
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
blocktype = tvb_get_ntohs(tvb, paramoffset);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, paramoffset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
paramoffset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, paramoffset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
paramoffset += 5;
num_valid = ws_strtoi32((const char*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s ",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_str(pinfo->cinfo, COL_INFO,val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN");
}
if (i+1 < count)
{
col_append_str(pinfo->cinfo, COL_INFO, ", ");
}
else
{
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, paramoffset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, paramoffset), blocktype_attribute2_names, "Unknown filesys"));
paramoffset += 1;
}
col_append_str(pinfo->cinfo, COL_INFO, ")");
break;
case S7COMM_PIP_PROGRAM:
case S7COMM_PI_MODU:
case S7COMM_PI_GARB:
if (paramlen == 0)
{
proto_item_append_text(param_tree, ": ()");
proto_item_append_text(tree, " -> %s()", servicename);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s()", servicename);
}
else
{
proto_tree_add_item_ret_string(param_tree, hf_s7comm_data_plccontrol_argument, tvb, paramoffset, paramlen, ENC_ASCII|ENC_NA, pinfo->pool, &str1);
proto_item_append_text(param_tree, ": (\"%s\")", str1);
proto_item_append_text(tree, " -> %s(\"%s\")", servicename, str1);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s(\"%s\")", servicename, str1);
}
break;
case S7COMM_PI_N_LOGIN_:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_password;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
s7comm_decode_pistart_parameters(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,proto_tree *param_tree,const guint8 *servicename,guint8 nfields,guint hf[],guint32 offset)
{
guint8 i;
guint8 len;
wmem_strbuf_t *args_buf;
args_buf = wmem_strbuf_create(pinfo->pool);
for (i = 0; i < nfields; i++)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_piservice_string_len, tvb, offset, 1, len);
offset += 1;
proto_tree_add_item(param_tree, hf[i], tvb, offset, len, ENC_ASCII|ENC_NA);
wmem_strbuf_append(args_buf, "\"");
wmem_strbuf_append(args_buf, tvb_format_text(pinfo->pool, tvb, offset, len));
if (i < nfields-1)
{
wmem_strbuf_append(args_buf, "\", ");
}
else
{
wmem_strbuf_append(args_buf, "\"");
}
offset += len + (len % 2 == 0);
}
proto_item_append_text(param_tree, ": (%s)", wmem_strbuf_get_str(args_buf));
proto_item_append_text(tree, " -> %s(%s)", servicename, wmem_strbuf_get_str(args_buf));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s(%s)", servicename, wmem_strbuf_get_str(args_buf));
return offset;
}
break;
case S7COMM_PI_N_LOGOUT:
case S7COMM_PI_N_CANCEL:
case S7COMM_PI_N_DASAVE:
case S7COMM_PI_N_DIGIOF:
case S7COMM_PI_N_DIGION:
case S7COMM_PI_N_DZERO_:
case S7COMM_PI_N_ENDEXT:
case S7COMM_PI_N_OST_OF:
case S7COMM_PI_N_OST_ON:
case S7COMM_PI_N_SCALE_:
case S7COMM_PI_N_SETUFR:
case S7COMM_PI_N_STRTLK:
case S7COMM_PI_N_STRTUL:
case S7COMM_PI_N_TMRASS:
hf[0] = hf_s7comm_pi_n_x_addressident;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 1, hf, paramoffset);
break;
case S7COMM_PI_N_F_DELE:
case S7COMM_PI_N_EXTERN:
case S7COMM_PI_N_EXTMOD:
case S7COMM_PI_N_F_DELR:
case S7COMM_PI_N_F_XFER:
case S7COMM_PI_N_LOCKE_:
case S7COMM_PI_N_SELECT:
case S7COMM_PI_N_SRTEXT:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_filename;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_F_CLOS:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_editwindowname;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_F_OPEN:
case S7COMM_PI_N_F_OPER:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_filename;
hf[2] = hf_s7comm_pi_n_x_editwindowname;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_F_SEEK:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_editwindowname;
hf[2] = hf_s7comm_pi_n_x_seekpointer;
hf[3] = hf_s7comm_pi_n_x_windowsize;
hf[4] = hf_s7comm_pi_n_x_comparestring;
hf[5] = hf_s7comm_pi_n_x_skipcount;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
break;
case S7COMM_PI_N_ASUP__:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_interruptnr;
hf[2] = hf_s7comm_pi_n_x_priority;
hf[3] = hf_s7comm_pi_n_x_liftfast;
hf[4] = hf_s7comm_pi_n_x_blsync;
hf[5] = hf_s7comm_pi_n_x_filename;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
break;
case S7COMM_PI_N_CHEKDM:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_magnr;
hf[2] = hf_s7comm_pi_n_x_dnr;
hf[3] = hf_s7comm_pi_n_x_spindlenumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_CHKDNO:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_wznr;
hf[2] = hf_s7comm_pi_n_x_wznr;
hf[3] = hf_s7comm_pi_n_x_dnr;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_CONFIG:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_class;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_CRCEDN:
case S7COMM_PI_N_DELECE:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_tnr;
hf[2] = hf_s7comm_pi_n_x_dnr;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_CREACE:
case S7COMM_PI_N_CREATO:
case S7COMM_PI_N_DELETO:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolnumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_CRTOCE:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolnumber;
hf[2] = hf_s7comm_pi_n_x_cenumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_DELVAR:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_datablocknumber;
hf[2] = hf_s7comm_pi_n_x_firstcolumnnumber;
hf[3] = hf_s7comm_pi_n_x_lastcolumnnumber;
hf[4] = hf_s7comm_pi_n_x_firstrownumber;
hf[5] = hf_s7comm_pi_n_x_lastrownumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
break;
case S7COMM_PI_N_F_COPY:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_direction;
hf[2] = hf_s7comm_pi_n_x_sourcefilename;
hf[3] = hf_s7comm_pi_n_x_destinationfilename;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_F_DMDA:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_channelnumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_F_PROR:
case S7COMM_PI_N_F_PROT:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_filename;
hf[2] = hf_s7comm_pi_n_x_protection;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_F_RENA:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_oldfilename;
hf[2] = hf_s7comm_pi_n_x_newfilename;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_FINDBL:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_findmode;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_IBN_SS:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_switch;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_MMCSEM:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_functionnumber;
hf[2] = hf_s7comm_pi_n_x_semaphorevalue;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_NCKMOD:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_onoff;
hf[2] = hf_s7comm_pi_n_x_mode;
hf[3] = hf_s7comm_pi_n_x_factor;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_NEWPWD:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_password;
hf[2] = hf_s7comm_pi_n_x_passwordlevel;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_SEL_BL:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_linenumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 2, hf, paramoffset);
break;
case S7COMM_PI_N_SETTST:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_magnr;
hf[2] = hf_s7comm_pi_n_x_weargroup;
hf[3] = hf_s7comm_pi_n_x_toolstatus;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_TMAWCO:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_magnr;
hf[2] = hf_s7comm_pi_n_x_weargroup;
hf[3] = hf_s7comm_pi_n_x_wearsearchstrat;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_TMCRTC:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolid;
hf[2] = hf_s7comm_pi_n_x_toolnumber;
hf[3] = hf_s7comm_pi_n_x_duplonumber;
hf[4] = hf_s7comm_pi_n_x_edgenumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 5, hf, paramoffset);
break;
case S7COMM_PI_N_TMCRTO:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolid;
hf[2] = hf_s7comm_pi_n_x_toolnumber;
hf[3] = hf_s7comm_pi_n_x_duplonumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_TMFDPL:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolnumber;
hf[2] = hf_s7comm_pi_n_x_placenr;
hf[3] = hf_s7comm_pi_n_x_magnr;
hf[4] = hf_s7comm_pi_n_x_placerefnr;
hf[5] = hf_s7comm_pi_n_x_magrefnr;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
break;
case S7COMM_PI_N_TMFPBP:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_magnrfrom;
hf[2] = hf_s7comm_pi_n_x_placenrfrom;
hf[3] = hf_s7comm_pi_n_x_magnrto;
hf[4] = hf_s7comm_pi_n_x_placenrto;
hf[5] = hf_s7comm_pi_n_x_magrefnr;
hf[6] = hf_s7comm_pi_n_x_placerefnr;
hf[7] = hf_s7comm_pi_n_x_halfplacesleft;
hf[8] = hf_s7comm_pi_n_x_halfplacesright;
hf[9] = hf_s7comm_pi_n_x_halfplacesup;
hf[10] = hf_s7comm_pi_n_x_halfplacesdown;
hf[11] = hf_s7comm_pi_n_x_placetype;
hf[12] = hf_s7comm_pi_n_x_searchdirection;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 13, hf, paramoffset);
break;
case S7COMM_PI_N_TMGETT:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolname;
hf[2] = hf_s7comm_pi_n_x_duplonumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_TMMVTL:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolnumber;
hf[2] = hf_s7comm_pi_n_x_placenrsource;
hf[3] = hf_s7comm_pi_n_x_magnrsource;
hf[4] = hf_s7comm_pi_n_x_placenrdestination;
hf[5] = hf_s7comm_pi_n_x_magnrdestination;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 6, hf, paramoffset);
break;
case S7COMM_PI_N_TMPCIT:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_spindlenumber;
hf[2] = hf_s7comm_pi_n_x_incrementnumber;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 3, hf, paramoffset);
break;
case S7COMM_PI_N_TMPOSM:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolnumber;
hf[2] = hf_s7comm_pi_n_x_toolid;
hf[3] = hf_s7comm_pi_n_x_duplonumber;
hf[4] = hf_s7comm_pi_n_x_placenrsource;
hf[5] = hf_s7comm_pi_n_x_magnrsource;
hf[6] = hf_s7comm_pi_n_x_placenrdestination;
hf[7] = hf_s7comm_pi_n_x_magnrdestination;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 8, hf, paramoffset);
break;
case S7COMM_PI_N_TRESMO:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_toolnumber;
hf[2] = hf_s7comm_pi_n_x_dnr;
hf[3] = hf_s7comm_pi_n_x_monitoringmode;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 4, hf, paramoffset);
break;
case S7COMM_PI_N_TSEARC:
hf[0] = hf_s7comm_pi_n_x_addressident;
hf[1] = hf_s7comm_pi_n_x_magnrfrom;
hf[2] = hf_s7comm_pi_n_x_placenrfrom;
hf[3] = hf_s7comm_pi_n_x_magnrto;
hf[4] = hf_s7comm_pi_n_x_placenrto;
hf[5] = hf_s7comm_pi_n_x_magrefnr;
hf[6] = hf_s7comm_pi_n_x_placerefnr;
hf[7] = hf_s7comm_pi_n_x_searchdirection;
hf[8] = hf_s7comm_pi_n_x_kindofsearch;
s7comm_decode_pistart_parameters(tvb, pinfo, tree, param_tree, servicename, 9, hf, paramoffset);
break;
default:
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]", servicename);
}
return offset;
}
break;
case S7COMM_FUNC_PLC_STOP:
offset = s7comm_decode_plc_controls_param_hex29(tvb, param_tree, offset -1);
s7comm_decode_plc_controls_param_hex29(tvbuff_t *tvb,proto_tree *tree,guint32 offset)
{
guint8 len;
offset += 1;
proto_tree_add_item(tree, hf_s7comm_piservice_unknown1, tvb, offset, 5, ENC_NA);
offset += 5;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_data_plccontrol_part2_len, tvb, offset, 1, len);
offset += 1;
proto_tree_add_item(tree, hf_s7comm_piservice_servicename, tvb, offset, len, ENC_ASCII);
offset += len;
return offset;
}
break;
default:
if (plength > 1)
{
proto_tree_add_item(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1, ENC_NA);
}
else
{
}
offset += plength - 1;
if (dlength > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
break;
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
switch (function)
{
case S7COMM_SERV_READVAR:
case S7COMM_SERV_WRITEVAR:
item_count = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
offset += 1;
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
if ((function == S7COMM_SERV_READVAR) && (dlength > 0))
{
offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
}
else if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0))
{
offset = s7comm_decode_response_write_data(tvb, data_tree, item_count, offset);
}
else
{
}
break;
case S7COMM_SERV_SETUPCOMM:
offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, offset);
s7comm_decode_pdu_setup_communication(tvbuff_t *tvb,proto_tree *tree,guint32 offset)
{
proto_tree_add_item(tree, hf_s7comm_param_setup_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(tree, hf_s7comm_param_maxamq_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tree, hf_s7comm_param_maxamq_called, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tree, hf_s7comm_param_neg_pdu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
return offset;
}
break;
case S7COMM_FUNCREQUESTDOWNLOAD:
case S7COMM_FUNCDOWNLOADBLOCK:
case S7COMM_FUNCDOWNLOADENDED:
case S7COMM_FUNCSTARTUPLOAD:
case S7COMM_FUNCUPLOAD:
case S7COMM_FUNCENDUPLOAD:
offset = s7comm_decode_plc_controls_updownload(tvb, pinfo, tree, param_tree, plength, dlength, offset -1, rosctr);
s7comm_decode_plc_controls_updownload(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,proto_tree *param_tree,guint16 plength,guint16 dlength,guint32 offset,guint8 rosctr)
{
guint8 len;
guint8 function;
guint32 errorcode;
const gchar *errorcode_text;
proto_item *item = NULL;
proto_tree *data_tree = NULL;
function = tvb_get_guint8(tvb, offset);
offset += 1;
errorcode = 0;
switch (function)
{
case S7COMM_FUNCREQUESTDOWNLOAD:
if (rosctr == S7COMM_ROSCTR_JOB)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
offset += 4;
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
if (plength > 18)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_part2_len, tvb, offset, 1, len);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_part2_unknown, tvb, offset, 1, ENC_ASCII);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_loadmem_len, tvb, offset, 6, ENC_ASCII);
offset += 6;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_mc7code_len, tvb, offset, 6, ENC_ASCII);
offset += 6;
}
else
{
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
break;
case S7COMM_FUNCSTARTUPLOAD:
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
offset += 4;
if (rosctr == S7COMM_ROSCTR_JOB)
{
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength > 8)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_upl_lenstring_len, tvb, offset, 1, len);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_upl_lenstring, tvb, offset, len, ENC_ASCII);
offset += len;
}
else
{
}
}
else
{
}
break;
case S7COMM_FUNCUPLOAD:
case S7COMM_FUNCDOWNLOADBLOCK:
if (rosctr == S7COMM_ROSCTR_JOB)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
if (function == S7COMM_FUNCUPLOAD)
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
offset += 4;
}
else
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
offset += 4;
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (dlength > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
proto_tree_add_item(data_tree, hf_s7comm_data_length, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength - 4, ENC_NA);
offset += dlength - 4;
}
else
{
}
}
else
{
}
break;
case S7COMM_FUNCENDUPLOAD:
case S7COMM_FUNCDOWNLOADENDED:
if (rosctr == S7COMM_ROSCTR_JOB)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
item = proto_tree_add_item_ret_uint(param_tree, hf_s7comm_data_blockcontrol_errorcode, tvb, offset, 2, ENC_BIG_ENDIAN, &errorcode);
if ((errorcode_text = try_val_to_str_ext(errorcode, &param_errcode_names_ext)))
{
proto_item_append_text(item, " (%s)", errorcode_text);
}
else
{
}
offset += 2;
if (function == S7COMM_FUNCENDUPLOAD)
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_uploadid, tvb, offset, 4, ENC_NA);
offset += 4;
}
else
{
proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
offset += 4;
offset = s7comm_decode_plc_controls_filename(tvb, pinfo, param_tree, offset);
s7comm_decode_plc_controls_filename(tvbuff_t *tvb,packet_info *pinfo,proto_tree *param_tree,guint32 offset)
{
guint8 len;
const guint8 *str;
guint16 blocktype;
gboolean is_plcfilename;
proto_item *item = NULL;
proto_item *itemadd = NULL;
proto_tree *file_tree = NULL;
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(param_tree, hf_s7comm_data_blockcontrol_filename_len, tvb, offset, 1, len);
offset += 1;
item = proto_tree_add_item(param_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, len, ENC_ASCII);
is_plcfilename = FALSE;
if (len == 9)
{
blocktype = tvb_get_ntohs(tvb, offset + 1);
if ((tvb_get_guint8(tvb, offset) == '_') && (blocktype >= S7COMM_BLOCKTYPE_OB) && (blocktype <= S7COMM_BLOCKTYPE_SFB))
{
gint32 num = 1;
gboolean num_valid;
is_plcfilename = TRUE;
file_tree = proto_item_add_subtree(item, ett_s7comm_plcfilename);
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute1_names, "Unknown identifier: %c"));
offset += 1;
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(file_tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &str);
offset += 5;
num_valid = ws_strtoi32((const gchar*)str, NULL, &num);
proto_item_append_text(file_tree, " [%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s",val_to_str(blocktype, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(file_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, file_tree, &ei_s7comm_data_blockcontrol_block_num_invalid);
proto_item_append_text(file_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
itemadd = proto_tree_add_item(file_tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
}
else
{
}
if (is_plcfilename == FALSE)
{
str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str);
offset += len;
}
else
{
}
return offset;
}
}
}
else if (rosctr == S7COMM_ROSCTR_ACK_DATA)
{
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
break;
}
if (errorcode > 0)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
}
else
{
}
return offset;
}
break;
case S7COMM_FUNCPISERVICE:
if (plength >= 2)
{
proto_tree_add_bitmask(param_tree, tvb, offset, hf_s7comm_data_blockcontrol_functionstatus,ett_s7comm_data_blockcontrol_status, s7comm_data_blockcontrol_status_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
break;
default:
if (plength > 1)
{
proto_tree_add_item(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1, ENC_NA);
}
else
{
}
offset += plength - 1;
if (dlength > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
break;
}
}
else
{
}
}
else
{
}
return offset;
}
break;
case S7COMM_ROSCTR_USERDATA:
s7comm_decode_ud(tvb, pinfo, s7comm_tree, plength, dlength, offset, tree);
s7comm_decode_ud(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,guint16 plength,guint16 dlength,guint32 offset,proto_tree *root_tree)
{
proto_item *item = NULL;
proto_tree *param_tree = NULL;
guint32 errorcode;
guint32 offset_temp;
guint8 function;
guint8 type;
guint8 funcgroup;
guint8 subfunc;
guint8 mode;
guint8 data_unit_ref = 0;
guint8 last_data_unit = 0;
guint8 seq_num;
guint32 r_id;
guint8 varspec_syntax_id = 0;
item = proto_tree_add_item(tree, hf_s7comm_param, tvb, offset, plength, ENC_NA);
param_tree = proto_item_add_subtree(item, ett_s7comm_param);
offset_temp = offset;
function = tvb_get_guint8(tvb, offset_temp);
proto_tree_add_uint(param_tree, hf_s7comm_param_service, tvb, offset_temp, 1, function);
offset_temp += 1;
proto_tree_add_item(param_tree, hf_s7comm_param_itemcount, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
if (function == S7COMM_SERV_MODETRANS)
{
proto_item_append_text(param_tree, ": ->(Mode transition indication)");
col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[Mode transition indication]");
proto_tree_add_item(param_tree, hf_s7comm_modetrans_param_unknown1, tvb, offset_temp, 4, ENC_BIG_ENDIAN);
offset_temp += 4;
mode = tvb_get_guint8(tvb, offset_temp);
proto_tree_add_uint(param_tree, hf_s7comm_modetrans_param_mode, tvb, offset_temp, 1, mode);
offset_temp += 1;
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(mode, modetrans_param_mode_names, "Unknown mode: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(mode, modetrans_param_mode_names, "Unknown mode: 0x%02x"));
proto_tree_add_item(param_tree, hf_s7comm_modetrans_param_unknown2, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
return offset_temp;
}
else
{
}
proto_tree_add_item(param_tree, hf_s7comm_item_varspec, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
proto_tree_add_item(param_tree, hf_s7comm_item_varspec_length, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
varspec_syntax_id = tvb_get_guint8(tvb, offset_temp);
proto_tree_add_item(param_tree, hf_s7comm_item_syntax_id, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
if (varspec_syntax_id == S7COMM_SYNTAXID_PBC_ID)
{
proto_item_append_text(param_tree, ": (Indication) ->(USEND)");
col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[Indication] -> [USEND]");
proto_tree_add_item(param_tree, hf_s7comm_pbc_unknown, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
proto_tree_add_item_ret_uint(param_tree, hf_s7comm_pbc_usend_r_id, tvb, offset_temp, 4, ENC_BIG_ENDIAN, &r_id);
col_append_fstr(pinfo->cinfo, COL_INFO, " R_ID=0x%X", r_id);
offset += plength;
offset = s7comm_decode_ud_usend(tvb, tree, dlength, offset);
s7comm_decode_ud_usend(tvbuff_t *tvb,proto_tree *tree,guint32 dlength,guint32 offset)
{
proto_item *item = NULL;
proto_tree *data_tree = NULL;
proto_tree *item_tree = NULL;
guint8 tsize;
guint16 len;
guint16 len2;
guint8 ret_val;
guint8 item_count;
guint8 i;
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
ret_val = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(data_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_pbc_usend_unknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
item_count = tvb_get_guint8(tvb, offset + 1);
proto_tree_add_uint(data_tree, hf_s7comm_param_itemcount, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
tsize = tvb_get_guint8(tvb, offset + 1);
len = tvb_get_ntohs(tvb, offset + 2);
if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBIT ||tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE ||tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT) {if (len % 8)
{
len /= 8;
len = len + 1;
}
else
{
len /= 8;
}
}
if ((len % 2) && (i < (item_count-1)))
{
len2 = len + 1;
}
else
{
len2 = len;
}
item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, len + 4, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]", i+1);
proto_tree_add_item(item_tree, hf_s7comm_pbc_usend_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_uint(item_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
proto_tree_add_uint(item_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);
offset += 4;
proto_tree_add_item(item_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
offset += len;
if (len != len2)
{
proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
return offset;
}
return offset;
}
else
{
}
type = (tvb_get_guint8(tvb, offset_temp) & 0xc0) >> 6;
funcgroup = (tvb_get_guint8(tvb, offset_temp) & 0x3f);
proto_tree_add_item(param_tree, hf_s7comm_userdata_param_type, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(param_tree, hf_s7comm_userdata_param_funcgroup, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s] -> [%s]",val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"),val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function group: 0x%02x"));
proto_item_append_text(param_tree, ": (%s)", val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function group: 0x%02x"));
subfunc = tvb_get_guint8(tvb, offset_temp);
switch (funcgroup)
{
case S7COMM_UD_FUNCGROUP_TIS:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_prog, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_tis_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_tis_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_CYCLIC:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_cyclic, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_BLOCK:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_block, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_CPU:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_cpu, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_cpu_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cpu_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_SEC:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_sec, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_TIME:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_time, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_DRR:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_drr, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_drr_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_drr_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
case S7COMM_UD_FUNCGROUP_NCPRG:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_ncprg, tvb, offset_temp, 1, subfunc);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",val_to_str(subfunc, userdata_ncprg_subfunc_names, "Unknown subfunc: 0x%02x"));
proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_ncprg_subfunc_names, "Unknown subfunc: 0x%02x"));
break;
default:
proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc, tvb, offset_temp, 1, subfunc);
break;
}
offset_temp += 1;
seq_num = tvb_get_guint8(tvb, offset_temp);
proto_tree_add_item(param_tree, hf_s7comm_userdata_param_seq_num, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
if (varspec_syntax_id == S7COMM_SYNTAXID_EXT)
{
data_unit_ref = tvb_get_guint8(tvb, offset_temp);
proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunitref, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
last_data_unit = tvb_get_guint8(tvb, offset_temp);
proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunit, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
offset_temp += 1;
proto_tree_add_item_ret_uint(param_tree, hf_s7comm_param_errcod, tvb, offset_temp, 2, ENC_BIG_ENDIAN, &errorcode);
if (errorcode > 0)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
}
else
{
}
}
else
{
}
offset += plength;
offset = s7comm_decode_ud_data(tvb, pinfo, tree, dlength, type, funcgroup, subfunc, seq_num, data_unit_ref, last_data_unit, offset, root_tree);
s7comm_decode_ud_data(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,guint16 dlength,guint8 type,guint8 funcgroup,guint8 subfunc,guint8 seq_num,guint8 data_unit_ref,guint8 last_data_unit,guint32 offset,proto_tree *root_tree)
{
proto_item *item = NULL;
proto_tree *data_tree = NULL;
guint8 tsize;
guint16 len;
guint8 ret_val;
guint32 length_rem = 0;
gboolean save_fragmented;
guint32 frag_id = 0;
gboolean more_frags = FALSE;
gboolean is_fragmented = FALSE;
tvbuff_t* new_tvb = NULL;
tvbuff_t* next_tvb = NULL;
fragment_head *fd_head;
gchar str_fragadd[32];
if (dlength >= 4)
{
item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
data_tree = proto_item_add_subtree(item, ett_s7comm_data);
ret_val = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(data_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
offset += 1;
tsize = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(data_tree, hf_s7comm_data_transport_size, tvb, offset, 1, tsize);
offset += 1;
len = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(data_tree, hf_s7comm_data_length, tvb, offset, 2, len);
offset += 2;
if (len >= 2)
{
more_frags = (last_data_unit == S7COMM_UD_LASTDATAUNIT_NO);
switch (funcgroup)
{
case S7COMM_UD_FUNCGROUP_NCPRG:
offset = s7comm_decode_ud_ncprg_pre_reass(tvb, data_tree, type, subfunc, &len, offset);
s7comm_decode_ud_ncprg_pre_reass(tvbuff_t *tvb,proto_tree *data_tree,guint8 type,guint8 subfunc,guint16 *dlength,guint32 offset)
{
if ((type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_IND) &&(subfunc == S7COMM_NCPRG_FUNCDOWNLOADBLOCK ||subfunc == S7COMM_NCPRG_FUNCUPLOAD ||subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD))
{
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
*dlength -= 2;
}
else
{
}
return offset;
}
is_fragmented = TRUE;
frag_id = seq_num;
break;
case S7COMM_UD_FUNCGROUP_PBC_BSEND:
offset = s7comm_decode_ud_pbc_bsend_pre_reass(tvb, pinfo, data_tree, type, &len, &frag_id, offset);
s7comm_decode_ud_pbc_bsend_pre_reass(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint8 type,guint16 *dlength,guint32 *r_id,guint32 offset)
{
if ((type == S7COMM_UD_TYPE_REQ || type == S7COMM_UD_TYPE_RES) && (*dlength >= 8))
{
proto_tree_add_item(data_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_pbc_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_pbc_bsend_r_id, tvb, offset, 4, ENC_BIG_ENDIAN);
*r_id = tvb_get_ntohl(tvb, offset);
col_append_fstr(pinfo->cinfo, COL_INFO, " R_ID=0x%X", *r_id);
offset += 4;
*dlength -= 8;
}
else
{
}
return offset;
}
is_fragmented = data_unit_ref > 0 || seq_num > 0;
break;
case S7COMM_UD_FUNCGROUP_CPU:
if (subfunc == S7COMM_UD_SUBF_CPU_AR_SEND_IND)
{
offset = s7comm_decode_ud_cpu_ar_send_pre_reass(tvb, pinfo, data_tree, &len, offset);
s7comm_decode_ud_cpu_ar_send_pre_reass(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint16 *dlength,guint32 offset)
{
guint32 ar_id;
if (*dlength >= 8)
{
proto_tree_add_item(data_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_pbc_arsend_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item_ret_uint(data_tree, hf_s7comm_pbc_arsend_ar_id, tvb, offset, 4, ENC_BIG_ENDIAN, &ar_id);
col_append_fstr(pinfo->cinfo, COL_INFO, " AR_ID=0x%X", ar_id);
offset += 4;
*dlength -= 8;
}
else
{
}
return offset;
}
}
else
{
}
is_fragmented = (data_unit_ref > 0);
frag_id = data_unit_ref;
break;
default:
is_fragmented = (data_unit_ref > 0);
frag_id = data_unit_ref;
break;
}
save_fragmented = pinfo->fragmented;
if (is_fragmented)
{
pinfo->fragmented = TRUE;
fd_head = fragment_add_seq_next(&s7comm_reassembly_table,tvb, offset, pinfo,frag_id,NULL,len,more_frags);
snprintf(str_fragadd, sizeof(str_fragadd), " id=%d", frag_id);
new_tvb = process_reassembled_data(tvb, offset, pinfo,"Reassembled S7COMM", fd_head, &s7comm_frag_items,NULL, tree);
if (new_tvb)
{
if (fd_head && fd_head->next)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " (S7COMM reassembled%s)", str_fragadd);
proto_item_append_text(data_tree, " (S7COMM reassembled%s)", str_fragadd);
}
else
{
}
next_tvb = new_tvb;
offset = 0;
}
else
{
next_tvb = tvb_new_subset_length(tvb, offset, -1);
col_append_fstr(pinfo->cinfo, COL_INFO, " (S7COMM fragment%s)", str_fragadd);
proto_item_append_text(data_tree, " (S7COMM fragment%s)", str_fragadd);
offset = 0;
}
}
else
{
next_tvb = tvb;
}
pinfo->fragmented = save_fragmented;
length_rem = tvb_reported_length_remaining(next_tvb, offset);
if (last_data_unit == S7COMM_UD_LASTDATAUNIT_YES && length_rem > 0)
{
switch (funcgroup)
{
case S7COMM_UD_FUNCGROUP_TIS:
offset = s7comm_decode_ud_tis_subfunc(next_tvb, data_tree, type, subfunc, offset);
s7comm_decode_ud_tis_subfunc(tvbuff_t *tvb,proto_tree *data_tree,guint8 type,guint8 subfunc,guint32 offset)
{
guint16 tp_size = 0;
guint16 td_size = 0;
tp_size = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(data_tree, hf_s7comm_tis_parametersize, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
td_size = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(data_tree, hf_s7comm_tis_datasize, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
offset = s7comm_decode_ud_tis_param(tvb, data_tree, type, tp_size, offset);
s7comm_decode_ud_tis_param(tvbuff_t *tvb,proto_tree *tree,guint8 type,guint16 tp_size,guint32 offset)
{
guint32 start_offset;
guint32 callenv_setup = 0;
proto_item *item = NULL;
proto_tree *tp_tree = NULL;
start_offset = offset;
if (tp_size > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_tis_parameter, tvb, offset, tp_size, ENC_NA);
tp_tree = proto_item_add_subtree(item, ett_s7comm_prog_parameter);
if (type == S7COMM_UD_TYPE_REQ)
{
if (tp_size >= 4)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_param1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param2, tvb, offset, 2, ENC_NA);
offset += 2;
}
else
{
}
if (tp_size >= 20)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_param3, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_answersize, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param5, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param6, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param7, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param8, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param9, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_trgevent, tvb, offset, 2, ENC_NA);
offset += 2;
}
else
{
}
if (tp_size >= 26)
{
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_type, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
if (tp_size >= 28)
{
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_saz, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
if (tp_size >= 36)
{
proto_tree_add_item_ret_uint(tp_tree, hf_s7comm_tis_p_callenv, tvb, offset, 2, ENC_BIG_ENDIAN, &callenv_setup);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (callenv_setup == 2)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
}
else
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (tp_size >= 38)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_address, tvb, offset, 2, ENC_BIG_ENDIAN);
}
else
{
}
}
}
else
{
}
}
else
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param2, tvb, offset, 2, ENC_NA);
}
}
else
{
}
return start_offset + tp_size;
}
offset = s7comm_decode_ud_tis_data(tvb, data_tree, type, subfunc, td_size, offset);
s7comm_decode_ud_tis_data(tvbuff_t *tvb,proto_tree *tree,guint8 type,guint8 subfunc,guint16 td_size,guint32 offset)
{
proto_item *item = NULL;
proto_tree *td_tree = NULL;
if (td_size > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_tis_data, tvb, offset, td_size, ENC_NA);
td_tree = proto_item_add_subtree(item, ett_s7comm_prog_data);
switch (subfunc)
{
case S7COMM_UD_SUBF_TIS_OUTISTACK:
offset = s7comm_decode_ud_tis_istack(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_istack(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
guint8 ob_number = 0;
switch (type)
{
case S7COMM_UD_TYPE_REQ:
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
break;
case S7COMM_UD_TYPE_RES:
case S7COMM_UD_TYPE_IND:
proto_tree_add_item(td_tree, hf_s7comm_tis_continued_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_continued_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_continued_address, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu1, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu2, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu3, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu4, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar1, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar2, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_stw, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 4, ENC_NA);
offset += 4;
ob_number = tvb_get_guint8(tvb, offset + 3);
switch (ob_number)
{
case 1:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_scan_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_prev_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_min_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_max_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case 10:
case 11:
case 12:
case 13:
case 14:
case 15:
case 16:
case 17:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_period_exe, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case 20:
case 21:
case 22:
case 23:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_scan_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_sign, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_dtime, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
break;
case 30:
case 31:
case 32:
case 33:
case 34:
case 35:
case 36:
case 37:
case 38:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_phase_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_exec_freq, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case 40:
case 41:
case 42:
case 43:
case 44:
case 45:
case 46:
case 47:
case 48:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_point_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
break;
case 55:
case 56:
case 57:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_inf_len, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_alarm_type, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_alarm_slot, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_alarm_spec, tvb, offset, 1, ENC_NA);
offset += 1;
break;
case 80:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_error_info, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_num, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_num, tvb, offset, 1, ENC_NA);
offset += 1;
break;
case 81:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_rack_cpu, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case 82:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_8x_fault_flags, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_type_b, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_8x_fault_flags, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_8x_fault_flags, tvb, offset, 1, ENC_NA);
offset += 1;
break;
case 83:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_io_flag, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_rack_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_type_w, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case 84:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4_dw, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
break;
case 85:
case 87:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ev_num, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_err_ob_num, tvb, offset, 1, ENC_NA);
offset += 1;
break;
case 86:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_id, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mdl_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_racks_flt, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
break;
case 90:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_inf, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_4_dw, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
break;
case 100:
case 101:
case 102:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_strtup, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_2, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_stop, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_strt_info, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
break;
case 121:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_sw_flt, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_blk_type, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_reserved_1, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_reg, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_blk_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_prg_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case 122:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_sw_flt, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_blk_type, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mem_area, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_mem_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_flt_blk_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_ob_prg_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
default:
proto_tree_add_item(td_tree, hf_s7comm_ob_ev_class, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_priority, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_ob_number, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_istack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
break;
}
offset = s7comm_add_timestamp_to_tree(tvb, td_tree, offset, FALSE, FALSE);
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_OUTBSTACK:
offset = s7comm_decode_ud_tis_bstack(tvb, td_tree, td_size, type, offset);
s7comm_decode_ud_tis_bstack(tvbuff_t *tvb,proto_tree *td_tree,guint16 td_size,guint8 type,guint32 offset)
{
guint16 i;
guint16 blocktype;
guint16 blocknumber;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
int rem;
guint32 replen;
replen = tvb_reported_length_remaining(tvb, offset);
if (replen < td_size)
{
td_size = replen;
}
else
{
}
switch (type)
{
case S7COMM_UD_TYPE_REQ:
proto_tree_add_item(td_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
break;
case S7COMM_UD_TYPE_RES:
case S7COMM_UD_TYPE_IND:
rem = td_size;
i = 1;
while (rem > 16)
{
item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 16, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
blocktype = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
blocknumber = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(item_tree, hf_s7comm_tis_register_db1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_tis_register_db2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(item_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 4, ENC_NA);
offset += 4;
proto_item_append_text(item, " [%d] BSTACK entry for: %s %d", i++,val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"), blocknumber);
rem -= 16;
if (blocktype == S7COMM_SUBBLKTYPE_OB)
{
proto_tree_add_item(item_tree, hf_s7comm_tis_interrupted_prioclass, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
rem -= 4;
if (rem >= 8)
{
offset = s7comm_add_timestamp_to_tree(tvb, item_tree, offset, FALSE, FALSE);
rem -= 8;
}
else
{
proto_tree_add_item(item_tree, hf_s7comm_tis_bstack_reserved, tvb, offset, rem, ENC_NA);
offset += rem;
break;
}
}
else
{
}
}
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_OUTLSTACK:
offset = s7comm_decode_ud_tis_lstack(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_lstack(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
guint16 len;
if (type == S7COMM_UD_TYPE_REQ)
{
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_prioclass, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_bstack_nest_depth, tvb, offset, 1, ENC_NA);
offset += 1;
}
else
{
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_NA);
offset += 2;
len = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_size, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_data, tvb, offset, len, ENC_NA);
offset += len;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_prioclass, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_reserved, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_lstack_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
offset = s7comm_add_timestamp_to_tree(tvb, td_tree, offset, FALSE, FALSE);
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_BREAKPOINT:
offset = s7comm_decode_ud_tis_breakpoint(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_breakpoint(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
switch (type)
{
case S7COMM_UD_TYPE_REQ:
proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
break;
case S7COMM_UD_TYPE_RES:
case S7COMM_UD_TYPE_IND:
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_interrupted_address, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_address, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_breakpoint_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_stw, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu1, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_accu2, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar1, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_ar2, tvb, offset, 4, ENC_NA);
offset += 4;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_EXITHOLD:
offset = s7comm_decode_ud_tis_exithold(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_exithold(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
switch (type)
{
case S7COMM_UD_TYPE_REQ:
proto_tree_add_item(td_tree, hf_s7comm_tis_exithold_until, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_exithold_res1, tvb, offset, 1, ENC_NA);
offset += 1;
break;
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_BLOCKSTAT:
case S7COMM_UD_SUBF_TIS_BLOCKSTAT2:
offset = s7comm_decode_ud_tis_blockstat(tvb, td_tree, td_size, type, subfunc, offset);
s7comm_decode_ud_tis_blockstat(tvbuff_t *tvb,proto_tree *td_tree,guint16 td_size,guint8 type,guint8 subfunc,guint32 offset)
{
proto_item *item = NULL;
proto_tree *item_tree = NULL;
guint16 line_nr;
guint16 line_cnt;
guint16 item_size = 4;
guint8 registerflags;
gchar str_flags[80];
if (type == S7COMM_UD_TYPE_REQ)
{
if (subfunc == S7COMM_UD_SUBF_TIS_BLOCKSTAT2)
{
proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_flagsunknown, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
line_cnt = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_tis_blockstat_number_of_lines, tvb, offset, 1, line_cnt);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, 1, ENC_NA);
offset += 1;
}
else
{
proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, 1, ENC_NA);
offset += 1;
line_cnt = (td_size - 2) / 2;
}
proto_tree_add_bitmask(td_tree, tvb, offset, hf_s7comm_diagdata_registerflag,ett_s7comm_diagdata_registerflag, s7comm_diagdata_registerflag_fields, ENC_BIG_ENDIAN);
offset += 1;
if (subfunc == S7COMM_UD_SUBF_TIS_BLOCKSTAT2)
{
item_size = 4;
}
else
{
item_size = 2;
}
for (line_nr = 0; line_nr < line_cnt; line_nr++)
{
item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, item_size, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
if (subfunc == S7COMM_UD_SUBF_TIS_BLOCKSTAT2)
{
proto_tree_add_item(item_tree, hf_s7comm_tis_blockstat_line_address, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
proto_tree_add_item(item_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, 1, ENC_NA);
offset += 1;
registerflags = tvb_get_guint8(tvb, offset);
make_registerflag_string(str_flags, registerflags, sizeof(str_flags));
proto_item_append_text(item, " [%d]: (%s)", line_nr+1, str_flags);
proto_tree_add_bitmask(item_tree, tvb, offset, hf_s7comm_diagdata_registerflag,ett_s7comm_diagdata_registerflag, s7comm_diagdata_registerflag_fields, ENC_BIG_ENDIAN);
offset += 1;
}
}
else if (type == S7COMM_UD_TYPE_IND)
{
proto_tree_add_item(td_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_data, tvb, offset, td_size - 2, ENC_NA);
offset += (td_size - 2);
}
else
{
proto_tree_add_item(td_tree, hf_s7comm_tis_blockstat_reserved, tvb, offset, td_size, ENC_NA);
offset += td_size;
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_VARSTAT:
offset = s7comm_decode_ud_tis_varstat(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_varstat(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
guint16 item_count;
guint16 i;
switch (type)
{
case S7COMM_UD_TYPE_REQ:
item_count = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
offset = s7comm_decode_ud_tis_item_address(tvb, offset, td_tree, i, " Address to read");
s7comm_decode_ud_tis_item_address(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint16 item_no,gchar *add_text)
{
guint32 bytepos = 0;
guint16 len = 0;
guint16 bitpos = 0;
guint16 db = 0;
guint8 area = 0;
proto_item *item = NULL;
item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, 6, ENC_NA);
sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
proto_item_append_text(item, " [%d]%s:", item_no + 1, add_text);
area = tvb_get_guint8(tvb, offset);
proto_tree_add_item(sub_tree, hf_s7comm_varstat_req_memory_area, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (area & 0x0f)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_repetition_factor, tvb, offset, 1, len);
offset += 1;
}
else
{
bitpos = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_bitpos, tvb, offset, 1, bitpos);
offset += 1;
}
db = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_db_number, tvb, offset, 2, db);
offset += 2;
bytepos = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_startaddress, tvb, offset, 2, bytepos);
offset += 2;
switch (area)
{
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MX:
proto_item_append_text(sub_tree, " (M%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MB:
proto_item_append_text(sub_tree, " (M%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MW:
proto_item_append_text(sub_tree, " (M%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MD:
proto_item_append_text(sub_tree, " (M%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EX:
proto_item_append_text(sub_tree, " (I%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EB:
proto_item_append_text(sub_tree, " (I%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EW:
proto_item_append_text(sub_tree, " (I%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_ED:
proto_item_append_text(sub_tree, " (I%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AX:
proto_item_append_text(sub_tree, " (Q%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AB:
proto_item_append_text(sub_tree, " (Q%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AW:
proto_item_append_text(sub_tree, " (Q%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AD:
proto_item_append_text(sub_tree, " (Q%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PEB:
proto_item_append_text(sub_tree, " (PI%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PEW:
proto_item_append_text(sub_tree, " (PI%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PED:
proto_item_append_text(sub_tree, " (PI%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBX:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.%d)", db, bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBB:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 BYTE %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBW:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 WORD %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBD:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 DWORD %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_T:
if (len >1)
{
proto_item_append_text(sub_tree, " (T %d..%d)", bytepos, bytepos + len - 1);
}
else
{
proto_item_append_text(sub_tree, " (T %d)", bytepos);
}
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_C:
if (len >1)
{
proto_item_append_text(sub_tree, " (C %d..%d)", bytepos, bytepos + len - 1);
}
else
{
proto_item_append_text(sub_tree, " (C %d)", bytepos);
}
break;
}
return offset;
}
}
break;
case S7COMM_UD_TYPE_IND:
item_count = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
offset = s7comm_decode_ud_tis_item_value(tvb, offset, td_tree, i, " Read data");
s7comm_decode_ud_tis_item_value(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint16 item_no,gchar *add_text)
{
guint16 len = 0, len2 = 0;
guint8 ret_val = 0;
guint8 tsize = 0;
guint8 head_len = 4;
proto_item *item = NULL;
ret_val = tvb_get_guint8(tvb, offset);
if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||ret_val == S7COMM_ITEM_RETVAL_DATA_ERR)
{
tsize = tvb_get_guint8(tvb, offset + 1);
len = tvb_get_ntohs(tvb, offset + 2);
if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT)
{
len /= 8;
}
else
{
}
if (len % 2)
{
len2 = len + 1;
}
else
{
len2 = len;
}
}
else
{
}
item = proto_tree_add_item(sub_tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
sub_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]%s: (%s)", item_no + 1, add_text, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
proto_tree_add_uint(sub_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
proto_tree_add_uint(sub_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
proto_tree_add_uint(sub_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);
offset += head_len;
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED)
{
proto_tree_add_item(sub_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
offset += len;
if (len != len2)
{
proto_tree_add_item(sub_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
return offset;
}
}
break;
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_DISABLEJOB:
case S7COMM_UD_SUBF_TIS_ENABLEJOB:
case S7COMM_UD_SUBF_TIS_DELETEJOB:
case S7COMM_UD_SUBF_TIS_READJOBLIST:
case S7COMM_UD_SUBF_TIS_READJOB:
case S7COMM_UD_SUBF_TIS_REPLACEJOB:
offset = s7comm_decode_ud_tis_jobs(tvb, td_tree, td_size, type, subfunc, offset);
s7comm_decode_ud_tis_jobs(tvbuff_t *tvb,proto_tree *td_tree,guint16 td_size,guint8 type,guint8 subfunc,guint32 offset)
{
guint16 i;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
guint16 job_tp_size;
guint16 job_td_size;
proto_tree *job_td_tree = NULL;
guint8 job_subfunc;
if (type == S7COMM_UD_TYPE_REQ)
{
switch (subfunc)
{
case S7COMM_UD_SUBF_TIS_DELETEJOB:
proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
case S7COMM_UD_SUBF_TIS_ENABLEJOB:
case S7COMM_UD_SUBF_TIS_DISABLEJOB:
case S7COMM_UD_SUBF_TIS_READJOB:
proto_tree_add_item(td_tree, hf_s7comm_tis_job_function, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_job_seqnr, tvb, offset, 1, ENC_NA);
offset += 1;
break;
case S7COMM_UD_SUBF_TIS_READJOBLIST:
proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
break;
case S7COMM_UD_SUBF_TIS_REPLACEJOB:
proto_tree_add_item(td_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
job_subfunc = tvb_get_guint8(tvb, offset);
proto_tree_add_item(td_tree, hf_s7comm_tis_job_function, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(td_tree, hf_s7comm_tis_job_seqnr, tvb, offset, 1, ENC_NA);
offset += 1;
job_tp_size = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(td_tree, hf_s7comm_tis_parametersize, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
job_td_size = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(td_tree, hf_s7comm_tis_datasize, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (job_tp_size > 0)
{
offset = s7comm_decode_ud_tis_param(tvb, td_tree, S7COMM_UD_TYPE_REQ, job_tp_size, offset);
s7comm_decode_ud_tis_param(tvbuff_t *tvb,proto_tree *tree,guint8 type,guint16 tp_size,guint32 offset)
{
guint32 start_offset;
guint32 callenv_setup = 0;
proto_item *item = NULL;
proto_tree *tp_tree = NULL;
start_offset = offset;
if (tp_size > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_tis_parameter, tvb, offset, tp_size, ENC_NA);
tp_tree = proto_item_add_subtree(item, ett_s7comm_prog_parameter);
if (type == S7COMM_UD_TYPE_REQ)
{
if (tp_size >= 4)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_param1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param2, tvb, offset, 2, ENC_NA);
offset += 2;
}
else
{
}
if (tp_size >= 20)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_param3, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_answersize, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param5, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param6, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param7, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param8, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param9, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_trgevent, tvb, offset, 2, ENC_NA);
offset += 2;
}
else
{
}
if (tp_size >= 26)
{
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_type, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
if (tp_size >= 28)
{
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_saz, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
if (tp_size >= 36)
{
proto_tree_add_item_ret_uint(tp_tree, hf_s7comm_tis_p_callenv, tvb, offset, 2, ENC_BIG_ENDIAN, &callenv_setup);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (callenv_setup == 2)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
}
else
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (tp_size >= 38)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_address, tvb, offset, 2, ENC_BIG_ENDIAN);
}
else
{
}
}
}
else
{
}
}
else
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param2, tvb, offset, 2, ENC_NA);
}
}
else
{
}
return start_offset + tp_size;
}
}
else
{
}
if (job_td_size > 0)
{
offset = s7comm_decode_ud_tis_data(tvb, td_tree, S7COMM_UD_TYPE_REQ, job_subfunc, job_td_size, offset);
}
else
{
}
break;
}
}
else
{
switch (subfunc)
{
case S7COMM_UD_SUBF_TIS_READJOBLIST:
for (i = 0; i < td_size / 4; i++)
{
item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d] Job", i + 1);
proto_tree_add_item(item_tree, hf_s7comm_tis_job_function, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_tis_job_seqnr, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_tis_job_reserved, tvb, offset, 2, ENC_NA);
offset += 2;
}
break;
case S7COMM_UD_SUBF_TIS_READJOB:
job_tp_size = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(td_tree, hf_s7comm_tis_parametersize, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
job_td_size = tvb_get_ntohs(tvb, offset);
proto_tree_add_item(td_tree, hf_s7comm_tis_datasize, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (job_tp_size > 0)
{
offset = s7comm_decode_ud_tis_param(tvb, td_tree, S7COMM_UD_TYPE_REQ, job_tp_size, offset);
s7comm_decode_ud_tis_param(tvbuff_t *tvb,proto_tree *tree,guint8 type,guint16 tp_size,guint32 offset)
{
guint32 start_offset;
guint32 callenv_setup = 0;
proto_item *item = NULL;
proto_tree *tp_tree = NULL;
start_offset = offset;
if (tp_size > 0)
{
item = proto_tree_add_item(tree, hf_s7comm_tis_parameter, tvb, offset, tp_size, ENC_NA);
tp_tree = proto_item_add_subtree(item, ett_s7comm_prog_parameter);
if (type == S7COMM_UD_TYPE_REQ)
{
if (tp_size >= 4)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_param1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param2, tvb, offset, 2, ENC_NA);
offset += 2;
}
else
{
}
if (tp_size >= 20)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_param3, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_answersize, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param5, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param6, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param7, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param8, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_param9, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_trgevent, tvb, offset, 2, ENC_NA);
offset += 2;
}
else
{
}
if (tp_size >= 26)
{
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_type, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
if (tp_size >= 28)
{
proto_tree_add_item(tp_tree, hf_s7comm_diagdata_req_saz, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
else
{
}
if (tp_size >= 36)
{
proto_tree_add_item_ret_uint(tp_tree, hf_s7comm_tis_p_callenv, tvb, offset, 2, ENC_BIG_ENDIAN, &callenv_setup);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (callenv_setup == 2)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db1_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_register_db2_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
}
else
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocktype, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_blocknr, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
if (tp_size >= 38)
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_p_callcond_address, tvb, offset, 2, ENC_BIG_ENDIAN);
}
else
{
}
}
}
else
{
}
}
else
{
proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param1, tvb, offset, 2, ENC_NA);
offset += 2;
proto_tree_add_item(tp_tree, hf_s7comm_tis_res_param2, tvb, offset, 2, ENC_NA);
}
}
else
{
}
return start_offset + tp_size;
}
}
else
{
}
if (job_td_size > 0)
{
item = proto_tree_add_item(td_tree, hf_s7comm_tis_data, tvb, offset, job_td_size, ENC_NA);
job_td_tree = proto_item_add_subtree(item, ett_s7comm_prog_data);
proto_tree_add_item(job_td_tree, hf_s7comm_tis_job_reserved, tvb, offset, job_td_size, ENC_NA);
offset += job_td_size;
}
else
{
}
break;
}
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_MODVAR:
offset = s7comm_decode_ud_tis_modvar(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_modvar(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
guint16 item_count;
guint16 i;
guint8 ret_val = 0;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
switch (type)
{
case S7COMM_UD_TYPE_REQ:
item_count = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
offset = s7comm_decode_ud_tis_item_address(tvb, offset, td_tree, i, " Address to write");
s7comm_decode_ud_tis_item_address(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint16 item_no,gchar *add_text)
{
guint32 bytepos = 0;
guint16 len = 0;
guint16 bitpos = 0;
guint16 db = 0;
guint8 area = 0;
proto_item *item = NULL;
item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, 6, ENC_NA);
sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
proto_item_append_text(item, " [%d]%s:", item_no + 1, add_text);
area = tvb_get_guint8(tvb, offset);
proto_tree_add_item(sub_tree, hf_s7comm_varstat_req_memory_area, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (area & 0x0f)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_repetition_factor, tvb, offset, 1, len);
offset += 1;
}
else
{
bitpos = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_bitpos, tvb, offset, 1, bitpos);
offset += 1;
}
db = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_db_number, tvb, offset, 2, db);
offset += 2;
bytepos = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_startaddress, tvb, offset, 2, bytepos);
offset += 2;
switch (area)
{
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MX:
proto_item_append_text(sub_tree, " (M%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MB:
proto_item_append_text(sub_tree, " (M%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MW:
proto_item_append_text(sub_tree, " (M%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MD:
proto_item_append_text(sub_tree, " (M%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EX:
proto_item_append_text(sub_tree, " (I%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EB:
proto_item_append_text(sub_tree, " (I%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EW:
proto_item_append_text(sub_tree, " (I%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_ED:
proto_item_append_text(sub_tree, " (I%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AX:
proto_item_append_text(sub_tree, " (Q%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AB:
proto_item_append_text(sub_tree, " (Q%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AW:
proto_item_append_text(sub_tree, " (Q%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AD:
proto_item_append_text(sub_tree, " (Q%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PEB:
proto_item_append_text(sub_tree, " (PI%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PEW:
proto_item_append_text(sub_tree, " (PI%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PED:
proto_item_append_text(sub_tree, " (PI%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBX:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.%d)", db, bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBB:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 BYTE %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBW:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 WORD %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBD:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 DWORD %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_T:
if (len >1)
{
proto_item_append_text(sub_tree, " (T %d..%d)", bytepos, bytepos + len - 1);
}
else
{
proto_item_append_text(sub_tree, " (T %d)", bytepos);
}
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_C:
if (len >1)
{
proto_item_append_text(sub_tree, " (C %d..%d)", bytepos, bytepos + len - 1);
}
else
{
proto_item_append_text(sub_tree, " (C %d)", bytepos);
}
break;
}
return offset;
}
}
for (i = 0; i < item_count; i++)
{
offset = s7comm_decode_ud_tis_item_value(tvb, offset, td_tree, i, " Data to write");
s7comm_decode_ud_tis_item_value(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint16 item_no,gchar *add_text)
{
guint16 len = 0, len2 = 0;
guint8 ret_val = 0;
guint8 tsize = 0;
guint8 head_len = 4;
proto_item *item = NULL;
ret_val = tvb_get_guint8(tvb, offset);
if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||ret_val == S7COMM_ITEM_RETVAL_DATA_ERR)
{
tsize = tvb_get_guint8(tvb, offset + 1);
len = tvb_get_ntohs(tvb, offset + 2);
if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT)
{
len /= 8;
}
else
{
}
if (len % 2)
{
len2 = len + 1;
}
else
{
len2 = len;
}
}
else
{
}
item = proto_tree_add_item(sub_tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
sub_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]%s: (%s)", item_no + 1, add_text, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
proto_tree_add_uint(sub_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
proto_tree_add_uint(sub_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
proto_tree_add_uint(sub_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);
offset += head_len;
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED)
{
proto_tree_add_item(sub_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
offset += len;
if (len != len2)
{
proto_tree_add_item(sub_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
return offset;
}
}
break;
case S7COMM_UD_TYPE_IND:
item_count = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
ret_val = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
proto_item_append_text(item, " [%d]: (%s)", i + 1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
offset += 1;
}
if (item_count % 2)
{
proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
break;
}
return offset;
}
break;
case S7COMM_UD_SUBF_TIS_FORCE:
offset = s7comm_decode_ud_tis_force(tvb, td_tree, type, offset);
s7comm_decode_ud_tis_force(tvbuff_t *tvb,proto_tree *td_tree,guint8 type,guint32 offset)
{
guint16 item_count;
guint16 i;
guint8 ret_val = 0;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
switch (type)
{
case S7COMM_UD_TYPE_REQ:
item_count = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
offset = s7comm_decode_ud_tis_item_address(tvb, offset, td_tree, i, " Address to force");
s7comm_decode_ud_tis_item_address(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint16 item_no,gchar *add_text)
{
guint32 bytepos = 0;
guint16 len = 0;
guint16 bitpos = 0;
guint16 db = 0;
guint8 area = 0;
proto_item *item = NULL;
item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, 6, ENC_NA);
sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
proto_item_append_text(item, " [%d]%s:", item_no + 1, add_text);
area = tvb_get_guint8(tvb, offset);
proto_tree_add_item(sub_tree, hf_s7comm_varstat_req_memory_area, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (area & 0x0f)
{
len = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_repetition_factor, tvb, offset, 1, len);
offset += 1;
}
else
{
bitpos = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_bitpos, tvb, offset, 1, bitpos);
offset += 1;
}
db = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_db_number, tvb, offset, 2, db);
offset += 2;
bytepos = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(sub_tree, hf_s7comm_varstat_req_startaddress, tvb, offset, 2, bytepos);
offset += 2;
switch (area)
{
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MX:
proto_item_append_text(sub_tree, " (M%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MB:
proto_item_append_text(sub_tree, " (M%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MW:
proto_item_append_text(sub_tree, " (M%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_MD:
proto_item_append_text(sub_tree, " (M%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EX:
proto_item_append_text(sub_tree, " (I%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EB:
proto_item_append_text(sub_tree, " (I%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_EW:
proto_item_append_text(sub_tree, " (I%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_ED:
proto_item_append_text(sub_tree, " (I%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AX:
proto_item_append_text(sub_tree, " (Q%d.%d)", bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AB:
proto_item_append_text(sub_tree, " (Q%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AW:
proto_item_append_text(sub_tree, " (Q%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_AD:
proto_item_append_text(sub_tree, " (Q%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PEB:
proto_item_append_text(sub_tree, " (PI%d.0 BYTE %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PEW:
proto_item_append_text(sub_tree, " (PI%d.0 WORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_PED:
proto_item_append_text(sub_tree, " (PI%d.0 DWORD %d)", bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBX:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.%d)", db, bytepos, bitpos);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBB:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 BYTE %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBW:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 WORD %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_DBD:
proto_item_append_text(sub_tree, " (DB%d.DBX%d.0 DWORD %d)", db, bytepos, len);
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_T:
if (len >1)
{
proto_item_append_text(sub_tree, " (T %d..%d)", bytepos, bytepos + len - 1);
}
else
{
proto_item_append_text(sub_tree, " (T %d)", bytepos);
}
break;
case S7COMM_UD_SUBF_TIS_VARSTAT_AREA_C:
if (len >1)
{
proto_item_append_text(sub_tree, " (C %d..%d)", bytepos, bytepos + len - 1);
}
else
{
proto_item_append_text(sub_tree, " (C %d)", bytepos);
}
break;
}
return offset;
}
}
for (i = 0; i < item_count; i++)
{
offset = s7comm_decode_ud_tis_item_value(tvb, offset, td_tree, i, " Value to force");
s7comm_decode_ud_tis_item_value(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint16 item_no,gchar *add_text)
{
guint16 len = 0, len2 = 0;
guint8 ret_val = 0;
guint8 tsize = 0;
guint8 head_len = 4;
proto_item *item = NULL;
ret_val = tvb_get_guint8(tvb, offset);
if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||ret_val == S7COMM_ITEM_RETVAL_DATA_ERR)
{
tsize = tvb_get_guint8(tvb, offset + 1);
len = tvb_get_ntohs(tvb, offset + 2);
if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT)
{
len /= 8;
}
else
{
}
if (len % 2)
{
len2 = len + 1;
}
else
{
len2 = len;
}
}
else
{
}
item = proto_tree_add_item(sub_tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
sub_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]%s: (%s)", item_no + 1, add_text, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
proto_tree_add_uint(sub_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
proto_tree_add_uint(sub_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
proto_tree_add_uint(sub_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);
offset += head_len;
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED)
{
proto_tree_add_item(sub_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
offset += len;
if (len != len2)
{
proto_tree_add_item(sub_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
else
{
}
return offset;
}
}
break;
case S7COMM_UD_TYPE_IND:
item_count = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(td_tree, hf_s7comm_varstat_item_count, tvb, offset, 2, item_count);
offset += 2;
for (i = 0; i < item_count; i++)
{
item = proto_tree_add_item(td_tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
ret_val = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
proto_item_append_text(item, " [%d]: (%s)", i + 1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
offset += 1;
}
if (item_count % 2)
{
proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
break;
}
return offset;
}
break;
default:
proto_tree_add_item(td_tree, hf_s7comm_varstat_unknown, tvb, offset, td_size, ENC_NA);
offset += td_size;
break;
}
}
else
{
}
return offset;
}
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_CYCLIC:
offset = s7comm_decode_ud_cyclic_subfunc(next_tvb, pinfo, seq_num, data_tree, type, subfunc, length_rem, offset);
s7comm_decode_ud_cyclic_subfunc(tvbuff_t *tvb,packet_info *pinfo,guint8 seq_num,proto_tree *data_tree,guint8 type,guint8 subfunc,guint32 dlength,guint32 offset)
{
gboolean know_data = FALSE;
guint32 offset_old;
guint32 len_item;
guint8 item_count;
guint8 i;
guint8 job_id;
switch (subfunc)
{
case S7COMM_UD_SUBF_CYCLIC_CHANGE_MOD:
if (type == S7COMM_UD_TYPE_REQ)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", seq_num);
}
else
{
}
case S7COMM_UD_SUBF_CYCLIC_TRANSF:
case S7COMM_UD_SUBF_CYCLIC_CHANGE:
item_count = tvb_get_guint8(tvb, offset + 1);
proto_tree_add_uint(data_tree, hf_s7comm_param_itemcount, tvb, offset, 2, item_count);
offset += 2;
if (type == S7COMM_UD_TYPE_REQ)
{
proto_tree_add_item(data_tree, hf_s7comm_cycl_interval_timebase, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_cycl_interval_time, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
for (i = 0; i < item_count; i++)
{
offset_old = offset;
offset = s7comm_decode_param_item(tvb, offset, data_tree, i);
s7comm_decode_param_item(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint8 item_no)
{
proto_item *item = NULL;
proto_tree *item_tree = NULL;
guint8 var_spec_type = 0;
guint8 var_spec_length = 0;
guint8 var_spec_syntax_id = 0;
var_spec_type = tvb_get_guint8(tvb, offset);
var_spec_length = tvb_get_guint8(tvb, offset + 1);
var_spec_syntax_id = tvb_get_guint8(tvb, offset + 2);
item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, var_spec_length + 2, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
proto_item_append_text(item, " [%d]:", item_no + 1);
proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_S7ANY)
{
offset = s7comm_syntaxid_s7any(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length >= 7 && var_spec_syntax_id == S7COMM_SYNTAXID_DBREAD)
{
offset = s7comm_syntaxid_dbread(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length >= 14 && var_spec_syntax_id == S7COMM_SYNTAXID_1200SYM)
{
offset = s7comm_syntaxid_1200sym(tvb, offset, item_tree, var_spec_length);
}
else if (var_spec_type == 0x12 && var_spec_length == 8&& ((var_spec_syntax_id == S7COMM_SYNTAXID_NCK)|| (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_METRIC)|| (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_INCH)))
{
offset = s7comm_syntaxid_nck(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_DRIVEESANY)
{
offset = s7comm_syntaxid_driveesany(tvb, offset, item_tree);
}
else
{
offset += var_spec_length - 1;
proto_item_append_text(item_tree, " Unknown variable specification");
}
return offset;
}
len_item = offset - offset_old;
if ((len_item % 2) && (i < (item_count-1)))
{
offset += 1;
}
else
{
}
}
}
else if (type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_IND)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", seq_num);
offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
}
else
{
}
know_data = TRUE;
break;
case S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE:
if (type == S7COMM_UD_TYPE_REQ)
{
proto_tree_add_item(data_tree, hf_s7comm_cycl_function, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_cycl_jobid, tvb, offset, 1, ENC_BIG_ENDIAN);
job_id = tvb_get_guint8(tvb, offset);
col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", job_id);
offset += 1;
know_data = TRUE;
}
else if (type == S7COMM_UD_TYPE_RES)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " JobID=%d", seq_num);
}
else
{
}
break;
case S7COMM_UD_SUBF_CYCLIC_RDREC:
offset = s7comm_decode_ud_readrec(tvb, data_tree, type, offset);
s7comm_decode_ud_readrec(tvbuff_t *tvb,proto_tree *tree,guint8 type,guint32 offset)
{
guint32 ret_val;
guint32 statuslen;
guint32 reclen;
guint8 item_count;
if (type == S7COMM_UD_TYPE_REQ)
{
proto_tree_add_item(tree, hf_s7comm_rdrec_reserved1, tvb, offset, 1, ENC_NA);
offset += 1;
item_count = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
offset += 1;
if (item_count > 0)
{
offset = s7comm_decode_param_item(tvb, offset, tree, 0);
s7comm_decode_param_item(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree,guint8 item_no)
{
proto_item *item = NULL;
proto_tree *item_tree = NULL;
guint8 var_spec_type = 0;
guint8 var_spec_length = 0;
guint8 var_spec_syntax_id = 0;
var_spec_type = tvb_get_guint8(tvb, offset);
var_spec_length = tvb_get_guint8(tvb, offset + 1);
var_spec_syntax_id = tvb_get_guint8(tvb, offset + 2);
item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, var_spec_length + 2, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_param_item);
proto_item_append_text(item, " [%d]:", item_no + 1);
proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_S7ANY)
{
offset = s7comm_syntaxid_s7any(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length >= 7 && var_spec_syntax_id == S7COMM_SYNTAXID_DBREAD)
{
offset = s7comm_syntaxid_dbread(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length >= 14 && var_spec_syntax_id == S7COMM_SYNTAXID_1200SYM)
{
offset = s7comm_syntaxid_1200sym(tvb, offset, item_tree, var_spec_length);
}
else if (var_spec_type == 0x12 && var_spec_length == 8&& ((var_spec_syntax_id == S7COMM_SYNTAXID_NCK)|| (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_METRIC)|| (var_spec_syntax_id == S7COMM_SYNTAXID_NCK_INCH)))
{
offset = s7comm_syntaxid_nck(tvb, offset, item_tree);
}
else if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_DRIVEESANY)
{
offset = s7comm_syntaxid_driveesany(tvb, offset, item_tree);
}
else
{
offset += var_spec_length - 1;
proto_item_append_text(item_tree, " Unknown variable specification");
}
return offset;
}
}
else
{
}
}
else if (type == S7COMM_UD_TYPE_RES)
{
proto_tree_add_item(tree, hf_s7comm_rdrec_reserved1, tvb, offset, 1, ENC_NA);
offset += 1;
item_count = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
offset += 1;
if (item_count > 0)
{
proto_tree_add_item_ret_uint(tree, hf_s7comm_data_returncode, tvb, offset, 1, ENC_BIG_ENDIAN, &ret_val);
offset += 1;
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK)
{
proto_tree_add_item(tree, hf_s7comm_data_transport_size, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_statuslen, tvb, offset, 1, ENC_BIG_ENDIAN, &statuslen);
offset += 1;
if (statuslen > 0)
{
proto_tree_add_item(tree, hf_s7comm_rdrec_statusdata, tvb, offset, statuslen, ENC_NA);
offset += statuslen;
}
else
{
offset += 1;
}
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK)
{
proto_tree_add_item_ret_uint(tree, hf_s7comm_rdrec_recordlen, tvb, offset, 2, ENC_BIG_ENDIAN, &reclen);
offset += 2;
if (reclen > 0)
{
proto_tree_add_item(tree, hf_s7comm_rdrec_data, tvb, offset, reclen, ENC_NA);
offset += reclen;
}
else
{
}
}
else
{
}
}
else
{
}
}
else
{
}
return offset;
}
know_data = TRUE;
break;
}
if (know_data == FALSE && dlength > 0)
{
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_BLOCK:
offset = s7comm_decode_ud_block_subfunc(next_tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, length_rem, offset);
s7comm_decode_ud_block_subfunc(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint8 type,guint8 subfunc,guint8 ret_val,guint8 tsize,guint32 dlength,guint32 offset)
{
guint32 count;
guint32 i;
const guint8 *pBlocknumber;
guint16 blocknumber;
guint8 blocktype;
guint16 blocktype16;
gboolean know_data = FALSE;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
proto_item *itemadd = NULL;
char str_timestamp[30];
char str_version[10];
switch (subfunc)
{
case S7COMM_UD_SUBF_BLOCK_LIST:
if (type == S7COMM_UD_TYPE_REQ)
{
}
else if (type == S7COMM_UD_TYPE_RES)
{
count = dlength / 4;
for (i = 0; i < count; i++)
{
item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
blocktype16 = tvb_get_ntohs(tvb, offset);
proto_item_append_text(item, " [%d]: (Block type %s)", i+1, val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
itemadd = proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
}
know_data = TRUE;
}
else
{
}
break;
case S7COMM_UD_SUBF_BLOCK_LISTTYPE:
if (type == S7COMM_UD_TYPE_REQ)
{
if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL)
{
blocktype16 = tvb_get_ntohs(tvb, offset);
itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]",val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
proto_item_append_text(data_tree, ": (%s)",val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
}
else
{
}
know_data = TRUE;
}
else if (type == S7COMM_UD_TYPE_RES)
{
if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL)
{
count = dlength / 4;
for (i = 0; i < count; i++)
{
item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]: (Block number %d)", i+1, tvb_get_ntohs(tvb, offset));
proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
}
else
{
}
know_data = TRUE;
}
else
{
}
break;
case S7COMM_UD_SUBF_BLOCK_BLOCKINFO:
if (type == S7COMM_UD_TYPE_REQ)
{
if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL)
{
gint32 num = -1;
gboolean num_valid;
blocktype16 = tvb_get_ntohs(tvb, offset);
itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item_ret_string(data_tree, hf_s7comm_ud_blockinfo_block_num_ascii, tvb, offset, 5, ENC_ASCII|ENC_NA, pinfo->pool, &pBlocknumber);
num_valid = ws_strtoi32((const gchar*)pBlocknumber, NULL, &num);
proto_item_append_text(data_tree, " [%s ",val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s ",val_to_str(blocktype16, blocktype_names, "Unknown Block type: 0x%04x"));
if (num_valid)
{
proto_item_append_text(data_tree, "%d]", num);
col_append_fstr(pinfo->cinfo, COL_INFO, "%d]", num);
}
else
{
expert_add_info(pinfo, data_tree, &ei_s7comm_ud_blockinfo_block_num_ascii_invalid);
proto_item_append_text(data_tree, "NaN]");
col_append_str(pinfo->cinfo, COL_INFO, "NaN]");
}
offset += 5;
itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_filesys, tvb, offset, 1, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", char_val_to_str(tvb_get_guint8(tvb, offset), blocktype_attribute2_names, "Unknown filesys"));
offset += 1;
}
else
{
}
know_data = TRUE;
}
else if (type == S7COMM_UD_TYPE_RES)
{
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK)
{
itemadd = proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 2, ENC_ASCII);
proto_item_append_text(itemadd, " (%s)", val_to_str(tvb_get_ntohs(tvb, offset), blocktype_names, "Unknown Block type: 0x%04x"));
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_infolength, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_const3, tvb, offset, 2, ENC_ASCII);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_userdata_blockinfo_flags,ett_s7comm_userdata_blockinfo_flags, s7comm_userdata_blockinfo_flags_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
blocktype = tvb_get_guint8(tvb, offset);
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_subblk_type, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
blocknumber = tvb_get_ntohs(tvb, offset);
proto_tree_add_uint(data_tree, hf_s7comm_ud_blockinfo_block_num, tvb, offset, 2, blocknumber);
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Block:[%s %d]",val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"),blocknumber);
proto_item_append_text(data_tree, ": (Block:[%s %d])",val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"),blocknumber);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_load_mem_len, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_blocksecurity, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
s7comm_get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_code_timestamp, tvb, offset, 6, str_timestamp);
offset += 6;
s7comm_get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_interface_timestamp, tvb, offset, 6, str_timestamp);
offset += 6;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_ssb_len, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_add_len, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_localdata_len, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_mc7_len, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_author, tvb, offset, 8, ENC_ASCII);
offset += 8;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_family, tvb, offset, 8, ENC_ASCII);
offset += 8;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_headername, tvb, offset, 8, ENC_ASCII);
offset += 8;
snprintf(str_version, sizeof(str_version), "%d.%d", ((tvb_get_guint8(tvb, offset) & 0xf0) >> 4), tvb_get_guint8(tvb, offset) & 0x0f);
proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_headerversion, tvb, offset, 1, str_version);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_checksum(data_tree, tvb, offset, hf_s7comm_ud_blockinfo_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_reserved1, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
}
else
{
}
know_data = TRUE;
}
else
{
}
break;
default:
break;
}
if (know_data == FALSE && dlength > 0)
{
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_CPU:
switch (subfunc)
{
case S7COMM_UD_SUBF_CPU_READSZL:
offset = s7comm_decode_ud_cpu_szl_subfunc(next_tvb, pinfo, data_tree, type, ret_val, length_rem, offset);
break;
case S7COMM_UD_SUBF_CPU_NOTIFY_IND:
case S7COMM_UD_SUBF_CPU_NOTIFY8_IND:
case S7COMM_UD_SUBF_CPU_ALARMSQ_IND:
case S7COMM_UD_SUBF_CPU_ALARMS_IND:
case S7COMM_UD_SUBF_CPU_SCAN_IND:
case S7COMM_UD_SUBF_CPU_ALARMACK:
case S7COMM_UD_SUBF_CPU_ALARMACK_IND:
case S7COMM_UD_SUBF_CPU_ALARM8_IND:
case S7COMM_UD_SUBF_CPU_ALARM8LOCK:
case S7COMM_UD_SUBF_CPU_ALARM8LOCK_IND:
case S7COMM_UD_SUBF_CPU_ALARM8UNLOCK:
case S7COMM_UD_SUBF_CPU_ALARM8UNLOCK_IND:
offset = s7comm_decode_ud_cpu_alarm_main(next_tvb, pinfo, data_tree, type, subfunc, offset);
s7comm_decode_ud_cpu_alarm_main(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint8 type,guint8 subfunc,guint32 offset)
{
guint32 start_offset;
guint32 asc_start_offset;
guint32 msg_obj_start_offset;
guint32 ev_id;
proto_item *msg_item = NULL;
proto_tree *msg_item_tree = NULL;
proto_item *msg_obj_item = NULL;
proto_tree *msg_obj_item_tree = NULL;
proto_item *msg_work_item = NULL;
proto_tree *msg_work_item_tree = NULL;
guint8 nr_objects;
guint8 i;
guint8 syntax_id;
guint8 nr_of_additional_values;
guint8 signalstate;
guint8 sig_nr;
guint8 ret_val;
guint8 querytype;
guint8 varspec_length;
start_offset = offset;
msg_item = proto_tree_add_item(data_tree, hf_s7comm_cpu_alarm_message_item, tvb, offset, 0, ENC_NA);
msg_item_tree = proto_item_add_subtree(msg_item, ett_s7comm_cpu_alarm_message);
switch (subfunc)
{
case S7COMM_UD_SUBF_CPU_SCAN_IND:
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_scan_unknown1, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
msg_work_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_scan_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case S7COMM_UD_SUBF_CPU_ALARM8_IND:
case S7COMM_UD_SUBF_CPU_ALARMACK_IND:
case S7COMM_UD_SUBF_CPU_ALARMSQ_IND:
case S7COMM_UD_SUBF_CPU_ALARMS_IND:
case S7COMM_UD_SUBF_CPU_NOTIFY_IND:
case S7COMM_UD_SUBF_CPU_NOTIFY8_IND:
msg_work_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
break;
}
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_function, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
nr_objects = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_item_tree, hf_s7comm_cpu_alarm_message_nr_objects, tvb, offset, 1, nr_objects);
offset += 1;
for (i = 0; i < nr_objects; i++)
{
msg_obj_start_offset = offset;
msg_obj_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_obj_item, tvb, offset, 0, ENC_NA);
msg_obj_item_tree = proto_item_add_subtree(msg_obj_item, ett_s7comm_cpu_alarm_message_object);
proto_item_append_text(msg_obj_item_tree, " [%d]", i+1);
if (type == S7COMM_UD_TYPE_REQ || type == S7COMM_UD_TYPE_IND)
{
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
varspec_length = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, varspec_length);
offset += 1;
syntax_id = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, syntax_id);
offset += 1;
switch (syntax_id)
{
case S7COMM_SYNTAXID_ALARM_LOCKFREESET:
case S7COMM_SYNTAXID_ALARM_INDSET:
case S7COMM_SYNTAXID_NOTIFY_INDSET:
case S7COMM_SYNTAXID_ALARM_ACKSET:
nr_of_additional_values = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_nr_add_values, tvb, offset, 1, nr_of_additional_values);
offset += 1;
ev_id = tvb_get_ntohl(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ev_id);
offset += 4;
proto_item_append_text(msg_obj_item_tree, ": EventID=0x%08x", ev_id);
col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%08x", ev_id);
if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
signalstate = tvb_get_guint8(tvb, offset);
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_eventstate,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
if (signalstate > 0)
{
col_append_str(pinfo->cinfo, COL_INFO, " On=[");
for (sig_nr = 0; sig_nr < 8; sig_nr++)
{
if (signalstate & 0x01)
{
signalstate >>= 1;
if (signalstate == 0)
{
col_append_fstr(pinfo->cinfo, COL_INFO, "SIG_%d", sig_nr + 1);
}
else
{
col_append_fstr(pinfo->cinfo, COL_INFO, "SIG_%d,", sig_nr + 1);
}
}
else
{
signalstate >>= 1;
}
}
col_append_str(pinfo->cinfo, COL_INFO, "]");
}
else
{
}
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_state,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_ALARM_ACKSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_going,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_coming,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_going,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_coming,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_lastchanged,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_event_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
if (nr_of_additional_values > 0)
{
asc_start_offset = offset;
msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_associated_value, tvb, offset, 0, ENC_NA);
msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_associated_value);
offset = s7comm_decode_response_read_data(tvb, msg_work_item_tree, nr_of_additional_values, offset);
proto_item_set_len(msg_work_item_tree, offset - asc_start_offset);
}
else
{
}
}
else
{
}
break;
case S7COMM_SYNTAXID_ALARM_QUERYREQSET:
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_unknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
querytype = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_querytype, tvb, offset, 1, querytype);
offset += 1;
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
ev_id = tvb_get_ntohl(tvb, offset);
switch (querytype)
{
case S7COMM_ALARM_MESSAGE_QUERYTYPE_BYALARMTYPE:
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_alarmtype, tvb, offset, 4, ENC_BIG_ENDIAN);
col_append_fstr(pinfo->cinfo, COL_INFO, " ByAlarmtype=%s",val_to_str(ev_id, alarm_message_query_alarmtype_names, "Unknown Alarmtype: %u"));
break;
case S7COMM_ALARM_MESSAGE_QUERYTYPE_BYEVENTID:
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ENC_BIG_ENDIAN);
col_append_fstr(pinfo->cinfo, COL_INFO, " ByEventID=0x%08x", ev_id);
break;
default:
break;
}
offset += 4;
break;
default:
offset += (varspec_length - 1);
break;
}
}
else if (type == S7COMM_UD_TYPE_RES)
{
ret_val = tvb_get_guint8(tvb, offset);
proto_item_append_text(msg_obj_item_tree, ": (%s)", val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
offset += 1;
}
else
{
}
proto_item_set_len(msg_obj_item_tree, offset - msg_obj_start_offset);
}
proto_item_set_len(msg_item_tree, offset - start_offset);
return offset;
}
break;
case S7COMM_UD_SUBF_CPU_ALARMQUERY:
if (type == S7COMM_UD_TYPE_RES)
{
offset = s7comm_decode_ud_cpu_alarm_query_response(next_tvb, data_tree, offset);
}
else
{
offset = s7comm_decode_ud_cpu_alarm_main(next_tvb, pinfo, data_tree, type, subfunc, offset);
s7comm_decode_ud_cpu_alarm_main(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint8 type,guint8 subfunc,guint32 offset)
{
guint32 start_offset;
guint32 asc_start_offset;
guint32 msg_obj_start_offset;
guint32 ev_id;
proto_item *msg_item = NULL;
proto_tree *msg_item_tree = NULL;
proto_item *msg_obj_item = NULL;
proto_tree *msg_obj_item_tree = NULL;
proto_item *msg_work_item = NULL;
proto_tree *msg_work_item_tree = NULL;
guint8 nr_objects;
guint8 i;
guint8 syntax_id;
guint8 nr_of_additional_values;
guint8 signalstate;
guint8 sig_nr;
guint8 ret_val;
guint8 querytype;
guint8 varspec_length;
start_offset = offset;
msg_item = proto_tree_add_item(data_tree, hf_s7comm_cpu_alarm_message_item, tvb, offset, 0, ENC_NA);
msg_item_tree = proto_item_add_subtree(msg_item, ett_s7comm_cpu_alarm_message);
switch (subfunc)
{
case S7COMM_UD_SUBF_CPU_SCAN_IND:
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_scan_unknown1, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
msg_work_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_scan_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
break;
case S7COMM_UD_SUBF_CPU_ALARM8_IND:
case S7COMM_UD_SUBF_CPU_ALARMACK_IND:
case S7COMM_UD_SUBF_CPU_ALARMSQ_IND:
case S7COMM_UD_SUBF_CPU_ALARMS_IND:
case S7COMM_UD_SUBF_CPU_NOTIFY_IND:
case S7COMM_UD_SUBF_CPU_NOTIFY8_IND:
msg_work_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_timestamp_coming, tvb, offset, 8, ENC_NA);
msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_timestamp);
offset = s7comm_add_timestamp_to_tree(tvb, msg_work_item_tree, offset, TRUE, FALSE);
break;
}
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_function, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
nr_objects = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_item_tree, hf_s7comm_cpu_alarm_message_nr_objects, tvb, offset, 1, nr_objects);
offset += 1;
for (i = 0; i < nr_objects; i++)
{
msg_obj_start_offset = offset;
msg_obj_item = proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_alarm_message_obj_item, tvb, offset, 0, ENC_NA);
msg_obj_item_tree = proto_item_add_subtree(msg_obj_item, ett_s7comm_cpu_alarm_message_object);
proto_item_append_text(msg_obj_item_tree, " [%d]", i+1);
if (type == S7COMM_UD_TYPE_REQ || type == S7COMM_UD_TYPE_IND)
{
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
varspec_length = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, varspec_length);
offset += 1;
syntax_id = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, syntax_id);
offset += 1;
switch (syntax_id)
{
case S7COMM_SYNTAXID_ALARM_LOCKFREESET:
case S7COMM_SYNTAXID_ALARM_INDSET:
case S7COMM_SYNTAXID_NOTIFY_INDSET:
case S7COMM_SYNTAXID_ALARM_ACKSET:
nr_of_additional_values = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_nr_add_values, tvb, offset, 1, nr_of_additional_values);
offset += 1;
ev_id = tvb_get_ntohl(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ev_id);
offset += 4;
proto_item_append_text(msg_obj_item_tree, ": EventID=0x%08x", ev_id);
col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%08x", ev_id);
if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
signalstate = tvb_get_guint8(tvb, offset);
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_eventstate,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
if (signalstate > 0)
{
col_append_str(pinfo->cinfo, COL_INFO, " On=[");
for (sig_nr = 0; sig_nr < 8; sig_nr++)
{
if (signalstate & 0x01)
{
signalstate >>= 1;
if (signalstate == 0)
{
col_append_fstr(pinfo->cinfo, COL_INFO, "SIG_%d", sig_nr + 1);
}
else
{
col_append_fstr(pinfo->cinfo, COL_INFO, "SIG_%d,", sig_nr + 1);
}
}
else
{
signalstate >>= 1;
}
}
col_append_str(pinfo->cinfo, COL_INFO, "]");
}
else
{
}
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_state,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_ALARM_ACKSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_going,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_ackstate_coming,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_going,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_coming,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_bitmask(msg_obj_item_tree, tvb, offset, hf_s7comm_cpu_alarm_message_event_lastchanged,ett_s7comm_cpu_alarm_message_signal, s7comm_cpu_alarm_message_signal_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_event_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
if (syntax_id == S7COMM_SYNTAXID_ALARM_INDSET || syntax_id == S7COMM_SYNTAXID_NOTIFY_INDSET)
{
if (nr_of_additional_values > 0)
{
asc_start_offset = offset;
msg_work_item = proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_associated_value, tvb, offset, 0, ENC_NA);
msg_work_item_tree = proto_item_add_subtree(msg_work_item, ett_s7comm_cpu_alarm_message_associated_value);
offset = s7comm_decode_response_read_data(tvb, msg_work_item_tree, nr_of_additional_values, offset);
proto_item_set_len(msg_work_item_tree, offset - asc_start_offset);
}
else
{
}
}
else
{
}
break;
case S7COMM_SYNTAXID_ALARM_QUERYREQSET:
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_unknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
querytype = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_querytype, tvb, offset, 1, querytype);
offset += 1;
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
ev_id = tvb_get_ntohl(tvb, offset);
switch (querytype)
{
case S7COMM_ALARM_MESSAGE_QUERYTYPE_BYALARMTYPE:
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_query_alarmtype, tvb, offset, 4, ENC_BIG_ENDIAN);
col_append_fstr(pinfo->cinfo, COL_INFO, " ByAlarmtype=%s",val_to_str(ev_id, alarm_message_query_alarmtype_names, "Unknown Alarmtype: %u"));
break;
case S7COMM_ALARM_MESSAGE_QUERYTYPE_BYEVENTID:
proto_tree_add_item(msg_obj_item_tree, hf_s7comm_cpu_alarm_message_eventid, tvb, offset, 4, ENC_BIG_ENDIAN);
col_append_fstr(pinfo->cinfo, COL_INFO, " ByEventID=0x%08x", ev_id);
break;
default:
break;
}
offset += 4;
break;
default:
offset += (varspec_length - 1);
break;
}
}
else if (type == S7COMM_UD_TYPE_RES)
{
ret_val = tvb_get_guint8(tvb, offset);
proto_item_append_text(msg_obj_item_tree, ": (%s)", val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
proto_tree_add_uint(msg_obj_item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
offset += 1;
}
else
{
}
proto_item_set_len(msg_obj_item_tree, offset - msg_obj_start_offset);
}
proto_item_set_len(msg_item_tree, offset - start_offset);
return offset;
}
}
break;
case S7COMM_UD_SUBF_CPU_DIAGMSG:
offset = s7comm_decode_ud_cpu_diagnostic_message(next_tvb, pinfo, TRUE, data_tree, offset);
s7comm_decode_ud_cpu_diagnostic_message(tvbuff_t *tvb,packet_info *pinfo,gboolean add_info_to_col,proto_tree *data_tree,guint32 offset)
{
proto_item *msg_item = NULL;
proto_tree *msg_item_tree = NULL;
guint16 eventid;
guint16 eventid_masked;
const gchar *event_text;
gboolean has_text = FALSE;
msg_item = proto_tree_add_item(data_tree, hf_s7comm_cpu_diag_msg_item, tvb, offset, 20, ENC_NA);
msg_item_tree = proto_item_add_subtree(msg_item, ett_s7comm_cpu_diag_msg);
eventid = tvb_get_ntohs(tvb, offset);
if ((eventid >= 0x8000) && (eventid <= 0x9fff))
{
eventid_masked = eventid & 0xf0ff;
if ((event_text = try_val_to_str_ext(eventid_masked, &cpu_diag_eventid_0x8_0x9_names_ext)))
{
if (add_info_to_col)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " Event='%s'", event_text);
}
else
{
}
has_text = TRUE;
}
else
{
if (add_info_to_col)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%04x", eventid);
}
else
{
}
}
}
else if ((eventid >= 0x1000) && (eventid < 0x8000))
{
if ((event_text = try_val_to_str_ext(eventid, &cpu_diag_eventid_fix_names_ext)))
{
if (add_info_to_col)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " Event='%s'", event_text);
}
else
{
}
has_text = TRUE;
}
else
{
if (add_info_to_col)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%04x", eventid);
}
else
{
}
}
}
else
{
if (add_info_to_col)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " EventID=0x%04x", eventid);
}
else
{
}
}
proto_tree_add_bitmask(msg_item_tree, tvb, offset, hf_s7comm_cpu_diag_msg_eventid,ett_s7comm_cpu_diag_msg_eventid, s7comm_cpu_diag_msg_eventid_fields, ENC_BIG_ENDIAN);
if (has_text)
{
proto_item_append_text(msg_item_tree, ": Event='%s'", event_text);
}
else
{
proto_item_append_text(msg_item_tree, ": EventID=0x%04x", eventid);
}
offset += 2;
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_prioclass, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_obnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_datid, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_info1, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(msg_item_tree, hf_s7comm_cpu_diag_msg_info2, tvb, offset, 4, ENC_BIG_ENDIAN);
offset += 4;
offset = s7comm_add_timestamp_to_tree(tvb, msg_item_tree, offset, FALSE, FALSE);
return offset;
}
break;
case S7COMM_UD_SUBF_CPU_MSGS:
offset = s7comm_decode_message_service(next_tvb, pinfo, data_tree, type, length_rem, offset);
s7comm_decode_message_service(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint8 type,guint32 dlength,guint32 offset)
{
guint8 events;
guint8 almtype;
gchar events_string[42];
switch (type)
{
case S7COMM_UD_TYPE_REQ:
events = tvb_get_guint8(tvb, offset);
proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_cpu_msgservice_subscribe_events,ett_s7comm_cpu_msgservice_subscribe_events, s7comm_cpu_msgservice_subscribe_events_fields, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_req_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
(void) g_strlcpy(events_string, "", sizeof(events_string));
if (events & 0x01)
{
(void) g_strlcat(events_string, "MODE,", sizeof(events_string));
}
else
{
}
if (events & 0x02)
{
(void) g_strlcat(events_string, "SYS,", sizeof(events_string));
}
else
{
}
if (events & 0x04)
{
(void) g_strlcat(events_string, "USR,", sizeof(events_string));
}
else
{
}
if (events & 0x08)
{
(void) g_strlcat(events_string, "-4-,", sizeof(events_string));
}
else
{
}
if (events & 0x10)
{
(void) g_strlcat(events_string, "-5-,", sizeof(events_string));
}
else
{
}
if (events & 0x20)
{
(void) g_strlcat(events_string, "-6-,", sizeof(events_string));
}
else
{
}
if (events & 0x40)
{
(void) g_strlcat(events_string, "-7-,", sizeof(events_string));
}
else
{
}
if (events & 0x80)
{
(void) g_strlcat(events_string, "ALM,", sizeof(events_string));
}
else
{
}
if (strlen(events_string) > 2)
{
events_string[strlen(events_string) - 1 ] = '\0';
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " SubscribedEvents=(%s)", events_string);
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_username, tvb, offset, 8, ENC_ASCII);
offset += 8;
if ((events & 0x80) && (dlength > 10))
{
almtype = tvb_get_guint8(tvb, offset);
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_almtype, tvb, offset, 1, ENC_BIG_ENDIAN);
col_append_fstr(pinfo->cinfo, COL_INFO, " AlmType=%s", val_to_str(almtype, cpu_msgservice_almtype_names, "Unknown type: 0x%02x"));
offset += 1;
if (almtype == S7COMM_CPU_MSG_ALMTYPE_AR_SEND_INITIATE || almtype == S7COMM_CPU_MSG_ALMTYPE_AR_SEND_ABORT)
{
offset = s7comm_decode_message_service_ar_send_args(tvb, pinfo, data_tree, type, offset);
s7comm_decode_message_service_ar_send_args(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,guint8 type,guint32 offset)
{
guint8 item_count;
guint8 i;
guint32 ar_id;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
item_count = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
offset += 1;
for (i = 0; i < item_count; i++)
{
if (type == S7COMM_UD_TYPE_REQ)
{
item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, 8, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_pbc_arsend_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item_ret_uint(item_tree, hf_s7comm_pbc_arsend_ar_id, tvb, offset, 4, ENC_BIG_ENDIAN, &ar_id);
col_append_fstr(pinfo->cinfo, COL_INFO, "%s0x%X", (i == 0) ? " AR_ID=" : ",", ar_id);
proto_item_append_text(item, " [%d]: AR_ID=0x%X", i+1, ar_id);
offset += 4;
}
else if (type == S7COMM_UD_TYPE_RES)
{
item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]", i+1);
proto_tree_add_item(item_tree, hf_s7comm_pbc_arsend_ret, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
if (type == S7COMM_UD_TYPE_RES && (item_count % 2))
{
proto_tree_add_item(tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
return offset;
}
}
else
{
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_req_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
}
else
{
}
break;
case S7COMM_UD_TYPE_RES:
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_result, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
if (dlength > 2)
{
almtype = tvb_get_guint8(tvb, offset);
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_almtype, tvb, offset, 1, ENC_BIG_ENDIAN);
col_append_fstr(pinfo->cinfo, COL_INFO, " AlmType=%s", val_to_str(almtype, cpu_msgservice_almtype_names, "Unknown type: 0x%02x"));
offset += 1;
if (almtype == S7COMM_CPU_MSG_ALMTYPE_AR_SEND_INITIATE || almtype == S7COMM_CPU_MSG_ALMTYPE_AR_SEND_ABORT)
{
offset = s7comm_decode_message_service_ar_send_args(tvb, pinfo, data_tree, type, offset);
s7comm_decode_message_service_ar_send_args(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree,guint8 type,guint32 offset)
{
guint8 item_count;
guint8 i;
guint32 ar_id;
proto_item *item = NULL;
proto_tree *item_tree = NULL;
item_count = tvb_get_guint8(tvb, offset);
proto_tree_add_uint(tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
offset += 1;
for (i = 0; i < item_count; i++)
{
if (type == S7COMM_UD_TYPE_REQ)
{
item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, 8, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(item_tree, hf_s7comm_pbc_arsend_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item_ret_uint(item_tree, hf_s7comm_pbc_arsend_ar_id, tvb, offset, 4, ENC_BIG_ENDIAN, &ar_id);
col_append_fstr(pinfo->cinfo, COL_INFO, "%s0x%X", (i == 0) ? " AR_ID=" : ",", ar_id);
proto_item_append_text(item, " [%d]: AR_ID=0x%X", i+1, ar_id);
offset += 4;
}
else if (type == S7COMM_UD_TYPE_RES)
{
item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
proto_item_append_text(item, " [%d]", i+1);
proto_tree_add_item(item_tree, hf_s7comm_pbc_arsend_ret, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
}
if (type == S7COMM_UD_TYPE_RES && (item_count % 2))
{
proto_tree_add_item(tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
else
{
}
return offset;
}
}
else
{
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_cpu_msgservice_res_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
}
}
else
{
}
break;
}
return offset;
}
break;
case S7COMM_UD_SUBF_CPU_AR_SEND_IND:
offset = s7comm_decode_ud_cpu_ar_send(next_tvb, data_tree, offset);
s7comm_decode_ud_cpu_ar_send(tvbuff_t *tvb,proto_tree *data_tree,guint32 offset)
{
guint32 len;
proto_tree_add_item_ret_uint(data_tree, hf_s7comm_pbc_arsend_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &len);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, len, ENC_NA);
offset += len;
return offset;
}
break;
default:
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, next_tvb, offset, length_rem, ENC_NA);
break;
}
break;
case S7COMM_UD_FUNCGROUP_SEC:
offset = s7comm_decode_ud_security_subfunc(next_tvb, data_tree, length_rem, offset);
s7comm_decode_ud_security_subfunc(tvbuff_t *tvb,proto_tree *data_tree,guint32 dlength,guint32 offset)
{
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_PBC_BSEND:
offset = s7comm_decode_ud_pbc_bsend_subfunc(next_tvb, data_tree, length_rem, offset, pinfo, root_tree);
s7comm_decode_ud_pbc_bsend_subfunc(tvbuff_t *tvb,proto_tree *data_tree,guint32 dlength,guint32 offset,packet_info *pinfo,proto_tree *tree)
{
proto_tree_add_item(data_tree, hf_s7comm_pbc_bsend_len, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 2, ENC_NA);
if (tvb_reported_length_remaining(tvb, offset) > 0)
{
struct tvbuff *next_tvb = tvb_new_subset_remaining(tvb,  offset);
heur_dtbl_entry_t *hdtbl_entry;
if (!dissector_try_heuristic(s7comm_heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL))
{
call_data_dissector(next_tvb, pinfo, data_tree);
}
else
{
}
}
else
{
}
offset += (dlength - 2);
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_TIME:
offset = s7comm_decode_ud_time_subfunc(next_tvb, data_tree, type, subfunc, ret_val, length_rem, offset);
s7comm_decode_ud_time_subfunc(tvbuff_t *tvb,proto_tree *data_tree,guint8 type,guint8 subfunc,guint8 ret_val,guint32 dlength,guint32 offset)
{
gboolean know_data = FALSE;
switch (subfunc)
{
case S7COMM_UD_SUBF_TIME_READ:
case S7COMM_UD_SUBF_TIME_READF:
if (type == S7COMM_UD_TYPE_RES)
{
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK)
{
proto_item_append_text(data_tree, ": ");
offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE, TRUE);
}
else
{
}
know_data = TRUE;
}
else
{
}
break;
case S7COMM_UD_SUBF_TIME_SET:
case S7COMM_UD_SUBF_TIME_SET2:
if (type == S7COMM_UD_TYPE_REQ)
{
if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK)
{
proto_item_append_text(data_tree, ": ");
offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE, TRUE);
}
else
{
}
know_data = TRUE;
}
else
{
}
break;
default:
break;
}
if (know_data == FALSE && dlength > 0)
{
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_NCPRG:
offset = s7comm_decode_ud_ncprg_subfunc(next_tvb, pinfo, data_tree, type, subfunc, length_rem, offset);
s7comm_decode_ud_ncprg_subfunc(tvbuff_t *tvb,packet_info *pinfo,proto_tree *data_tree,guint8 type,guint8 subfunc,guint32 dlength,guint32 offset)
{
const guint8 *str_filename;
guint32 string_end_offset;
guint32 string_len;
guint32 filelength;
guint32 start_offset;
if (dlength >= 2)
{
if (type == S7COMM_UD_TYPE_REQ && subfunc == S7COMM_NCPRG_FUNCREQUESTDOWNLOAD)
{
proto_tree_add_item_ret_string(data_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, dlength,ENC_ASCII|ENC_NA, pinfo->pool, &str_filename);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str_filename);
offset += dlength;
}
else if (type == S7COMM_UD_TYPE_REQ && subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD)
{
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_unackcount, tvb, offset, 1, ENC_NA);
offset += 1;
dlength -= 1;
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
offset += 1;
dlength -= 1;
proto_tree_add_item_ret_string(data_tree, hf_s7comm_data_blockcontrol_filename, tvb, offset, dlength,ENC_ASCII|ENC_NA, pinfo->pool, &str_filename);
col_append_fstr(pinfo->cinfo, COL_INFO, " File:[%s]", str_filename);
offset += dlength;
}
else if (type == S7COMM_UD_TYPE_RES && subfunc == S7COMM_NCPRG_FUNCREQUESTDOWNLOAD)
{
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_unackcount, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
offset += 1;
}
else if (type == S7COMM_UD_TYPE_IND && (subfunc == S7COMM_NCPRG_FUNCCONTUPLOAD || subfunc == S7COMM_NCPRG_FUNCCONTDOWNLOAD))
{
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_unackcount, tvb, offset, 1, ENC_NA);
offset += 1;
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
offset += 1;
}
else if ((type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_IND) &&(subfunc == S7COMM_NCPRG_FUNCDOWNLOADBLOCK ||subfunc == S7COMM_NCPRG_FUNCUPLOAD ||subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD))
{
start_offset = offset;
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filelength, tvb, offset, 8, ENC_ASCII);
offset += 8;
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filetime, tvb, offset, 16, ENC_ASCII);
offset += 16;
if (dlength > 24)
{
if (subfunc == S7COMM_NCPRG_FUNCDOWNLOADBLOCK || subfunc == S7COMM_NCPRG_FUNCSTARTUPLOAD || subfunc == S7COMM_NCPRG_FUNCUPLOAD)
{
string_end_offset = tvb_find_guint8(tvb, offset, dlength-8-16, 0x0a);
if (string_end_offset > 0)
{
string_len = string_end_offset - offset + 1;
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filepath, tvb, offset, string_len, ENC_ASCII);
offset += string_len;
filelength = dlength - (offset - start_offset);
proto_tree_add_item(data_tree, hf_s7comm_data_ncprg_filedata, tvb, offset, filelength, ENC_NA);
offset += filelength;
}
else
{
}
}
else
{
}
}
else
{
}
}
else
{
proto_tree_add_item(data_tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 2, ENC_NA);
offset += 2;
dlength -= 2;
if (dlength >= 4)
{
proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
}
}
else
{
}
return offset;
}
break;
case S7COMM_UD_FUNCGROUP_DRR:
offset = s7comm_decode_ud_drr_subfunc(next_tvb, data_tree, length_rem, offset);
s7comm_decode_ud_drr_subfunc(tvbuff_t *tvb,proto_tree *tree,guint32 dlength,guint32 offset)
{
if (dlength > 0)
{
proto_tree_add_item(tree, hf_s7comm_data_drr_data, tvb, offset, dlength, ENC_NA);
offset += dlength;
}
else
{
}
return offset;
}
break;
default:
break;
}
}
else
{
}
}
else
{
}
}
else
{
}
return offset;
}
return offset;
}
break;
}
if (errorcode > 0)
{
col_append_fstr(pinfo->cinfo, COL_INFO, " -> Errorcode:[0x%04x]", errorcode);
}
else
{
}
col_set_fence(pinfo->cinfo, COL_INFO);
return TRUE;
}
