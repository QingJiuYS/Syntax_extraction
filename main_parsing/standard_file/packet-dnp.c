dissect_dnp3_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
proto_item  *ti, *tdl, *tc, *hidden_item;
proto_tree  *dnp3_tree, *dl_tree, *field_tree;
int          offset = 0, temp_offset = 0;
gboolean     dl_prm;
guint8       dl_len, dl_ctl, dl_func;
const gchar *func_code_str;
guint16      dl_dst, dl_src, calc_dl_crc;
col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNP 3.0");
col_clear(pinfo->cinfo, COL_INFO);
temp_offset += 2;
dl_len = tvb_get_guint8(tvb, temp_offset);
temp_offset += 1;
dl_ctl = tvb_get_guint8(tvb, temp_offset);
temp_offset += 1;
dl_dst = tvb_get_letohs(tvb, temp_offset);
temp_offset += 2;
dl_src = tvb_get_letohs(tvb, temp_offset);
dl_func = dl_ctl & DNP3_CTL_FUNC;
dl_prm = dl_ctl & DNP3_CTL_PRM;
func_code_str = val_to_str(dl_func, dl_prm ? dnp3_ctl_func_pri_vals : dnp3_ctl_func_sec_vals,"Unknown function (0x%02x)");
col_append_fstr(pinfo->cinfo, COL_INFO, "from %u to %u", dl_src, dl_dst);
col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "len=%u, %s", dl_len, func_code_str);
ti = proto_tree_add_item(tree, proto_dnp3, tvb, offset, -1, ENC_NA);
dnp3_tree = proto_item_add_subtree(ti, ett_dnp3);
dl_tree = proto_tree_add_subtree_format(dnp3_tree, tvb, offset, DNP_HDR_LEN, ett_dnp3_dl, &tdl,"Data Link Layer, Len: %u, From: %u, To: %u, ", dl_len, dl_src, dl_dst);
if (dl_prm)
{
if (dl_ctl & DNP3_CTL_DIR)
{
proto_item_append_text(tdl, "DIR, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_PRM)
{
proto_item_append_text(tdl, "PRM, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_FCB)
{
proto_item_append_text(tdl, "FCB, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_FCV)
{
proto_item_append_text(tdl, "FCV, ");
}
else
{
}
}
else
{
if (dl_ctl & DNP3_CTL_DIR)
{
proto_item_append_text(tdl, "DIR, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_PRM)
{
proto_item_append_text(tdl, "PRM, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_RES)
{
proto_item_append_text(tdl, "RES, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_DFC)
{
proto_item_append_text(tdl, "DFC, ");
}
else
{
}
}
proto_item_append_text(tdl, "%s", func_code_str);
proto_tree_add_item(dl_tree, hf_dnp3_start, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(dl_tree, hf_dnp3_len, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
tc = proto_tree_add_uint_format_value(dl_tree, hf_dnp3_ctl, tvb, offset, 1, dl_ctl,"0x%02x (", dl_ctl);
if (dl_prm)
{
if (dl_ctl & DNP3_CTL_DIR)
{
proto_item_append_text(tc, "DIR, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_PRM)
{
proto_item_append_text(tc, "PRM, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_FCB)
{
proto_item_append_text(tc, "FCB, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_FCV)
{
proto_item_append_text(tc, "FCV, ");
}
else
{
}
}
else
{
if (dl_ctl & DNP3_CTL_DIR)
{
proto_item_append_text(tc, "DIR, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_PRM)
{
proto_item_append_text(tc, "PRM, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_RES)
{
proto_item_append_text(tc, "RES, ");
}
else
{
}
if (dl_ctl & DNP3_CTL_DFC)
{
proto_item_append_text(tc, "DFC, ");
}
else
{
}
}
proto_item_append_text(tc, "%s)", func_code_str );
field_tree = proto_item_add_subtree(tc, ett_dnp3_dl_ctl);
if (dl_prm)
{
proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_prifunc, tvb, offset, 1, ENC_BIG_ENDIAN);
}
else
{
proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_dfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_secfunc, tvb, offset, 1, ENC_BIG_ENDIAN);
}
offset += 1;
proto_tree_add_item(dl_tree, hf_dnp3_dst, tvb, offset, 2, ENC_LITTLE_ENDIAN);
hidden_item = proto_tree_add_item(dl_tree, hf_dnp3_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_item_set_hidden(hidden_item);
offset += 2;
proto_tree_add_item(dl_tree, hf_dnp3_src, tvb, offset, 2, ENC_LITTLE_ENDIAN);
hidden_item = proto_tree_add_item(dl_tree, hf_dnp3_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_item_set_hidden(hidden_item);
offset += 2;
calc_dl_crc = calculateCRCtvb(tvb, 0, DNP_HDR_LEN - 2);
proto_tree_add_checksum(dl_tree, tvb, offset, hf_dnp3_data_hdr_crc,hf_dnp3_data_hdr_crc_status, &ei_dnp3_data_hdr_crc_incorrect,pinfo, calc_dl_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
offset += 2;
if ((dl_func != DL_FUNC_LINK_STAT) && (dl_func != DL_FUNC_STAT_LINK) &&(dl_func != DL_FUNC_RESET_LINK) && (dl_func != DL_FUNC_ACK))
{
proto_tree *data_tree;
proto_item *data_ti;
guint8      tr_ctl, tr_seq;
gboolean    tr_fir, tr_fin;
guint8     *al_buffer, *al_buffer_ptr;
guint8      data_len;
int         data_start = offset;
int         tl_offset;
gboolean    crc_OK = FALSE;
tvbuff_t   *next_tvb;
guint       i;
static int * const transport_flags[] =
{
&hf_dnp3_tr_fin,&hf_dnp3_tr_fir,&hf_dnp3_tr_seq,NULL};
tr_ctl = tvb_get_guint8(tvb, offset);
tr_seq = tr_ctl & DNP3_TR_SEQ;
tr_fir = tr_ctl & DNP3_TR_FIR;
tr_fin = tr_ctl & DNP3_TR_FIN;
tc = proto_tree_add_bitmask(dnp3_tree, tvb, offset, hf_dnp3_tr_ctl, ett_dnp3_tr_ctl, transport_flags, ENC_BIG_ENDIAN);
proto_item_append_text(tc, "(");
if (tr_fir)
{
proto_item_append_text(tc, "FIR, ");
}
else
{
}
if (tr_fin)
{
proto_item_append_text(tc, "FIN, ");
}
else
{
}
proto_item_append_text(tc, "Sequence %u)", tr_seq);
data_tree = proto_tree_add_subtree(dnp3_tree, tvb, offset, -1, ett_dnp3_dl_data, &data_ti, "Data Chunks");
data_len = dl_len - 5;
al_buffer = (guint8 *)wmem_alloc(pinfo->pool, data_len);
al_buffer_ptr = al_buffer;
i = 0;
tl_offset = 1;
while (data_len > 0)
{
guint8        chk_size;
const guint8 *chk_ptr;
proto_tree   *chk_tree;
proto_item   *chk_len_ti;
guint16       calc_crc, act_crc;
chk_size = MIN(data_len, AL_MAX_CHUNK_SIZE);
chk_ptr  = tvb_get_ptr(tvb, offset, chk_size);
memcpy(al_buffer_ptr, chk_ptr + tl_offset, chk_size - tl_offset);
al_buffer_ptr += chk_size - tl_offset;
chk_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, chk_size + 2, ett_dnp3_dl_chunk, NULL, "Data Chunk: %u", i);
proto_tree_add_item(chk_tree, hf_dnp3_data_chunk, tvb, offset, chk_size, ENC_NA);
chk_len_ti = proto_tree_add_uint(chk_tree, hf_dnp3_data_chunk_len, tvb, offset, 0, chk_size);
proto_item_set_generated(chk_len_ti);
offset  += chk_size;
calc_crc = calculateCRC(chk_ptr, chk_size);
proto_tree_add_checksum(chk_tree, tvb, offset, hf_dnp3_data_chunk_crc,hf_dnp3_data_chunk_crc_status, &ei_dnp3_data_chunk_crc_incorrect,pinfo, calc_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
act_crc  = tvb_get_letohs(tvb, offset);
offset  += 2;
crc_OK   = calc_crc == act_crc;
if (!crc_OK)
{
break;
}
else
{
}
data_len -= chk_size;
i++;
tl_offset = 0;
}
proto_item_set_len(data_ti, offset - data_start);
if (crc_OK)
{
tvbuff_t *al_tvb;
gboolean  save_fragmented;
al_tvb = tvb_new_child_real_data(tvb, al_buffer, (guint) (al_buffer_ptr-al_buffer), (gint) (al_buffer_ptr-al_buffer));
save_fragmented = pinfo->fragmented;
static guint al_max_fragments = 60;
static guint al_fragment_aging = 64;
fragment_head *frag_al = NULL;
pinfo->fragmented = TRUE;
if (!pinfo->fd->visited)
{
frag_al = fragment_add_seq_single_aging(&al_reassembly_table,al_tvb, 0, pinfo, tr_seq, NULL,tvb_reported_length(al_tvb),tr_fir, tr_fin,al_max_fragments, al_fragment_aging);
}
else
{
frag_al = fragment_get_reassembled_id(&al_reassembly_table, pinfo, tr_seq);
}
next_tvb = process_reassembled_data(al_tvb, 0, pinfo,"Reassembled DNP 3.0 Application Layer message", frag_al, &dnp3_frag_items,NULL, dnp3_tree);
if (frag_al)
{
if (pinfo->num == frag_al->reassembled_in && pinfo->curr_layer_num == frag_al->reas_in_layer_num)
{
dissect_dnp3_al(next_tvb, pinfo, dnp3_tree);
dissect_dnp3_al(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
guint8        al_ctl, al_seq, al_func, al_class = 0, i;
guint16       bytes, obj_type = 0;
guint         data_len = 0, offset = 0;
proto_item   *ti, *tc;
proto_tree   *al_tree, *robj_tree;
const gchar  *func_code_str, *obj_type_str;
nstime_t      al_cto;
static int * const control_flags[] =
{
&hf_dnp3_al_fir,&hf_dnp3_al_fin,&hf_dnp3_al_con,&hf_dnp3_al_uns,&hf_dnp3_al_seq,NULL};
nstime_set_zero (&al_cto);
data_len = tvb_captured_length(tvb);
al_ctl = tvb_get_guint8(tvb, offset);
al_seq = al_ctl & DNP3_AL_SEQ;
al_func = tvb_get_guint8(tvb, (offset+1));
func_code_str = val_to_str_ext(al_func, &dnp3_al_func_vals_ext, "Unknown function (0x%02x)");
col_clear(pinfo->cinfo, COL_INFO);
col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, func_code_str);
col_set_fence(pinfo->cinfo, COL_INFO);
al_tree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_dnp3_al, &ti, "Application Layer: (");
if (al_ctl & DNP3_AL_FIR)
{
proto_item_append_text(ti, "FIR, ");
}
else
{
}
if (al_ctl & DNP3_AL_FIN)
{
proto_item_append_text(ti, "FIN, ");
}
else
{
}
if (al_ctl & DNP3_AL_CON)
{
proto_item_append_text(ti, "CON, ");
}
else
{
}
if (al_ctl & DNP3_AL_UNS)
{
proto_item_append_text(ti, "UNS, ");
}
else
{
}
proto_item_append_text(ti, "Sequence %u, %s)", al_seq, func_code_str);
tc = proto_tree_add_bitmask(al_tree, tvb, offset, hf_dnp3_al_ctl, ett_dnp3_al_ctl, control_flags, ENC_BIG_ENDIAN);
proto_item_append_text(tc, "(");
if (al_ctl & DNP3_AL_FIR)
{
proto_item_append_text(tc, "FIR, ");
}
else
{
}
if (al_ctl & DNP3_AL_FIN)
{
proto_item_append_text(tc, "FIN, ");
}
else
{
}
if (al_ctl & DNP3_AL_CON)
{
proto_item_append_text(tc, "CON, ");
}
else
{
}
if (al_ctl & DNP3_AL_UNS)
{
proto_item_append_text(tc, "UNS, ");
}
else
{
}
proto_item_append_text(tc, "Sequence %u)", al_seq);
offset += 1;
proto_tree_add_uint_format(al_tree, hf_dnp3_al_func, tvb, offset, 1, al_func,"Function Code: %s (0x%02x)", func_code_str, al_func);
offset += 1;
switch (al_func)
{
case AL_FUNC_CONFIRM:
if (data_len > 2)
{
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "CONFIRM Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);
}
}
else
{
}
break;
case AL_FUNC_READ:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "READ Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);
switch(obj_type)
{
case AL_OBJ_CLASS0:
case AL_OBJ_CLASS1:
case AL_OBJ_CLASS2:
case AL_OBJ_CLASS3:
al_class |= (1 << ((obj_type & 0x0f) - 1));
break;
default:
obj_type_str = val_to_str_ext_const((obj_type & 0xFF00), &dnp3_al_read_obj_vals_ext, "Unknown Object Type");
col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, obj_type_str);
break;
}
}
if (al_class != 0)
{
col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Class ");
for (i = 0; i < 4; i++)
{
if (al_class & (1 << i))
{
col_append_fstr(pinfo->cinfo, COL_INFO, "%u", i);
}
else
{
}
}
}
else
{
}
break;
case AL_FUNC_WRITE:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "WRITE Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
obj_type_str = val_to_str_ext_const((obj_type & 0xFF00), &dnp3_al_write_obj_vals_ext, "Unknown Object Type");
col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, obj_type_str);
}
break;
case AL_FUNC_SELECT:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "SELECT Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_OPERATE:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "OPERATE Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_DIROP:
case AL_FUNC_DIROPNACK:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "DIRECT OPERATE Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_FRZ:
case AL_FUNC_FRZNACK:
case AL_FUNC_FRZCLR:
case AL_FUNC_FRZCLRNACK:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Freeze Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);
}
break;
case AL_FUNC_ENSPMSG:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Enable Spontaneous Msg's Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_DISSPMSG:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Disable Spontaneous Msg's Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_DELAYMST:
break;
case AL_FUNC_OPENFILE:
case AL_FUNC_CLOSEFILE:
case AL_FUNC_DELETEFILE:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "File Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_AUTHREQ:
case AL_FUNC_AUTHERR:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Authentication Request Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_RESPON:
case AL_FUNC_UNSOLI:
case AL_FUNC_AUTHRESP:
dnp3_al_process_iin(tvb, pinfo, offset, al_tree);
offset += 2;
bytes = tvb_reported_length_remaining(tvb, offset);
if (bytes > 0)
{
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "RESPONSE Data Objects");
while (offset <= (data_len-2))
{
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
}
else
{
}
default:
break;
}
return 0;
}
}
else
{
col_set_fence(pinfo->cinfo, COL_INFO);
col_append_fstr(pinfo->cinfo, COL_INFO," (Application Layer fragment %u, reassembled in packet %u)",tr_seq, frag_al->reassembled_in);
proto_tree_add_item(dnp3_tree, hf_al_frag_data, al_tvb, 0, -1, ENC_NA);
}
}
else
{
col_append_fstr(pinfo->cinfo, COL_INFO," (Application Layer Unreassembled fragment %u)",tr_seq);
proto_tree_add_item(dnp3_tree, hf_al_frag_data, al_tvb, 0, -1, ENC_NA);
}
pinfo->fragmented = save_fragmented;
}
else
{
wmem_free(pinfo->pool, al_buffer);
next_tvb = NULL;
}
}
else
{
}
proto_item_set_len(ti, offset);
return offset;
}
