dissect_tpkt_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gboolean desegment, dissector_handle_t subdissector_handle)
{
proto_item *ti = NULL;
proto_tree *tpkt_tree = NULL;
volatile int offset = 0;
int length_remaining;
int data_len;
volatile int length;
tvbuff_t *volatile next_tvb;
const char *saved_proto;
heur_dtbl_entry_t *hdtbl_entry;
if (desegment)
{
col_clear(pinfo->cinfo, COL_INFO);
}
else
{
}
while (tvb_reported_length_remaining(tvb, offset) != 0)
{
if (tvb_get_guint8(tvb, offset) != 3)
{
if (dissector_try_heuristic(tpkt_heur_subdissector_list, tvb,pinfo, proto_tree_get_root(tree),&hdtbl_entry, NULL))
{
return;
}
else
{
}
col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPKT");
col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
if (tree)
{
ti = proto_tree_add_item(tree, proto_tpkt, tvb,offset, -1, ENC_NA);
tpkt_tree = proto_item_add_subtree(ti, ett_tpkt);
proto_tree_add_item(tpkt_tree, hf_tpkt_continuation_data, tvb, offset, -1, ENC_NA);
}
else
{
}
return;
}
else
{
}
length_remaining = tvb_captured_length_remaining(tvb, offset);
if (desegment && pinfo->can_desegment)
{
if (length_remaining < 4)
{
pinfo->desegment_offset = offset;
pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
return;
}
else
{
}
}
else
{
}
data_len = tvb_get_ntohs(tvb, offset + 2);
if (desegment && pinfo->can_desegment)
{
if (length_remaining < data_len)
{
pinfo->desegment_offset = offset;
pinfo->desegment_len =data_len - length_remaining;
return;
}
else
{
}
}
else
{
}
saved_proto = pinfo->current_proto;
pinfo->current_proto = "TPKT";
col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPKT");
if (!desegment && !pinfo->fragmented)
{
col_add_fstr(pinfo->cinfo, COL_INFO,"TPKT Data length = %u", data_len);
}
else
{
}
if (tree)
{
ti = proto_tree_add_item(tree, proto_tpkt, tvb,offset, 4, ENC_NA);
tpkt_tree = proto_item_add_subtree(ti, ett_tpkt);
proto_item_set_text(ti, "TPKT");
proto_tree_add_item(tpkt_tree, hf_tpkt_version, tvb,offset, 1, ENC_BIG_ENDIAN);
proto_item_append_text(ti, ", Version: 3");
proto_tree_add_item(tpkt_tree, hf_tpkt_reserved, tvb,offset + 1, 1, ENC_BIG_ENDIAN);
proto_tree_add_uint(tpkt_tree, hf_tpkt_length, tvb,offset + 2, 2, data_len);
proto_item_append_text(ti, ", Length: %u", data_len);
}
else
{
}
pinfo->current_proto = saved_proto;
offset += 4;
data_len -= 4;
length = length_remaining - 4;
if (length > data_len)
{
length = data_len;
}
else
{
}
next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, data_len);
TRY
{
call_dissector(subdissector_handle, next_tvb, pinfo,tree);
}
CATCH_NONFATAL_ERRORS
{
show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
}
ENDTRY;
offset += length;
}
}
