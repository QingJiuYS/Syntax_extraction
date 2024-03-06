static gint dissect_ositp_internal(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree,gboolean uses_inactive_subset)
{
int offset = 0;
guint8 li, tpdu, cdt;
gboolean first_tpdu = TRUE;
int new_offset;
gboolean found_ositp = FALSE;
gboolean is_cltp = FALSE;
gboolean subdissector_found = FALSE;
col_clear(pinfo->cinfo, COL_INFO);
while (tvb_offset_exists(tvb, offset))
{
if (!first_tpdu)
{
col_append_str(pinfo->cinfo, COL_INFO, ", ");
expert_add_info(pinfo, NULL, &ei_cotp_multiple_tpdus);
tvb = tvb_new_subset_remaining(tvb, offset);
offset = 0 ;
}
else
{
}
if ((li = tvb_get_guint8(tvb, offset + P_LI)) == 0)
{
col_append_str(pinfo->cinfo, COL_INFO, "Length indicator is zero");
if (!first_tpdu)
{
call_data_dissector( tvb_new_subset_remaining(tvb, offset),pinfo, tree);
}
else
{
}
return found_ositp;
}
else
{
}
tpdu = (tvb_get_guint8(tvb, offset + P_TPDU) >> 4) & 0x0F;
if (tpdu == UD_TPDU)
{
pinfo->current_proto = "CLTP";
}
else
{
}
cdt = tvb_get_guint8(tvb, offset + P_CDT) & 0x0F;
switch (tpdu)
{
case CC_TPDU :
case CR_TPDU :
new_offset = ositp_decode_CR_CC(tvb, offset, li, tpdu, pinfo, tree,uses_inactive_subset, &subdissector_found);
break;
case DR_TPDU :
new_offset = ositp_decode_DR(tvb, offset, li, tpdu, pinfo, tree);
break;
case DT_TPDU :
new_offset = ositp_decode_DT(tvb, offset, li, tpdu, pinfo, tree,uses_inactive_subset, &subdissector_found);
break;
case ED_TPDU :
new_offset = ositp_decode_ED(tvb, offset, li, tpdu, pinfo, tree);
break;
case RJ_TPDU :
new_offset = ositp_decode_RJ(tvb, offset, li, tpdu, cdt, pinfo, tree);
break;
case DC_TPDU :
new_offset = ositp_decode_DC(tvb, offset, li, tpdu, pinfo, tree);
break;
case AK_TPDU :
new_offset = ositp_decode_AK(tvb, offset, li, tpdu, cdt, pinfo, tree);
break;
case EA_TPDU :
new_offset = ositp_decode_EA(tvb, offset, li, tpdu, pinfo, tree);
break;
case ER_TPDU :
new_offset = ositp_decode_ER(tvb, offset, li, tpdu, pinfo, tree);
break;
case UD_TPDU :
new_offset = ositp_decode_UD(tvb, offset, li, tpdu, pinfo, tree,&subdissector_found);
is_cltp = TRUE;
break;
default      :
if (first_tpdu)
{
col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown TPDU type (0x%x)",tpdu);
}
else
{
}
new_offset = -1;
break;
}
if (new_offset == -1)
{
if (!first_tpdu)
{
call_data_dissector( tvb_new_subset_remaining(tvb, offset),pinfo, tree);
}
else
{
}
break;
}
else
{
}
if (first_tpdu)
{
if (!subdissector_found)
{
col_set_str(pinfo->cinfo, COL_PROTOCOL, is_cltp ? "CLTP" : "COTP");
}
else
{
}
found_ositp = TRUE;
}
else
{
}
offset = new_offset;
first_tpdu = FALSE;
}
return found_ositp ? offset : 0;
}
