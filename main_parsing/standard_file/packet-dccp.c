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
if (dccp_summary_in_tree)
{
proto_item_append_text(dccp_item, ", Src Port: %s, Dst Port: %s",port_with_resolution_to_str(pinfo->pool, PT_DCCP, dccph->sport),port_with_resolution_to_str(pinfo->pool, PT_DCCP, dccph->dport));
}
else
{
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
if (dccp_check_checksum && !pinfo->fragmented && len >= csum_coverage_len)
{
SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data, pinfo->src.len);
SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data, pinfo->dst.len);
switch (pinfo->src.type)
{
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
else
{
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
if (dccp_summary_in_tree)
{
proto_item_append_text(dccp_item, " [%s]",val_to_str_const(dccph->type, dccp_packet_type_vals,"Unknown Type"));
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]",val_to_str_const(dccph->type, dccp_packet_type_vals,"Unknown Type"));
dccph->x = tvb_get_guint8(tvb, offset) & 0x01;
proto_tree_add_boolean(dccp_tree, hf_dccp_x, tvb, offset, 1,dccph->x);
offset += 1;
if (dccph->x)
{
if (advertised_dccp_header_len < DCCP_GEN_HDR_LEN_X)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u)",advertised_dccp_header_len, DCCP_GEN_HDR_LEN_X);
return tvb_reported_length(tvb);
}
else
{
}
dccph->reserved2 = tvb_get_guint8(tvb, offset);
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_res2, tvb, offset, 1,dccph->reserved2);
proto_item_set_hidden(hidden_item);
offset += 1;
dccph->seq = tvb_get_ntoh48(tvb, offset);
if((dccp_relative_seq) && (dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET))
{
seq = dccph->seq - dccpd->fwd->base_seq;
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_seq, tvb, offset, 6,seq, "%" PRIu64 "    (relative sequence number)", seq);
}
else
{
seq = dccph->seq;
}
proto_tree_add_uint64(dccp_tree, hf_dccp_seq_abs, tvb, offset, 6, dccph->seq);
offset += 6;
}
else
{
if (advertised_dccp_header_len < DCCP_GEN_HDR_LEN_NO_X)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u)",advertised_dccp_header_len, DCCP_GEN_HDR_LEN_NO_X);
return tvb_reported_length(tvb);
}
else
{
}
dccph->seq = tvb_get_ntoh24(tvb, offset);
proto_tree_add_uint64(dccp_tree, hf_dccp_seq, tvb, offset, 3, dccph->seq);
if((dccp_relative_seq) && (dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET))
{
seq = (dccph->seq - dccpd->fwd->base_seq) & 0xffffff;
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_seq, tvb, offset, 3,seq, "%" PRIu64 "    (relative sequence number)", seq);
}
else
{
seq = dccph->seq;
}
offset += 3;
}
if (dccp_summary_in_tree)
{
proto_item_append_text(dccp_item, " Seq=%" PRIu64, seq);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%" PRIu64, seq);
switch (dccph->type)
{
case 0x0:
case 0xA:
if (advertised_dccp_header_len < offset + 4)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 4,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
else
{
}
dccph->service_code = tvb_get_ntohl(tvb, offset);
if (tree)
{
proto_tree_add_uint(dccp_tree, hf_dccp_service_code, tvb, offset, 4,dccph->service_code);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%s)",val_to_str(dccph->service_code, dccp_service_code_vals, "Unknown (%u)"));
offset += 4;
if( !(dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET) )
{
dccpd->fwd->base_seq = dccph->seq;
dccpd->fwd->static_flags |= DCCP_S_BASE_SEQ_SET;
}
else
{
}
break;
case 0x1:
if (advertised_dccp_header_len < offset + 12)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for Response",advertised_dccp_header_len, offset + 12);
return tvb_reported_length(tvb);
}
else
{
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree)
{
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
else
{
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
ack = dccph->ack - dccpd->rev->base_seq;
}
else
{
ack = dccph->ack;
}
if (tree)
{
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6, ack);
}
else
{
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 2, 6, dccph->ack);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
dccph->service_code = tvb_get_ntohl(tvb, offset);
if (tree)
{
proto_tree_add_uint(dccp_tree, hf_dccp_service_code, tvb, offset, 4,dccph->service_code);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%s)",val_to_str(dccph->service_code, dccp_service_code_vals, "Unknown (%u)"));
offset += 4;
if( !(dccpd->fwd->static_flags & DCCP_S_BASE_SEQ_SET) )
{
dccpd->fwd->base_seq = dccph->seq;
dccpd->fwd->static_flags |= DCCP_S_BASE_SEQ_SET;
}
else
{
}
break;
case 0x2:
break;
case 0x3:
case 0x4:
if (dccph->x)
{
if (advertised_dccp_header_len < offset + 8)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 8,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
else
{
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree)
{
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset,2, dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
else
{
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
ack = dccph->ack - dccpd->rev->base_seq;
}
else
{
ack = dccph->ack;
}
if (tree)
{
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
else
{
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 2, 6, dccph->ack);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
}
else
{
if (advertised_dccp_header_len < offset + 4)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 4,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
else
{
}
dccph->ack_reserved = tvb_get_guint8(tvb, offset);
if (tree)
{
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset,1, dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
else
{
}
dccph->ack = tvb_get_guint8(tvb, offset + 1);
dccph->ack <<= 16;
dccph->ack += tvb_get_ntohs(tvb, offset + 2);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
ack = (dccph->ack - dccpd->rev->base_seq) & 0xffffff;
}
else
{
ack = dccph->ack;
}
if (tree)
{
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 1, 3,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
else
{
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 1, 3, dccph->ack);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 4;
}
break;
case 0x7:
if (advertised_dccp_header_len < offset + 4)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for Reset",advertised_dccp_header_len, offset + 4);
return tvb_reported_length(tvb);
}
else
{
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree)
{
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
else
{
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
ack = (dccph->ack - dccpd->rev->base_seq) & 0xffffff;
}
else
{
ack = dccph->ack;
}
if (tree)
{
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 1, 3,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
else
{
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 1, 3, dccph->ack);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
dccph->reset_code = tvb_get_guint8(tvb, offset);
dccph->data1 = tvb_get_guint8(tvb, offset + 1);
dccph->data2 = tvb_get_guint8(tvb, offset + 2);
dccph->data3 = tvb_get_guint8(tvb, offset + 3);
if (tree)
{
proto_tree_add_uint(dccp_tree, hf_dccp_reset_code, tvb, offset, 1,dccph->reset_code);
proto_tree_add_uint(dccp_tree, hf_dccp_data1, tvb, offset + 1, 1,dccph->data1);
proto_tree_add_uint(dccp_tree, hf_dccp_data2, tvb, offset + 2, 1,dccph->data2);
proto_tree_add_uint(dccp_tree, hf_dccp_data3, tvb, offset + 3, 1,dccph->data3);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (code=%s)",val_to_str_const(dccph->reset_code, dccp_reset_code_vals,"Unknown"));
offset += 4;
break;
case 0x5:
case 0x6:
case 0x8:
case 0x9:
if (advertised_dccp_header_len < offset + 8)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is smaller than the minimum (%u) for %s",advertised_dccp_header_len, offset + 8,val_to_str(dccph->type, dccp_packet_type_vals, "Unknown (%u)"));
return tvb_reported_length(tvb);
}
else
{
}
dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
if (tree)
{
hidden_item =proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,dccph->ack_reserved);
proto_item_set_hidden(hidden_item);
}
else
{
}
dccph->ack = tvb_get_ntohs(tvb, offset + 2);
dccph->ack <<= 32;
dccph->ack += tvb_get_ntohl(tvb, offset + 4);
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
ack = (dccph->ack - dccpd->rev->base_seq) & 0xffffff;
}
else
{
ack = dccph->ack;
}
if (tree)
{
if((dccp_relative_seq) && (dccpd->rev->static_flags & DCCP_S_BASE_SEQ_SET))
{
proto_tree_add_uint64_format_value(dccp_tree, hf_dccp_ack, tvb, offset + 1, 3,ack, "%" PRIu64 "    (relative acknowledgement number)", ack);
}
else
{
}
proto_tree_add_uint64(dccp_tree, hf_dccp_ack_abs, tvb, offset + 1, 3, dccph->ack);
}
else
{
}
col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", ack);
offset += 8;
break;
default:
expert_add_info(pinfo, dccp_item, &ei_dccp_packet_type_reserved);
return tvb_reported_length(tvb);
}
if (advertised_dccp_header_len > DCCP_HDR_LEN_MAX)
{
expert_add_info_format(pinfo, offset_item, &ei_dccp_advertised_header_length_bad,"Advertised header length (%u) is larger than the maximum (%u)",advertised_dccp_header_len, DCCP_HDR_LEN_MAX);
return tvb_reported_length(tvb);
}
else
{
}
if (advertised_dccp_header_len > offset)
{
options_len = advertised_dccp_header_len - offset;
if (dccp_tree)
{
dccp_item =proto_tree_add_none_format(dccp_tree, hf_dccp_options, tvb,offset,options_len, "Options: (%u byte%s)",options_len,plurality(options_len, "", "s"));
dccp_options_tree = proto_item_add_subtree(dccp_item,ett_dccp_options);
}
else
{
}
dissect_options(tvb, pinfo, dccp_options_tree, tree, dccph, offset,offset + options_len);
dissect_options(tvbuff_t *tvb, packet_info *pinfo,proto_tree *dccp_options_tree, proto_tree *tree _U_,e_dccphdr *dccph _U_,int offset_start,int offset_end)
{
int         offset      = offset_start;
guint8      option_type = 0;
guint8      option_len  = 0;
guint32     p;
guint8      mp_option_type = 0;
proto_item *option_item;
proto_tree *option_tree;
proto_item *mp_option_sub_item;
proto_tree *mp_option_sub_tree;
while (offset < offset_end)
{
option_type = tvb_get_guint8(tvb, offset);
option_item =proto_tree_add_uint(dccp_options_tree, hf_dccp_option_type, tvb,offset,1,option_type);
if (option_type >= 32)
{
option_len = tvb_get_guint8(tvb, offset+1);
if (option_len < 2)
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Option length incorrect, must be >= 2");
return;
}
else
{
}
proto_item_set_len(option_item, option_len);
offset += 2;
option_len -= 2;
}
else
{
option_len = 1;
}
option_tree = proto_item_add_subtree(option_item, ett_dccp_options_item);
switch (option_type)
{
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
dissect_feature_options(proto_tree *dccp_options_tree, tvbuff_t *tvb,int offset, guint8 option_len)
{
guint8      feature_number = tvb_get_guint8(tvb, offset);
proto_item *dccp_item;
proto_tree *feature_tree;
int         i;
feature_tree =proto_tree_add_subtree_format(dccp_options_tree, tvb, offset, option_len,ett_dccp_feature, &dccp_item, "%s(",rval_to_str_const(feature_number, dccp_feature_numbers_rvals, "Unknown feature number"));
if (feature_number != 10)
{
proto_tree_add_uint(feature_tree, hf_dccp_feature_number, tvb,offset, 1, feature_number);
}
else
{
proto_tree_add_item(feature_tree, hf_mpdccp_version, tvb,offset, option_len, ENC_BIG_ENDIAN);
}
offset++;
option_len--;
switch (feature_number)
{
case 1:
case 2:
case 4:
case 6:
case 7:
case 8:
case 9:
case 192:
for (i = 0; i < option_len; i++)
{
proto_item_append_text(dccp_item, "%s %d", i ? "," : "",tvb_get_guint8(tvb,offset + i));
}
break;
case 3:
case 5:
if (option_len > 0)
{
proto_item_append_text(dccp_item, " %" PRIu64,dccp_ntoh_var(tvb, offset, option_len));
}
else
{
}
break;
case 10:
for (i = 0; i < option_len; i++)
{
proto_item_append_text(dccp_item, "%s %d", i ? "," : "", feature_number);
}
break;
default:
proto_item_append_text(dccp_item, "%d", feature_number);
break;
}
proto_item_append_text(dccp_item, ")");
}
break;
case 36:
proto_tree_add_item(option_tree, hf_dccp_init_cookie, tvb, offset, option_len, ENC_NA);
break;
case 37:
if (option_len > 6)
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"NDP Count too long (max 6 bytes)");
}
else
{
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
if (option_len == 4)
{
proto_tree_add_item(option_tree, hf_dccp_timestamp, tvb,offset, 4, ENC_BIG_ENDIAN);
}
else
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Timestamp too long [%u != 4]", option_len);
}
break;
case 42:
if (option_len == 4)
{
proto_tree_add_item(option_tree, hf_dccp_timestamp_echo,tvb, offset, 4, ENC_BIG_ENDIAN);
}
else if (option_len == 6)
{
proto_tree_add_item(option_tree, hf_dccp_timestamp_echo,tvb, offset, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset + 4, 2, ENC_BIG_ENDIAN);
}
else if (option_len == 8)
{
proto_tree_add_item(option_tree, hf_dccp_timestamp_echo,tvb, offset, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset + 4, 4, ENC_BIG_ENDIAN);
}
else
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong Timestamp Echo length");
}
break;
case 43:
if (option_len == 2)
{
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset, 2, ENC_BIG_ENDIAN);
}
else if (option_len == 4)
{
proto_tree_add_item(option_tree, hf_dccp_elapsed_time,tvb, offset, 4, ENC_BIG_ENDIAN);
}
else
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong Elapsed Time length");
}
break;
case 44:
if (option_len == 4)
{
proto_tree_add_item(option_tree, hf_dccp_data_checksum,tvb, offset, 4, ENC_BIG_ENDIAN);
}
else
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong Data checksum length");
}
break;
case 46:
mp_option_type = tvb_get_guint8(tvb, offset);
option_len -= 1;
switch (mp_option_type)
{
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
if (option_len == 9)
{
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_join_id, tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_join_token, tvb, offset+1, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_join_nonce, tvb, offset+5, 4, ENC_BIG_ENDIAN);
}
else
{
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
if (option_len > 8 && option_len < 69)
{
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_key_type, tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_key_key, tvb, offset+1, option_len-1, ENC_NA);
}
else
{
mp_option_sub_item = proto_tree_add_item(mp_option_sub_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [8 < %u < 69]", option_len);
}
break;
case 4:
if (option_len == 6)
{
offset += 1;
proto_tree_add_item(option_tree, hf_mpdccp_seq, tvb, offset, 6, ENC_BIG_ENDIAN);
}
else
{
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_seq, tvb, offset, option_len, ENC_BIG_ENDIAN);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 6]", option_len);
}
break;
case 5:
if (option_len == 20)
{
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_hmac, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_hmac_sha, tvb, offset, 20, ENC_NA);
}
else
{
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_hmac, tvb, offset, option_len, ENC_BIG_ENDIAN);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 20]", option_len);
}
break;
case 6:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_rtt, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
if (option_len == 9)
{
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_rtt_type,tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_rtt_value,tvb, offset+1, 4, ENC_BIG_ENDIAN);
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_rtt_age,tvb, offset+5, 4, ENC_BIG_ENDIAN);
}
else
{
mp_option_sub_item = proto_tree_add_item(mp_option_sub_tree, hf_dccp_option_data, tvb, offset, option_len, ENC_NA);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 9]", option_len);
}
break;
case 7:
mp_option_sub_item=proto_tree_add_item(option_tree,hf_mpdccp_addaddr,tvb,offset,1,ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
switch (option_len)
{
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
if (option_len == 1)
{
mp_option_sub_item=proto_tree_add_item(option_tree,hf_mpdccp_removeaddr,tvb,offset,1,ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
proto_tree_add_item(mp_option_sub_tree,hf_mpdccp_addrid,tvb,offset,1,ENC_BIG_ENDIAN);
}
else
{
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_removeaddr, tvb, offset, option_len, ENC_BIG_ENDIAN);
expert_add_info_format(pinfo, mp_option_sub_item, &ei_dccp_option_len_bad,"Wrong Data checksum length, [%u != 1]", option_len);
}
break;
case 9:
mp_option_sub_item = proto_tree_add_item(option_tree, hf_mpdccp_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
mp_option_sub_tree = proto_item_add_subtree(mp_option_sub_item, ett_dccp_options_item);
offset += 1;
if (option_len == 1)
{
proto_tree_add_item(mp_option_sub_tree, hf_mpdccp_prio_value, tvb, offset, 1, ENC_BIG_ENDIAN);
}
else
{
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
if (option_len == 4)
{
p = tvb_get_ntohl(tvb, offset);
if (p == 0xFFFFFFFF)
{
proto_tree_add_uint_format_value(option_tree, hf_dccp_ccid3_loss_event_rate, tvb, offset,option_len, p, "0 (or max)");
}
else
{
proto_tree_add_uint(option_tree, hf_dccp_ccid3_loss_event_rate, tvb, offset, option_len, p);
}
}
else
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong CCID3 Loss Event Rate length");
}
break;
case 193:
proto_tree_add_item(dccp_options_tree, hf_dccp_ccid3_loss_intervals, tvb, offset, option_len, ENC_NA);
break;
case 194:
if (option_len == 4)
{
proto_tree_add_uint_format_value(option_tree, hf_dccp_ccid3_receive_rate, tvb, offset, option_len,tvb_get_ntohl(tvb, offset), "%u bytes/sec",tvb_get_ntohl(tvb, offset));
}
else
{
expert_add_info_format(pinfo, option_item, &ei_dccp_option_len_bad,"Wrong CCID3 Receive Rate length");
}
break;
default:
if (((option_type >= 47) && (option_type <= 127)) ||((option_type >= 3) && (option_type <= 31)))
{
proto_tree_add_item(option_tree, hf_dccp_option_reserved, tvb, offset, option_len, ENC_NA);
break;
}
else
{
}
if (option_type >= 128)
{
proto_tree_add_bytes_format(option_tree, hf_dccp_ccid_option_data, tvb, offset, option_len,NULL, "CCID option %d", option_type);
break;
}
else
{
}
proto_tree_add_item(option_tree, hf_dccp_option_unknown, tvb, offset, option_len, ENC_NA);
break;
}
offset += option_len;
}
}
}
else
{
}
offset += options_len;
proto_item_set_end(dccp_item, tvb, offset);
tap_queue_packet(dccp_tap, pinfo, dccph);
if (!pinfo->flags.in_error_pkt || tvb_reported_length_remaining(tvb, offset) > 0)
{
decode_dccp_ports(tvb, offset, pinfo, tree, dccph->sport, dccph->dport);
}
else
{
}
return tvb_reported_length(tvb);
}
