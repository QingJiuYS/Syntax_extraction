#include "config.h"
#include <math.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-tcp.h"
#include "packet-udp.h"
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/crc16-tvb.h>
#include <wsutil/crc16.h>
#include <wsutil/str_util.h>
#include "packet-tls.h"
#define DNP_HDR_LEN     10
#define TCP_PORT_DNP    20000
#define UDP_PORT_DNP    20000
#define TCP_PORT_DNP_TLS    19999
#define DNP3_CTL_DIR    0x80
#define DNP3_CTL_PRM    0x40
#define DNP3_CTL_FCB    0x20
#define DNP3_CTL_FCV    0x10
#define DNP3_CTL_RES    0x20
#define DNP3_CTL_DFC    0x10
#define DNP3_CTL_FUNC   0x0f
#define DNP3_TR_FIR     0x40
#define DNP3_TR_FIN     0x80
#define DNP3_TR_SEQ     0x3f
#define AL_MAX_CHUNK_SIZE 16
#define DL_FUNC_RESET_LINK  0x00
#define DL_FUNC_RESET_PROC  0x01
#define DL_FUNC_TEST_LINK   0x02
#define DL_FUNC_USER_DATA   0x03
#define DL_FUNC_UNC_DATA    0x04
#define DL_FUNC_LINK_STAT   0x09
#define DL_FUNC_ACK         0x00
#define DL_FUNC_NACK        0x01
#define DL_FUNC_STAT_LINK   0x0B
#define DL_FUNC_NO_FUNC     0x0E
#define DL_FUNC_NOT_IMPL    0x0F
#define DNP3_AL_UNS   0x10
#define DNP3_AL_CON   0x20
#define DNP3_AL_FIN   0x40
#define DNP3_AL_FIR   0x80
#define DNP3_AL_SEQ   0x0f
#define DNP3_AL_FUNC  0xff
#define AL_FUNC_CONFIRM    0x00
#define AL_FUNC_READ       0x01
#define AL_FUNC_WRITE      0x02
#define AL_FUNC_SELECT     0x03
#define AL_FUNC_OPERATE    0x04
#define AL_FUNC_DIROP      0x05
#define AL_FUNC_DIROPNACK  0x06
#define AL_FUNC_FRZ        0x07
#define AL_FUNC_FRZNACK    0x08
#define AL_FUNC_FRZCLR     0x09
#define AL_FUNC_FRZCLRNACK 0x0A
#define AL_FUNC_FRZT       0x0B
#define AL_FUNC_FRZTNACK   0x0C
#define AL_FUNC_COLDRST    0x0D
#define AL_FUNC_WARMRST    0x0E
#define AL_FUNC_INITDATA   0x0F
#define AL_FUNC_INITAPP    0x10
#define AL_FUNC_STARTAPP   0x11
#define AL_FUNC_STOPAPP    0x12
#define AL_FUNC_SAVECFG    0x13
#define AL_FUNC_ENSPMSG    0x14
#define AL_FUNC_DISSPMSG   0x15
#define AL_FUNC_ASSIGNCL   0x16
#define AL_FUNC_DELAYMST   0x17
#define AL_FUNC_RECCT      0x18
#define AL_FUNC_OPENFILE   0x19
#define AL_FUNC_CLOSEFILE  0x1A
#define AL_FUNC_DELETEFILE 0x1B
#define AL_FUNC_GETFILEINF 0x1C
#define AL_FUNC_AUTHFILE   0x1D
#define AL_FUNC_ABORTFILE  0x1E
#define AL_FUNC_ACTCNF     0x1F
#define AL_FUNC_AUTHREQ    0x20
#define AL_FUNC_AUTHERR    0x21
#define AL_FUNC_RESPON     0x81
#define AL_FUNC_UNSOLI     0x82
#define AL_FUNC_AUTHRESP   0x83
#define AL_IIN_BMSG        0x0100
#define AL_IIN_CLS1D       0x0200
#define AL_IIN_CLS2D       0x0400
#define AL_IIN_CLS3D       0x0800
#define AL_IIN_TSR         0x1000
#define AL_IIN_DOL         0x2000
#define AL_IIN_DT          0x4000
#define AL_IIN_RST         0x8000
#define AL_IIN_FCNI        0x0001
#define AL_IIN_OBJU        0x0002
#define AL_IIN_PIOOR       0x0004
#define AL_IIN_EBO         0x0008
#define AL_IIN_OAE         0x0010
#define AL_IIN_CC          0x0020
#define AL_OBJQ_PREFIX         0x70
#define AL_OBJQ_RANGE          0x0F
#define AL_OBJQL_PREFIX_NI     0x00
#define AL_OBJQL_PREFIX_1O     0x01
#define AL_OBJQL_PREFIX_2O     0x02
#define AL_OBJQL_PREFIX_4O     0x03
#define AL_OBJQL_PREFIX_1OS    0x04
#define AL_OBJQL_PREFIX_2OS    0x05
#define AL_OBJQL_PREFIX_4OS    0x06
#define AL_OBJQL_IDX11_1OIS    0x01
#define AL_OBJQL_IDX11_2OIS    0x02
#define AL_OBJQL_IDX11_4OIS    0x03
#define AL_OBJQL_RANGE_SSI8    0x00
#define AL_OBJQL_RANGE_SSI16   0x01
#define AL_OBJQL_RANGE_SSI32   0x02
#define AL_OBJQL_RANGE_AA8     0x03
#define AL_OBJQL_RANGE_AA16    0x04
#define AL_OBJQL_RANGE_AA32    0x05
#define AL_OBJQL_RANGE_R0      0x06
#define AL_OBJQL_RANGE_SF8     0x07
#define AL_OBJQL_RANGE_SF16    0x08
#define AL_OBJQL_RANGE_SF32    0x09
#define AL_OBJQL_RANGE_FF      0x0B
#define AL_OBJ_GRP_MASK 0xFF00
#define AL_OBJ_VAR_MASK 0x00FF
#define AL_OBJ_GROUP(GV)        (((GV) & AL_OBJ_GRP_MASK) >> 8)
#define AL_OBJ_VARIATION(GV)    ((GV) & AL_OBJ_VAR_MASK)
#define AL_DATA_TYPE_NONE         0x0
#define AL_DATA_TYPE_VSTR         0x1
#define AL_DATA_TYPE_UINT         0x2
#define AL_DATA_TYPE_INT          0x3
#define AL_DATA_TYPE_FLT          0x4
#define AL_DATA_TYPE_OSTR         0x5
#define AL_DATA_TYPE_BSTR         0x6
#define AL_DATA_TYPE_TIME         0x7
#define AL_DATA_TYPE_UNCD         0x8
#define AL_DATA_TYPE_U8BS8LIST    0xFE
#define AL_DATA_TYPE_U8BS8EXLIST  0xFF
#define AL_OBJ_DA_GRP           0x0000
#define AL_OBJ_DA_CFG_ID        0x00C4
#define AL_OBJ_DA_CFG_VER       0x00C5
#define AL_OBJ_DA_CFG_BLD_DATE  0x00C6
#define AL_OBJ_DA_CFG_CHG_DATE  0x00C7
#define AL_OBJ_DA_CFG_SIG       0x00C8
#define AL_OBJ_DA_CFG_SIG_ALG   0x00C9
#define AL_OBJ_DA_MRID          0x00CA
#define AL_OBJ_DA_ALT           0x00CB
#define AL_OBJ_DA_LONG          0x00CC
#define AL_OBJ_DA_LAT           0x00CD
#define AL_OBJ_DA_SEC_OP        0x00CE
#define AL_OBJ_DA_PRM_OP        0x00CF
#define AL_OBJ_DA_SYS_NAME      0x00D0
#define AL_OBJ_DA_SEC_VER       0x00D1
#define AL_OBJ_DA_SEC_STAT      0x00D2
#define AL_OBJ_DA_USR_ATTR      0x00D3
#define AL_OBJ_DA_MSTR_DSP      0x00D4
#define AL_OBJ_DA_OS_DSP        0x00D5
#define AL_OBJ_DA_MSTR_DS       0x00D6
#define AL_OBJ_DA_OS_DS         0x00D7
#define AL_OBJ_DA_BO_REQ        0x00D8
#define AL_OBJ_DA_LOC_TA        0x00D9
#define AL_OBJ_DA_DUR_TA        0x00DA
#define AL_OBJ_DA_AO_EVT        0x00DB
#define AL_OBJ_DA_MAX_AO        0x00DC
#define AL_OBJ_DA_NUM_AO        0x00DD
#define AL_OBJ_DA_BO_EVT        0x00DE
#define AL_OBJ_DA_MAX_BO        0x00DF
#define AL_OBJ_DA_NUM_BO        0x00E0
#define AL_OBJ_DA_FCTR_EVT      0x00E1
#define AL_OBJ_DA_FCTR          0x00E2
#define AL_OBJ_DA_CTR_EVT       0x00E3
#define AL_OBJ_DA_MAX_CTR       0x00E4
#define AL_OBJ_DA_NUM_CTR       0x00E5
#define AL_OBJ_DA_AIF           0x00E6
#define AL_OBJ_DA_AI_EVT        0x00E7
#define AL_OBJ_DA_MAX_AI        0x00E8
#define AL_OBJ_DA_NUM_AI        0x00E9
#define AL_OBJ_DA_2BI_EVT       0x00EA
#define AL_OBJ_DA_MAX_2BI       0x00EB
#define AL_OBJ_DA_NUM_2BI       0x00EC
#define AL_OBJ_DA_BI_EVT        0x00ED
#define AL_OBJ_DA_MAX_BI        0x00EE
#define AL_OBJ_DA_NUM_BI        0x00EF
#define AL_OBJ_DA_MXTX_FR       0x00F0
#define AL_OBJ_DA_MXRX_FR       0x00F1
#define AL_OBJ_DA_SWVER         0x00F2
#define AL_OBJ_DA_HWVER         0x00F3
#define AL_OBJ_DA_OWNER         0x00F4
#define AL_OBJ_DA_LOC           0x00F5
#define AL_OBJ_DA_ID            0x00F6
#define AL_OBJ_DA_DEVNAME       0x00F7
#define AL_OBJ_DA_SERNUM        0x00F8
#define AL_OBJ_DA_CONF          0x00F9
#define AL_OBJ_DA_PROD          0x00FA
#define AL_OBJ_DA_MFG           0x00FC
#define AL_OBJ_DA_ALL           0x00FE
#define AL_OBJ_DA_LVAR          0x00FF
#define AL_OBJ_BI_ALL      0x0100
#define AL_OBJ_BI_1BIT     0x0101
#define AL_OBJ_BI_STAT     0x0102
#define AL_OBJ_BIC_ALL     0x0200
#define AL_OBJ_BIC_NOTIME  0x0201
#define AL_OBJ_BIC_TIME    0x0202
#define AL_OBJ_BIC_RTIME   0x0203
#define AL_OBJ_2BI_ALL     0x0300
#define AL_OBJ_2BI_NF      0x0301
#define AL_OBJ_2BI_STAT    0x0302
#define AL_OBJ_2BIC_ALL    0x0400
#define AL_OBJ_2BIC_NOTIME 0x0401
#define AL_OBJ_2BIC_TIME   0x0402
#define AL_OBJ_2BIC_RTIME  0x0403
#define AL_OBJ_BI_FLAG0    0x0001
#define AL_OBJ_BI_FLAG1    0x0002
#define AL_OBJ_BI_FLAG2    0x0004
#define AL_OBJ_BI_FLAG3    0x0008
#define AL_OBJ_BI_FLAG4    0x0010
#define AL_OBJ_BI_FLAG5    0x0020
#define AL_OBJ_BI_FLAG6    0x0040
#define AL_OBJ_BI_FLAG7    0x0080
#define AL_OBJ_BO_ALL      0x0A00
#define AL_OBJ_BO          0x0A01
#define AL_OBJ_BO_STAT     0x0A02
#define AL_OBJ_BOC_ALL     0x0B00
#define AL_OBJ_BOC_NOTIME  0x0B01
#define AL_OBJ_BOC_TIME    0x0B02
#define AL_OBJ_CTLOP_BLK   0x0C01
#define AL_OBJ_CTL_PCB     0x0C02
#define AL_OBJ_CTL_PMASK   0x0C03
#define AL_OBJ_BOE_NOTIME  0x0D01
#define AL_OBJ_BOE_TIME    0x0D02
#define AL_OBJCTLC_CODE    0x0F
#define AL_OBJCTLC_MISC    0x30
#define AL_OBJCTLC_TC      0xC0
#define AL_OBJCTLC_CODE0   0x00
#define AL_OBJCTLC_CODE1   0x01
#define AL_OBJCTLC_CODE2   0x02
#define AL_OBJCTLC_CODE3   0x03
#define AL_OBJCTLC_CODE4   0x04
#define AL_OBJCTLC_NOTSET  0x00
#define AL_OBJCTLC_QUEUE   0x01
#define AL_OBJCTLC_CLEAR   0x02
#define AL_OBJCTLC_BOTHSET 0x03
#define AL_OBJCTLC_TC0     0x00
#define AL_OBJCTLC_TC1     0x01
#define AL_OBJCTLC_TC2     0x02
#define AL_OBJCTLC_TC3     0x03
#define AL_OBJCTL_STAT0    0x00
#define AL_OBJCTL_STAT1    0x01
#define AL_OBJCTL_STAT2    0x02
#define AL_OBJCTL_STAT3    0x03
#define AL_OBJCTL_STAT4    0x04
#define AL_OBJCTL_STAT5    0x05
#define AL_OBJCTL_STAT6    0x06
#define AL_OBJCTL_STAT7    0x07
#define AL_OBJCTL_STAT8    0x08
#define AL_OBJCTL_STAT9    0x09
#define AL_OBJCTL_STAT10   0x0A
#define AL_OBJCTL_STAT11   0x0B
#define AL_OBJCTL_STAT12   0x0C
#define AL_OBJCTL_STAT126  0x7E
#define AL_OBJCTL_STAT127  0x7F
#define AL_OBJCTL_STATUS_MASK 0x7F
#define AL_OBJ_BO_FLAG0    0x0001
#define AL_OBJ_BO_FLAG1    0x0002
#define AL_OBJ_BO_FLAG2    0x0004
#define AL_OBJ_BO_FLAG3    0x0008
#define AL_OBJ_BO_FLAG4    0x0010
#define AL_OBJ_BO_FLAG5    0x0020
#define AL_OBJ_BO_FLAG6    0x0040
#define AL_OBJ_BO_FLAG7    0x0080
#define AL_OBJ_CTR_ALL     0x1400
#define AL_OBJ_CTR_32      0x1401
#define AL_OBJ_CTR_16      0x1402
#define AL_OBJ_DCTR_32     0x1403
#define AL_OBJ_DCTR_16     0x1404
#define AL_OBJ_CTR_32NF    0x1405
#define AL_OBJ_CTR_16NF    0x1406
#define AL_OBJ_DCTR_32NF   0x1407
#define AL_OBJ_DCTR_16NF   0x1408
#define AL_OBJ_FCTR_ALL    0x1500
#define AL_OBJ_FCTR_32     0x1501
#define AL_OBJ_FCTR_16     0x1502
#define AL_OBJ_FDCTR_32    0x1503
#define AL_OBJ_FDCTR_16    0x1504
#define AL_OBJ_FCTR_32T    0x1505
#define AL_OBJ_FCTR_16T    0x1506
#define AL_OBJ_FDCTR_32T   0x1507
#define AL_OBJ_FDCTR_16T   0x1508
#define AL_OBJ_FCTR_32NF   0x1509
#define AL_OBJ_FCTR_16NF   0x150A
#define AL_OBJ_FDCTR_32NF  0x150B
#define AL_OBJ_FDCTR_16NF  0x150C
#define AL_OBJ_CTRC_ALL    0x1600
#define AL_OBJ_CTRC_32     0x1601
#define AL_OBJ_CTRC_16     0x1602
#define AL_OBJ_DCTRC_32    0x1603
#define AL_OBJ_DCTRC_16    0x1604
#define AL_OBJ_CTRC_32T    0x1605
#define AL_OBJ_CTRC_16T    0x1606
#define AL_OBJ_DCTRC_32T   0x1607
#define AL_OBJ_DCTRC_16T   0x1608
#define AL_OBJ_FCTRC_ALL   0x1700
#define AL_OBJ_FCTRC_32    0x1701
#define AL_OBJ_FCTRC_16    0x1702
#define AL_OBJ_FDCTRC_32   0x1703
#define AL_OBJ_FDCTRC_16   0x1704
#define AL_OBJ_FCTRC_32T   0x1705
#define AL_OBJ_FCTRC_16T   0x1706
#define AL_OBJ_FDCTRC_32T  0x1707
#define AL_OBJ_FDCTRC_16T  0x1708
#define AL_OBJ_CTR_FLAG0   0x0001
#define AL_OBJ_CTR_FLAG1   0x0002
#define AL_OBJ_CTR_FLAG2   0x0004
#define AL_OBJ_CTR_FLAG3   0x0008
#define AL_OBJ_CTR_FLAG4   0x0010
#define AL_OBJ_CTR_FLAG5   0x0020
#define AL_OBJ_CTR_FLAG6   0x0040
#define AL_OBJ_CTR_FLAG7   0x0080
#define AL_OBJ_AI_ALL      0x1E00
#define AL_OBJ_AI_32       0x1E01
#define AL_OBJ_AI_16       0x1E02
#define AL_OBJ_AI_32NF     0x1E03
#define AL_OBJ_AI_16NF     0x1E04
#define AL_OBJ_AI_FLT      0x1E05
#define AL_OBJ_AI_DBL      0x1E06
#define AL_OBJ_AIF_FLT     0x1F07
#define AL_OBJ_AIF_DBL     0x1F08
#define AL_OBJ_AIC_ALL     0x2000
#define AL_OBJ_AIC_32NT    0x2001
#define AL_OBJ_AIC_16NT    0x2002
#define AL_OBJ_AIC_32T     0x2003
#define AL_OBJ_AIC_16T     0x2004
#define AL_OBJ_AIC_FLTNT   0x2005
#define AL_OBJ_AIC_DBLNT   0x2006
#define AL_OBJ_AIC_FLTT    0x2007
#define AL_OBJ_AIC_DBLT    0x2008
#define AL_OBJ_AIFC_FLTNT  0x2105
#define AL_OBJ_AIFC_DBLNT  0x2106
#define AL_OBJ_AIFC_FLTT   0x2107
#define AL_OBJ_AIFC_DBLT   0x2108
#define AL_OBJ_AI_FLAG0    0x0001
#define AL_OBJ_AI_FLAG1    0x0002
#define AL_OBJ_AI_FLAG2    0x0004
#define AL_OBJ_AI_FLAG3    0x0008
#define AL_OBJ_AI_FLAG4    0x0010
#define AL_OBJ_AI_FLAG5    0x0020
#define AL_OBJ_AI_FLAG6    0x0040
#define AL_OBJ_AI_FLAG7    0x0080
#define AL_OBJ_AIDB_ALL    0x2200
#define AL_OBJ_AIDB_16     0x2201
#define AL_OBJ_AIDB_32     0x2202
#define AL_OBJ_AIDB_FLT    0x2203
#define AL_OBJ_AO_ALL      0x2800
#define AL_OBJ_AO_32       0x2801
#define AL_OBJ_AO_16       0x2802
#define AL_OBJ_AO_FLT      0x2803
#define AL_OBJ_AO_DBL      0x2804
#define AL_OBJ_AO_32OPB    0x2901
#define AL_OBJ_AO_16OPB    0x2902
#define AL_OBJ_AO_FLTOPB   0x2903
#define AL_OBJ_AO_DBLOPB   0x2904
#define AL_OBJ_AOC_ALL     0x2A00
#define AL_OBJ_AOC_32NT    0x2A01
#define AL_OBJ_AOC_16NT    0x2A02
#define AL_OBJ_AOC_32T     0x2A03
#define AL_OBJ_AOC_16T     0x2A04
#define AL_OBJ_AOC_FLTNT   0x2A05
#define AL_OBJ_AOC_DBLNT   0x2A06
#define AL_OBJ_AOC_FLTT    0x2A07
#define AL_OBJ_AOC_DBLT    0x2A08
#define AL_OBJ_AOC_32EVNT  0x2B01
#define AL_OBJ_AOC_16EVNT  0x2B02
#define AL_OBJ_AOC_32EVTT  0x2B03
#define AL_OBJ_AOC_16EVTT  0x2B04
#define AL_OBJ_AOC_FLTEVNT 0x2B05
#define AL_OBJ_AOC_DBLEVNT 0x2B06
#define AL_OBJ_AOC_FLTEVTT 0x2B07
#define AL_OBJ_AOC_DBLEVTT 0x2B08
#define AL_OBJ_AO_FLAG0    0x0001
#define AL_OBJ_AO_FLAG1    0x0002
#define AL_OBJ_AO_FLAG2    0x0004
#define AL_OBJ_AO_FLAG3    0x0008
#define AL_OBJ_AO_FLAG4    0x0010
#define AL_OBJ_AO_FLAG5    0x0020
#define AL_OBJ_AO_FLAG6    0x0040
#define AL_OBJ_AO_FLAG7    0x0080
#define AL_OBJ_TD_ALL      0x3200
#define AL_OBJ_TD          0x3201
#define AL_OBJ_TDI         0x3202
#define AL_OBJ_TDR         0x3203
#define AL_OBJ_TDCTO       0x3301
#define AL_OBJ_UTDCTO      0x3302
#define AL_OBJ_TDELAYC     0x3401
#define AL_OBJ_TDELAYF     0x3402
#define AL_OBJ_CLASS0      0x3C01
#define AL_OBJ_CLASS1      0x3C02
#define AL_OBJ_CLASS2      0x3C03
#define AL_OBJ_CLASS3      0x3C04
#define AL_OBJ_FILE_CMD         0x4603
#define AL_OBJ_FILE_STAT        0x4604
#define AL_OBJ_FILE_TRANS       0x4605
#define AL_OBJ_FILE_TRAN_ST     0x4606
#define AL_OBJ_FILE_MODE_NULL   0x00
#define AL_OBJ_FILE_MODE_READ   0x01
#define AL_OBJ_FILE_MODE_WRITE  0x02
#define AL_OBJ_FILE_MODE_APPEND 0x03
#define AL_OBJ_IIN         0x5001
#define AL_OBJ_DS_PROTO    0x5501
#define AL_OBJ_DSD_CONT    0x5601
#define AL_OBJ_DSD_CHAR    0x5602
#define AL_OBJ_DSD_PIDX    0x5603
#define AL_OBJ_DS_PV       0x5701
#define AL_OBJ_DS_SS       0x5801
#define AL_OBJ_OCT         0x6E00
#define AL_OBJ_OCT_EVT     0x6F00
#define AL_OBJ_VT_OBLK     0x7000
#define AL_OBJ_VT_EVTD     0x7100
#define AL_OBJ_SA_AUTH_CH     0x7801
#define AL_OBJ_SA_AUTH_RP     0x7802
#define AL_OBJ_SA_AUTH_AGMRQ  0x7803
#define AL_OBJ_SA_AUTH_SKSR   0x7804
#define AL_OBJ_SA_AUTH_SKS    0x7805
#define AL_OBJ_SA_AUTH_SKC    0x7806
#define AL_OBJ_SA_AUTH_ERR    0x7807
#define AL_OBJ_SA_AUTH_MAC    0x7809
#define AL_OBJ_SA_AUTH_USC    0x780A
#define AL_OBJ_SA_AUTH_UKCR   0x780B
#define AL_OBJ_SA_AUTH_UKCRP  0x780C
#define AL_OBJ_SA_AUTH_UKC    0x780D
#define AL_OBJ_SA_AUTH_UKCC   0x780F
#define AL_OBJ_SA_SECSTAT     0x7901
#define AL_OBJ_SA_SECSTATEVT  0x7A01
#define AL_OBJ_SA_SECSTATEVTT 0x7A02
void proto_register_dnp3(void);
void proto_reg_handoff_dnp3(void);
static int proto_dnp3 = -1;
static int hf_dnp3_start = -1;
static int hf_dnp3_len = -1;
static int hf_dnp3_ctl = -1;
static int hf_dnp3_ctl_prifunc = -1;
static int hf_dnp3_ctl_secfunc = -1;
static int hf_dnp3_ctl_dir = -1;
static int hf_dnp3_ctl_prm = -1;
static int hf_dnp3_ctl_fcb = -1;
static int hf_dnp3_ctl_fcv = -1;
static int hf_dnp3_ctl_dfc = -1;
static int hf_dnp3_dst = -1;
static int hf_dnp3_src = -1;
static int hf_dnp3_addr = -1;
static int hf_dnp3_data_hdr_crc = -1;
static int hf_dnp3_data_hdr_crc_status = -1;
static int hf_dnp3_tr_ctl = -1;
static int hf_dnp3_tr_fin = -1;
static int hf_dnp3_tr_fir = -1;
static int hf_dnp3_tr_seq = -1;
static int hf_dnp3_data_chunk = -1;
static int hf_dnp3_data_chunk_len = -1;
static int hf_dnp3_data_chunk_crc = -1;
static int hf_dnp3_data_chunk_crc_status = -1;
static int hf_dnp3_al_ctl = -1;
static int hf_dnp3_al_fir = -1;
static int hf_dnp3_al_fin = -1;
static int hf_dnp3_al_con = -1;
static int hf_dnp3_al_uns = -1;
static int hf_dnp3_al_seq = -1;
static int hf_dnp3_al_func = -1;
static int hf_dnp3_al_iin = -1;
static int hf_dnp3_al_iin_bmsg = -1;
static int hf_dnp3_al_iin_cls1d = -1;
static int hf_dnp3_al_iin_cls2d = -1;
static int hf_dnp3_al_iin_cls3d = -1;
static int hf_dnp3_al_iin_tsr = -1;
static int hf_dnp3_al_iin_dol = -1;
static int hf_dnp3_al_iin_dt = -1;
static int hf_dnp3_al_iin_rst = -1;
static int hf_dnp3_al_iin_fcni = -1;
static int hf_dnp3_al_iin_obju = -1;
static int hf_dnp3_al_iin_pioor = -1;
static int hf_dnp3_al_iin_ebo = -1;
static int hf_dnp3_al_iin_oae = -1;
static int hf_dnp3_al_iin_cc = -1;
static int hf_dnp3_al_obj = -1;
static int hf_dnp3_al_objq_prefix = -1;
static int hf_dnp3_al_objq_range = -1;
static int hf_dnp3_al_range_start8 = -1;
static int hf_dnp3_al_range_stop8 = -1;
static int hf_dnp3_al_range_start16 = -1;
static int hf_dnp3_al_range_stop16 = -1;
static int hf_dnp3_al_range_start32 = -1;
static int hf_dnp3_al_range_stop32 = -1;
static int hf_dnp3_al_range_abs8 = -1;
static int hf_dnp3_al_range_abs16 = -1;
static int hf_dnp3_al_range_abs32 = -1;
static int hf_dnp3_al_range_quant8 = -1;
static int hf_dnp3_al_range_quant16 = -1;
static int hf_dnp3_al_range_quant32 = -1;
static int hf_dnp3_al_index8 = -1;
static int hf_dnp3_al_index16 = -1;
static int hf_dnp3_al_index32 = -1;
static int hf_dnp3_al_size8 = -1;
static int hf_dnp3_al_size16 = -1;
static int hf_dnp3_al_size32 = -1;
static int hf_dnp3_bocs_bit = -1;
static int hf_dnp3_al_biq_b0 = -1;
static int hf_dnp3_al_biq_b1 = -1;
static int hf_dnp3_al_biq_b2 = -1;
static int hf_dnp3_al_biq_b3 = -1;
static int hf_dnp3_al_biq_b4 = -1;
static int hf_dnp3_al_biq_b5 = -1;
static int hf_dnp3_al_biq_b6 = -1;
static int hf_dnp3_al_biq_b7 = -1;
static int hf_dnp3_al_boq_b0 = -1;
static int hf_dnp3_al_boq_b1 = -1;
static int hf_dnp3_al_boq_b2 = -1;
static int hf_dnp3_al_boq_b3 = -1;
static int hf_dnp3_al_boq_b4 = -1;
static int hf_dnp3_al_boq_b5 = -1;
static int hf_dnp3_al_boq_b6 = -1;
static int hf_dnp3_al_boq_b7 = -1;
static int hf_dnp3_al_ctrq_b0 = -1;
static int hf_dnp3_al_ctrq_b1 = -1;
static int hf_dnp3_al_ctrq_b2 = -1;
static int hf_dnp3_al_ctrq_b3 = -1;
static int hf_dnp3_al_ctrq_b4 = -1;
static int hf_dnp3_al_ctrq_b5 = -1;
static int hf_dnp3_al_ctrq_b6 = -1;
static int hf_dnp3_al_ctrq_b7 = -1;
static int hf_dnp3_al_aiq_b0 = -1;
static int hf_dnp3_al_aiq_b1 = -1;
static int hf_dnp3_al_aiq_b2 = -1;
static int hf_dnp3_al_aiq_b3 = -1;
static int hf_dnp3_al_aiq_b4 = -1;
static int hf_dnp3_al_aiq_b5 = -1;
static int hf_dnp3_al_aiq_b6 = -1;
static int hf_dnp3_al_aiq_b7 = -1;
static int hf_dnp3_al_aoq_b0 = -1;
static int hf_dnp3_al_aoq_b1 = -1;
static int hf_dnp3_al_aoq_b2 = -1;
static int hf_dnp3_al_aoq_b3 = -1;
static int hf_dnp3_al_aoq_b4 = -1;
static int hf_dnp3_al_aoq_b5 = -1;
static int hf_dnp3_al_aoq_b6 = -1;
static int hf_dnp3_al_aoq_b7 = -1;
static int hf_dnp3_al_timestamp = -1;
static int hf_dnp3_al_file_perms = -1;
static int hf_dnp3_al_file_perms_read_owner = -1;
static int hf_dnp3_al_file_perms_write_owner = -1;
static int hf_dnp3_al_file_perms_exec_owner = -1;
static int hf_dnp3_al_file_perms_read_group = -1;
static int hf_dnp3_al_file_perms_write_group = -1;
static int hf_dnp3_al_file_perms_exec_group = -1;
static int hf_dnp3_al_file_perms_read_world = -1;
static int hf_dnp3_al_file_perms_write_world = -1;
static int hf_dnp3_al_file_perms_exec_world = -1;
static int hf_dnp3_al_rel_timestamp = -1;
static int hf_dnp3_al_ana16 = -1;
static int hf_dnp3_al_ana32 = -1;
static int hf_dnp3_al_anaflt = -1;
static int hf_dnp3_al_anadbl = -1;
static int hf_dnp3_al_bit = -1;
static int hf_dnp3_al_2bit = -1;
static int hf_dnp3_al_cnt16 = -1;
static int hf_dnp3_al_cnt32 = -1;
static int hf_dnp3_al_ctrlstatus = -1;
static int hf_dnp3_al_anaout16 = -1;
static int hf_dnp3_al_anaout32 = -1;
static int hf_dnp3_al_anaoutflt = -1;
static int hf_dnp3_al_anaoutdbl = -1;
static int hf_dnp3_al_file_mode = -1;
static int hf_dnp3_al_file_auth = -1;
static int hf_dnp3_al_file_size = -1;
static int hf_dnp3_al_file_maxblk = -1;
static int hf_dnp3_al_file_reqID = -1;
static int hf_dnp3_al_file_handle = -1;
static int hf_dnp3_al_file_status = -1;
static int hf_dnp3_al_file_blocknum = -1;
static int hf_dnp3_al_file_lastblock = -1;
static int hf_dnp3_al_file_data = -1;
static int hf_dnp3_ctlobj_code_c = -1;
static int hf_dnp3_ctlobj_code_m = -1;
static int hf_dnp3_ctlobj_code_tc = -1;
static int hf_dnp3_al_datatype = -1;
static int hf_dnp3_al_da_length = -1;
static int hf_dnp3_al_da_uint8 = -1;
static int hf_dnp3_al_da_uint16 = -1;
static int hf_dnp3_al_da_uint32 = -1;
static int hf_dnp3_al_da_int8 = -1;
static int hf_dnp3_al_da_int16 = -1;
static int hf_dnp3_al_da_int32 = -1;
static int hf_dnp3_al_da_flt = -1;
static int hf_dnp3_al_da_dbl = -1;
static int hf_dnp3_al_sa_cd = -1;
static int hf_dnp3_al_sa_cdl = -1;
static int hf_dnp3_al_sa_csq = -1;
static int hf_dnp3_al_sa_err = -1;
static int hf_dnp3_al_sa_key = -1;
static int hf_dnp3_al_sa_kcm = -1;
static int hf_dnp3_al_sa_ks = -1;
static int hf_dnp3_al_sa_ksq = -1;
static int hf_dnp3_al_sa_kwa = -1;
static int hf_dnp3_al_sa_mac = -1;
static int hf_dnp3_al_sa_mal = -1;
static int hf_dnp3_al_sa_rfc = -1;
static int hf_dnp3_al_sa_seq = -1;
static int hf_dnp3_al_sa_uk = -1;
static int hf_dnp3_al_sa_ukl = -1;
static int hf_dnp3_al_sa_usr = -1;
static int hf_dnp3_al_sa_usrn = -1;
static int hf_dnp3_al_sa_usrnl = -1;
static int hf_dnp3_al_sa_assoc_id = -1;
static int hf_dnp3_al_point_index = -1;
static int hf_dnp3_al_da_value = -1;
static int hf_dnp3_al_count = -1;
static int hf_dnp3_al_on_time = -1;
static int hf_dnp3_al_off_time = -1;
static int hf_dnp3_al_time_delay = -1;
static int hf_dnp3_al_file_string_offset = -1;
static int hf_dnp3_al_file_string_length = -1;
static int hf_dnp3_al_file_name = -1;
static int hf_dnp3_al_octet_string = -1;
static int hf_dnp3_unknown_data_chunk = -1;
static const value_string dnp3_ctl_func_pri_vals[] = {
{ DL_FUNC_RESET_LINK, "Reset of Remote Link" },
{ DL_FUNC_RESET_PROC, "Reset of User Process" },
{ DL_FUNC_TEST_LINK,  "Test Function For Link" },
{ DL_FUNC_USER_DATA,  "User Data" },
{ DL_FUNC_UNC_DATA,   "Unconfirmed User Data" },
{ DL_FUNC_LINK_STAT,  "Request Link Status" },
{ 0, NULL }
};
static const value_string dnp3_ctl_func_sec_vals[] = {
{ DL_FUNC_ACK,        "ACK" },
{ DL_FUNC_NACK,       "NACK" },
{ DL_FUNC_STAT_LINK,  "Status of Link" },
{ DL_FUNC_NO_FUNC,    "Link Service Not Functioning" },
{ DL_FUNC_NOT_IMPL,   "Link Service Not Used or Implemented" },
{ 0,  NULL }
};
static const value_string dnp3_al_func_vals[] = {
{ AL_FUNC_CONFIRM,    "Confirm" },
{ AL_FUNC_READ,       "Read" },
{ AL_FUNC_WRITE,      "Write" },
{ AL_FUNC_SELECT,     "Select" },
{ AL_FUNC_OPERATE,    "Operate" },
{ AL_FUNC_DIROP,      "Direct Operate" },
{ AL_FUNC_DIROPNACK,  "Direct Operate No Ack" },
{ AL_FUNC_FRZ,        "Immediate Freeze" },
{ AL_FUNC_FRZNACK,    "Immediate Freeze No Ack" },
{ AL_FUNC_FRZCLR,     "Freeze and Clear" },
{ AL_FUNC_FRZCLRNACK, "Freeze and Clear No ACK" },
{ AL_FUNC_FRZT,       "Freeze With Time" },
{ AL_FUNC_FRZTNACK,   "Freeze With Time No ACK" },
{ AL_FUNC_COLDRST,    "Cold Restart" },
{ AL_FUNC_WARMRST,    "Warm Restart" },
{ AL_FUNC_INITDATA,   "Initialize Data" },
{ AL_FUNC_INITAPP,    "Initialize Application" },
{ AL_FUNC_STARTAPP,   "Start Application" },
{ AL_FUNC_STOPAPP,    "Stop Application" },
{ AL_FUNC_SAVECFG,    "Save Configuration" },
{ AL_FUNC_ENSPMSG,    "Enable Spontaneous Messages" },
{ AL_FUNC_DISSPMSG,   "Disable Spontaneous Messages" },
{ AL_FUNC_ASSIGNCL,   "Assign Classes" },
{ AL_FUNC_DELAYMST,   "Delay Measurement" },
{ AL_FUNC_RECCT,      "Record Current Time" },
{ AL_FUNC_OPENFILE,   "Open File" },
{ AL_FUNC_CLOSEFILE,  "Close File" },
{ AL_FUNC_DELETEFILE, "Delete File" },
{ AL_FUNC_GETFILEINF, "Get File Info" },
{ AL_FUNC_AUTHFILE,   "Authenticate File" },
{ AL_FUNC_ABORTFILE,  "Abort File" },
{ AL_FUNC_ACTCNF,     "Activate Config" },
{ AL_FUNC_AUTHREQ,    "Authentication Request" },
{ AL_FUNC_AUTHERR,    "Authentication Error" },
{ AL_FUNC_RESPON,     "Response" },
{ AL_FUNC_UNSOLI,     "Unsolicited Response" },
{ AL_FUNC_AUTHRESP,   "Authentication Response" },
{ 0, NULL }
};
static value_string_ext dnp3_al_func_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_func_vals);
static const value_string dnp3_al_iin_vals[] = {
{ AL_IIN_BMSG,    "Broadcast message Rx'd" },
{ AL_IIN_CLS1D,   "Class 1 Data Available" },
{ AL_IIN_CLS2D,   "Class 2 Data Available" },
{ AL_IIN_CLS3D,   "Class 3 Data Available" },
{ AL_IIN_TSR,     "Time Sync Required from Master" },
{ AL_IIN_DOL,     "Outputs in Local Mode" },
{ AL_IIN_DT,      "Device Trouble" },
{ AL_IIN_RST,     "Device Restart" },
{ AL_IIN_FCNI,    "Function Code not implemented" },
{ AL_IIN_OBJU,    "Requested Objects Unknown" },
{ AL_IIN_PIOOR,   "Parameters Invalid or Out of Range" },
{ AL_IIN_EBO,     "Event Buffer Overflow" },
{ AL_IIN_OAE,     "Operation Already Executing" },
{ AL_IIN_CC,      "Device Configuration Corrupt" },
{ 0, NULL }
};
static const value_string dnp3_al_objq_prefix_vals[] = {
{ AL_OBJQL_PREFIX_NI,    "None" },
{ AL_OBJQL_PREFIX_1O,    "1-Octet Index Prefix" },
{ AL_OBJQL_PREFIX_2O,    "2-Octet Index Prefix" },
{ AL_OBJQL_PREFIX_4O,    "4-Octet Index Prefix" },
{ AL_OBJQL_PREFIX_1OS,   "1-Octet Object Size Prefix" },
{ AL_OBJQL_PREFIX_2OS,   "2-Octet Object Size Prefix" },
{ AL_OBJQL_PREFIX_4OS,   "4-Octet Object Size Prefix" },
{ 0, NULL }
};
static value_string_ext dnp3_al_objq_prefix_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_objq_prefix_vals);
static const value_string dnp3_al_objq_range_vals[] = {
{ AL_OBJQL_RANGE_SSI8,    "8-bit Start and Stop Indices" },
{ AL_OBJQL_RANGE_SSI16,   "16-bit Start and Stop Indices" },
{ AL_OBJQL_RANGE_SSI32,   "32-bit Start and Stop Indices" },
{ AL_OBJQL_RANGE_AA8,     "8-bit Absolute Address in Range Field" },
{ AL_OBJQL_RANGE_AA16,    "16-bit Absolute Address in Range Field" },
{ AL_OBJQL_RANGE_AA32,    "32-bit Absolute Address in Range Field" },
{ AL_OBJQL_RANGE_R0,      "No Range Field" },
{ AL_OBJQL_RANGE_SF8,     "8-bit Single Field Quantity" },
{ AL_OBJQL_RANGE_SF16,    "16-bit Single Field Quantity" },
{ AL_OBJQL_RANGE_SF32,    "32-bit Single Field Quantity" },
{ 10,                     "Reserved" },
{ AL_OBJQL_RANGE_FF,      "Free-format Qualifier" },
{ 0, NULL }
};
static value_string_ext dnp3_al_objq_range_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_objq_range_vals);
static const value_string dnp3_al_obj_vals[] = {
{ AL_OBJ_DA_CFG_ID,      "Device Attributes - Configuration ID (Obj:00, Var:196)" },
{ AL_OBJ_DA_CFG_VER,     "Device Attributes - Configuration version (Obj:00, Var:197)" },
{ AL_OBJ_DA_CFG_BLD_DATE,"Device Attributes - Configuration build date (Obj:00, Var:198)" },
{ AL_OBJ_DA_CFG_CHG_DATE,"Device Attributes - Configuration last change date (Obj:00, Var:199)" },
{ AL_OBJ_DA_CFG_SIG,     "Device Attributes - Configuration signature (Obj:00, Var:200)" },
{ AL_OBJ_DA_CFG_SIG_ALG, "Device Attributes - Configuration signature algorithm (Obj:00, Var:201)" },
{ AL_OBJ_DA_MRID,        "Device Attributes - Master Resource ID (mRID) (Obj:00, Var:202)" },
{ AL_OBJ_DA_ALT,         "Device Attributes - Device altitude (Obj:00, Var:203)" },
{ AL_OBJ_DA_LONG,        "Device Attributes - Device longitude (Obj:00, Var:204)" },
{ AL_OBJ_DA_LAT,         "Device Attributes - Device latitude (Obj:00, Var:205)" },
{ AL_OBJ_DA_SEC_OP,      "Device Attributes - User-assigned secondary operator name (Obj:00, Var:206)" },
{ AL_OBJ_DA_PRM_OP,      "Device Attributes - User-assigned primary operator name (Obj:00, Var:207)" },
{ AL_OBJ_DA_SYS_NAME,    "Device Attributes - User-assigned system name (Obj:00, Var:208)" },
{ AL_OBJ_DA_SEC_VER,     "Device Attributes - Secure authentication version (Obj:00, Var:209)" },
{ AL_OBJ_DA_SEC_STAT,    "Device Attributes - Number of security statistics per association (Obj:00, Var:210)" },
{ AL_OBJ_DA_USR_ATTR,    "Device Attributes - Identifier of support for user-specific attributes (Obj:00, Var:211)" },
{ AL_OBJ_DA_MSTR_DSP,    "Device Attributes - Number of master-defined data set prototypes (Obj:00, Var:212)" },
{ AL_OBJ_DA_OS_DSP,      "Device Attributes - Number of outstation-defined data set prototypes (Obj:00, Var:213)" },
{ AL_OBJ_DA_MSTR_DS,     "Device Attributes - Number of master-defined data sets (Obj:00, Var:214)" },
{ AL_OBJ_DA_OS_DS,       "Device Attributes - Number of outstation-defined data sets (Obj:00, Var:215)" },
{ AL_OBJ_DA_BO_REQ,      "Device Attributes - Max number of binary outputs per request (Obj:00, Var:216)" },
{ AL_OBJ_DA_LOC_TA,      "Device Attributes - Local timing accuracy (Obj:00, Var:217)" },
{ AL_OBJ_DA_DUR_TA,      "Device Attributes - Duration of timing accuracy (Obj:00, Var:218)" },
{ AL_OBJ_DA_AO_EVT,      "Device Attributes - Support for analog output events (Obj:00, Var:219)" },
{ AL_OBJ_DA_MAX_AO,      "Device Attributes - Max analog output index (Obj:00, Var:220)" },
{ AL_OBJ_DA_NUM_AO,      "Device Attributes - Number of analog outputs (Obj:00, Var:221)" },
{ AL_OBJ_DA_BO_EVT,      "Device Attributes - Support for binary output events (Obj:00, Var:222)" },
{ AL_OBJ_DA_MAX_BO,      "Device Attributes - Max binary output index (Obj:00, Var:223)" },
{ AL_OBJ_DA_NUM_BO,      "Device Attributes - Number of binary outputs (Obj:00, Var:224)" },
{ AL_OBJ_DA_FCTR_EVT,    "Device Attributes - Support for frozen counter events (Obj:00, Var:225)" },
{ AL_OBJ_DA_FCTR,        "Device Attributes - Support for frozen counters (Obj:00, Var:226)" },
{ AL_OBJ_DA_CTR_EVT,     "Device Attributes - Support for counter events (Obj:00, Var:227)" },
{ AL_OBJ_DA_MAX_CTR,     "Device Attributes - Max counter index (Obj:00, Var:228)" },
{ AL_OBJ_DA_NUM_CTR,     "Device Attributes - Number of counter points (Obj:00, Var:229)" },
{ AL_OBJ_DA_AIF,         "Device Attributes - Support for frozen analog inputs (Obj:00, Var:230)" },
{ AL_OBJ_DA_AI_EVT,      "Device Attributes - Support for analog input events (Obj:00, Var:231)" },
{ AL_OBJ_DA_MAX_AI,      "Device Attributes - Maximum analog input index (Obj:00, Var:232)" },
{ AL_OBJ_DA_NUM_AI,      "Device Attributes - Number of analog input points (Obj:00, Var:233)" },
{ AL_OBJ_DA_2BI_EVT,     "Device Attributes - Support for Double-Bit BI Events (Obj:00, Var:234)" },
{ AL_OBJ_DA_MAX_2BI,     "Device Attributes - Max Double-bit BI Point Index (Obj:00, Var:235)" },
{ AL_OBJ_DA_NUM_2BI,     "Device Attributes - Number of Double-bit BI Points (Obj:00, Var:236)" },
{ AL_OBJ_DA_BI_EVT,      "Device Attributes - Support for Binary Input Events (Obj:00, Var:237)" },
{ AL_OBJ_DA_MAX_BI,      "Device Attributes - Max Binary Input Point Index (Obj:00, Var:238)" },
{ AL_OBJ_DA_NUM_BI,      "Device Attributes - Number of Binary Input Points (Obj:00, Var:239)" },
{ AL_OBJ_DA_MXTX_FR,     "Device Attributes - Maximum Transmit Fragment Size (Obj:00, Var:240)" },
{ AL_OBJ_DA_MXRX_FR,     "Device Attributes - Maximum Receive Fragment Size (Obj:00, Var:241)" },
{ AL_OBJ_DA_SWVER,       "Device Attributes - Device Manufacturers SW Version (Obj:00, Var:242)" },
{ AL_OBJ_DA_HWVER,       "Device Attributes - Device Manufacturers HW Version (Obj:00, Var:243)" },
{ AL_OBJ_DA_LOC,         "Device Attributes - User-Assigned Location (Obj:00, Var:245)" },
{ AL_OBJ_DA_ID,          "Device Attributes - User-Assigned ID code/number (Obj:00, Var:246)" },
{ AL_OBJ_DA_DEVNAME,     "Device Attributes - User-Assigned Device Name (Obj:00, Var:247)" },
{ AL_OBJ_DA_SERNUM,      "Device Attributes - Device Serial Number (Obj:00, Var:248)" },
{ AL_OBJ_DA_CONF,        "Device Attributes - DNP Subset and Conformance (Obj:00, Var:249)" },
{ AL_OBJ_DA_PROD,        "Device Attributes - Device Product Name and Model (Obj:00, Var:250)" },
{ AL_OBJ_DA_MFG,         "Device Attributes - Device Manufacturers Name (Obj:00, Var:252)" },
{ AL_OBJ_DA_ALL,         "Device Attributes - Non-specific All-attributes Request (Obj:00, Var:254)" },
{ AL_OBJ_DA_LVAR,        "Device Attributes - List of Attribute Variations (Obj:00, Var:255)" },
{ AL_OBJ_BI_ALL,         "Binary Input Default Variation (Obj:01, Var:Default)" },
{ AL_OBJ_BI_1BIT,        "Single-Bit Binary Input (Obj:01, Var:01)" },
{ AL_OBJ_BI_STAT,        "Binary Input With Status (Obj:01, Var:02)" },
{ AL_OBJ_BIC_ALL,        "Binary Input Change Default Variation (Obj:02, Var:Default)" },
{ AL_OBJ_BIC_NOTIME,     "Binary Input Change Without Time (Obj:02, Var:01)" },
{ AL_OBJ_BIC_TIME,       "Binary Input Change With Time (Obj:02, Var:02)" },
{ AL_OBJ_BIC_RTIME,      "Binary Input Change With Relative Time (Obj:02, Var:03)" },
{ AL_OBJ_2BI_ALL,        "Double-bit Input Default Variation (Obj:03, Var:Default)" },
{ AL_OBJ_2BI_NF,         "Double-bit Input No Flags (Obj:03, Var:01)" },
{ AL_OBJ_2BI_STAT,       "Double-bit Input With Status (Obj:03, Var:02)" },
{ AL_OBJ_2BIC_ALL,       "Double-bit Input Change Default Variation (Obj:04, Var:Default)" },
{ AL_OBJ_2BIC_NOTIME,    "Double-bit Input Change Without Time (Obj:04, Var:01)" },
{ AL_OBJ_2BIC_TIME,      "Double-bit Input Change With Time (Obj:04, Var:02)" },
{ AL_OBJ_2BIC_RTIME,     "Double-bit Input Change With Relative Time (Obj:04, Var:03)" },
{ AL_OBJ_BO_ALL,         "Binary Output Default Variation (Obj:10, Var:Default)" },
{ AL_OBJ_BO,             "Binary Output (Obj:10, Var:01)" },
{ AL_OBJ_BO_STAT,        "Binary Output Status (Obj:10, Var:02)" },
{ AL_OBJ_BOC_ALL,        "Binary Output Change Default Variation (Obj:11, Var:Default)" },
{ AL_OBJ_BOC_NOTIME,     "Binary Output Change Without Time (Obj:11, Var:01)" },
{ AL_OBJ_BOC_TIME,       "Binary Output Change With Time (Obj:11, Var:02)" },
{ AL_OBJ_CTLOP_BLK,      "Control Relay Output Block (Obj:12, Var:01)" },
{ AL_OBJ_CTL_PCB,        "Pattern Control Block (Obj:12, Var:02)" },
{ AL_OBJ_CTL_PMASK,      "Pattern Mask (Obj:12, Var:03)" },
{ AL_OBJ_BOE_NOTIME,     "Binary Command Event Without Time (Obj 13, Var:01)" },
{ AL_OBJ_BOE_TIME,       "Binary Command Event With Time (Obj 13, Var:02)" },
{ AL_OBJ_CTR_ALL,        "Binary Counter Default Variation (Obj:20, Var:Default)" },
{ AL_OBJ_CTR_32,         "32-Bit Binary Counter (Obj:20, Var:01)" },
{ AL_OBJ_CTR_16,         "16-Bit Binary Counter (Obj:20, Var:02)" },
{ AL_OBJ_DCTR_32,        "32-Bit Binary Delta Counter (Obj:20, Var:03)" },
{ AL_OBJ_DCTR_16,        "16-Bit Binary Delta Counter (Obj:20, Var:04)" },
{ AL_OBJ_CTR_32NF,       "32-Bit Binary Counter Without Flag (Obj:20, Var:05)" },
{ AL_OBJ_CTR_16NF,       "16-Bit Binary Counter Without Flag (Obj:20, Var:06)" },
{ AL_OBJ_DCTR_32NF,      "32-Bit Binary Delta Counter Without Flag (Obj:20, Var:07)" },
{ AL_OBJ_DCTR_16NF,      "16-Bit Binary Delta Counter Without Flag (Obj:20, Var:08)" },
{ AL_OBJ_FCTR_ALL,       "Frozen Binary Counter Default Variation (Obj:21, Var:Default)" },
{ AL_OBJ_FCTR_32,        "32-Bit Frozen Binary Counter (Obj:21, Var:01)" },
{ AL_OBJ_FCTR_16,        "16-Bit Frozen Binary Counter (Obj:21, Var:02)" },
{ AL_OBJ_FDCTR_32,       "32-Bit Frozen Binary Delta Counter (Obj:21, Var:03)" },
{ AL_OBJ_FDCTR_16,       "16-Bit Frozen Binary Delta Counter (Obj:21, Var:04)" },
{ AL_OBJ_FCTR_32T,       "32-Bit Frozen Binary Counter With Flag and Time (Obj:21, Var:05)" },
{ AL_OBJ_FCTR_16T,       "16-Bit Frozen Binary Counter With Flag and Time (Obj:21, Var:06)" },
{ AL_OBJ_FDCTR_32T,      "32-Bit Frozen Binary Delta Counter With Flag and Time (Obj:21, Var:07)" },
{ AL_OBJ_FDCTR_16T,      "16-Bit Frozen Binary Delta Counter With Flag and Time (Obj:21, Var:08)" },
{ AL_OBJ_FCTR_32NF,      "32-Bit Frozen Binary Counter Without Flag (Obj:21, Var:09)" },
{ AL_OBJ_FCTR_16NF,      "16-Bit Frozen Binary Counter Without Flag (Obj:21, Var:10)" },
{ AL_OBJ_FDCTR_32NF,     "32-Bit Frozen Binary Delta Counter Without Flag (Obj:21, Var:11)" },
{ AL_OBJ_FDCTR_16NF,     "16-Bit Frozen Binary Delta Counter Without Flag (Obj:21, Var:12)" },
{ AL_OBJ_CTRC_ALL,       "Binary Counter Change Default Variation (Obj:22, Var:Default)" },
{ AL_OBJ_CTRC_32,        "32-Bit Counter Change Event w/o Time (Obj:22, Var:01)" },
{ AL_OBJ_CTRC_16,        "16-Bit Counter Change Event w/o Time (Obj:22, Var:02)" },
{ AL_OBJ_DCTRC_32,       "32-Bit Delta Counter Change Event w/o Time (Obj:22, Var:03)" },
{ AL_OBJ_DCTRC_16,       "16-Bit Delta Counter Change Event w/o Time (Obj:22, Var:04)" },
{ AL_OBJ_CTRC_32T,       "32-Bit Counter Change Event with Time (Obj:22, Var:05)" },
{ AL_OBJ_CTRC_16T,       "16-Bit Counter Change Event with Time (Obj:22, Var:06)" },
{ AL_OBJ_DCTRC_32T,      "32-Bit Delta Counter Change Event with Time (Obj:22, Var:07)" },
{ AL_OBJ_DCTRC_16T,      "16-Bit Delta Counter Change Event with Time (Obj:22, Var:08)" },
{ AL_OBJ_FCTRC_ALL,      "Frozen Binary Counter Change Default Variation (Obj:23, Var:Default)" },
{ AL_OBJ_FCTRC_32,       "32-Bit Frozen Counter Change Event w/o Time (Obj:23, Var:01)" },
{ AL_OBJ_FCTRC_16,       "16-Bit Frozen Counter Change Event w/o Time (Obj:23, Var:02)" },
{ AL_OBJ_FDCTRC_32,      "32-Bit Frozen Delta Counter Change Event w/o Time (Obj:23, Var:03)" },
{ AL_OBJ_FDCTRC_16,      "16-Bit Frozen Delta Counter Change Event w/o Time (Obj:23, Var:04)" },
{ AL_OBJ_FCTRC_32T,      "32-Bit Frozen Counter Change Event with Time (Obj:23, Var:05)" },
{ AL_OBJ_FCTRC_16T,      "16-Bit Frozen Counter Change Event with Time (Obj:23, Var:06)" },
{ AL_OBJ_FDCTRC_32T,     "32-Bit Frozen Delta Counter Change Event with Time (Obj:23, Var:07)" },
{ AL_OBJ_FDCTRC_16T,     "16-Bit Frozen Delta Counter Change Event with Time (Obj:23, Var:08)" },
{ AL_OBJ_AI_ALL,         "Analog Input Default Variation (Obj:30, Var:Default)" },
{ AL_OBJ_AI_32,          "32-Bit Analog Input (Obj:30, Var:01)" },
{ AL_OBJ_AI_16,          "16-Bit Analog Input (Obj:30, Var:02)" },
{ AL_OBJ_AI_32NF,        "32-Bit Analog Input Without Flag (Obj:30, Var:03)" },
{ AL_OBJ_AI_16NF,        "16-Bit Analog Input Without Flag (Obj:30, Var:04)" },
{ AL_OBJ_AI_FLT,         "32-Bit Floating Point Input (Obj:30, Var:05)" },
{ AL_OBJ_AI_DBL,         "64-Bit Floating Point Input (Obj:30, Var:06)" },
{ AL_OBJ_AIF_FLT,        "32-Bit Frozen Floating Point Input (Obj:31, Var:07)" },
{ AL_OBJ_AIF_DBL,        "64-Bit Frozen Floating Point Input (Obj:31, Var:08)" },
{ AL_OBJ_AIC_ALL,        "Analog Input Change Default Variation (Obj:32, Var:Default)" },
{ AL_OBJ_AIC_32NT,       "32-Bit Analog Change Event w/o Time (Obj:32, Var:01)" },
{ AL_OBJ_AIC_16NT,       "16-Bit Analog Change Event w/o Time (Obj:32, Var:02)" },
{ AL_OBJ_AIC_32T,        "32-Bit Analog Change Event with Time (Obj:32, Var:03)" },
{ AL_OBJ_AIC_16T,        "16-Bit Analog Change Event with Time (Obj:32, Var:04)" },
{ AL_OBJ_AIC_FLTNT,      "32-Bit Floating Point Change Event w/o Time (Obj:32, Var:05)" },
{ AL_OBJ_AIC_DBLNT,      "64-Bit Floating Point Change Event w/o Time (Obj:32, Var:06)" },
{ AL_OBJ_AIC_FLTT,       "32-Bit Floating Point Change Event w/ Time (Obj:32, Var:07)" },
{ AL_OBJ_AIC_DBLT,       "64-Bit Floating Point Change Event w/ Time (Obj:32, Var:08)" },
{ AL_OBJ_AIFC_FLTNT,     "32-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:05)" },
{ AL_OBJ_AIFC_DBLNT,     "64-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:06)" },
{ AL_OBJ_AIFC_FLTT,      "32-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:07)" },
{ AL_OBJ_AIFC_DBLT,      "64-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:08)" },
{ AL_OBJ_AIDB_ALL,       "Analog Input Deadband Default Variation (Obj:34, Var:Default)" },
{ AL_OBJ_AIDB_16,        "16-Bit Analog Input Deadband (Obj:34, Var:01)" },
{ AL_OBJ_AIDB_32,        "32-Bit Analog Input Deadband (Obj:34, Var:02)" },
{ AL_OBJ_AIDB_FLT,       "32-Bit Floating Point Analog Input Deadband (Obj:34, Var:03)" },
{ AL_OBJ_AO_ALL,         "Analog Output Default Variation (Obj:40, Var:Default)" },
{ AL_OBJ_AO_32,          "32-Bit Analog Output Status (Obj:40, Var:01)" },
{ AL_OBJ_AO_16,          "16-Bit Analog Output Status (Obj:40, Var:02)" },
{ AL_OBJ_AO_FLT,         "32-Bit Floating Point Output Status (Obj:40, Var:03)" },
{ AL_OBJ_AO_DBL,         "64-Bit Floating Point Output Status (Obj:40, Var:04)" },
{ AL_OBJ_AO_32OPB,       "32-Bit Analog Output Block (Obj:41, Var:01)" },
{ AL_OBJ_AO_16OPB,       "16-Bit Analog Output Block (Obj:41, Var:02)" },
{ AL_OBJ_AO_FLTOPB,      "32-Bit Floating Point Output Block (Obj:41, Var:03)" },
{ AL_OBJ_AO_DBLOPB,      "64-Bit Floating Point Output Block (Obj:41, Var:04)" },
{ AL_OBJ_AOC_ALL,        "Analog Output Event Default Variation (Obj:42, Var:Default)" },
{ AL_OBJ_AOC_32NT,       "32-Bit Analog Output Event w/o Time (Obj:42, Var:01)" },
{ AL_OBJ_AOC_16NT,       "16-Bit Analog Output Event w/o Time (Obj:42, Var:02)" },
{ AL_OBJ_AOC_32T,        "32-Bit Analog Output Event with Time (Obj:42, Var:03)" },
{ AL_OBJ_AOC_16T,        "16-Bit Analog Output Event with Time (Obj:42, Var:04)" },
{ AL_OBJ_AOC_FLTNT,      "32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05)" },
{ AL_OBJ_AOC_DBLNT,      "64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06)" },
{ AL_OBJ_AOC_FLTT,       "32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07)" },
{ AL_OBJ_AOC_DBLT,       "64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08)" },
{ AL_OBJ_AOC_32EVNT,     "32-Bit Analog Output Event w/o Time (Obj:43, Var:01)" },
{ AL_OBJ_AOC_16EVNT,     "16-Bit Analog Output Event w/o Time (Obj:43, Var:02)" },
{ AL_OBJ_AOC_32EVTT,     "32-Bit Analog Output Event with Time (Obj:43, Var:03)" },
{ AL_OBJ_AOC_16EVTT,     "16-Bit Analog Output Event with Time (Obj:43, Var:04)" },
{ AL_OBJ_AOC_FLTEVNT,    "32-Bit Floating Point Output Event w/o Time (Obj:43, Var:05)" },
{ AL_OBJ_AOC_DBLEVNT,    "64-Bit Floating Point Output Event w/o Time (Obj:43, Var:06)" },
{ AL_OBJ_AOC_FLTEVTT,    "32-Bit Floating Point Output Event w/ Time (Obj:43, Var:07)" },
{ AL_OBJ_AOC_DBLEVTT,    "64-Bit Floating Point Output Event w/ Time (Obj:43, Var:08)" },
{ AL_OBJ_TD_ALL,         "Time and Date Default Variations (Obj:50, Var:Default)" },
{ AL_OBJ_TD,             "Time and Date (Obj:50, Var:01)" },
{ AL_OBJ_TDI,            "Time and Date w/Interval (Obj:50, Var:02)" },
{ AL_OBJ_TDR,            "Last Recorded Time and Date (Obj:50, Var:03)" },
{ AL_OBJ_TDCTO,          "Time and Date CTO (Obj:51, Var:01)" },
{ AL_OBJ_UTDCTO,         "Unsynchronized Time and Date CTO (Obj:51, Var:02)"},
{ AL_OBJ_TDELAYF,        "Time Delay - Fine (Obj:52, Var:02)" },
{ AL_OBJ_CLASS0,         "Class 0 Data (Obj:60, Var:01)" },
{ AL_OBJ_CLASS1,         "Class 1 Data (Obj:60, Var:02)" },
{ AL_OBJ_CLASS2,         "Class 2 Data (Obj:60, Var:03)" },
{ AL_OBJ_CLASS3,         "Class 3 Data (Obj:60, Var:04)" },
{ AL_OBJ_FILE_CMD,       "File Control - File Command (Obj:70, Var:03)" },
{ AL_OBJ_FILE_STAT,      "File Control - File Status (Obj:70, Var:04)" },
{ AL_OBJ_FILE_TRANS,     "File Control - File Transport (Obj:70, Var:05)" },
{ AL_OBJ_FILE_TRAN_ST,   "File Control - File Transport Status (Obj:70, Var:06)" },
{ AL_OBJ_IIN,            "Internal Indications (Obj:80, Var:01)" },
{ AL_OBJ_DS_PROTO,       "Data-Set Prototype, with UUID (Obj:85, Var:01)" },
{ AL_OBJ_DSD_CONT,       "Data-Set Descriptor, Data-Set Contents (Obj:86, Var:01)" },
{ AL_OBJ_DSD_CHAR,       "Data-Set Descriptor, Characteristics (Obj:86, Var:02)" },
{ AL_OBJ_DSD_PIDX,       "Data-Set Descriptor, Point Index Attributes (Obj:86, Var:03)" },
{ AL_OBJ_DS_PV,          "Data-Set, Present Value (Obj:87, Var:01)" },
{ AL_OBJ_DS_SS,          "Data-Set, Snapshot (Obj:88, Var:01)" },
{ AL_OBJ_OCT,            "Octet String (Obj:110)" },
{ AL_OBJ_OCT_EVT,        "Octet String Event (Obj:111)" },
{ AL_OBJ_VT_OBLK,        "Virtual Terminal Output Block (Obj:112)" },
{ AL_OBJ_VT_EVTD,        "Virtual Terminal Event Data (Obj:113)" },
{ AL_OBJ_SA_AUTH_CH,     "Authentication Challenge (Obj:120, Var:01)" },
{ AL_OBJ_SA_AUTH_RP,     "Authentication Reply (Obj:120, Var:02)" },
{ AL_OBJ_SA_AUTH_AGMRQ,  "Authentication Aggressive Mode Request (Obj:120, Var:03)" },
{ AL_OBJ_SA_AUTH_SKSR,   "Authentication Session Key Status Request (Obj:120, Var:04)" },
{ AL_OBJ_SA_AUTH_SKS,    "Authentication Session Key Status (Obj:120, Var:05)" },
{ AL_OBJ_SA_AUTH_SKC,    "Authentication Session Key Change (Obj:120, Var:06)" },
{ AL_OBJ_SA_AUTH_ERR,    "Authentication Error (Obj:120, Var:07)" },
{ AL_OBJ_SA_AUTH_MAC,    "Authentication Message Authentication Code (Obj:120, Var:09)" },
{ AL_OBJ_SA_AUTH_UKCR,   "Authentication Update Key Change Request (Obj:120, Var:11)" },
{ AL_OBJ_SA_AUTH_UKCRP,  "Authentication Update Key Change Reply (Obj:120, Var:12)"},
{ AL_OBJ_SA_AUTH_UKC,    "Authentication Update Key Change (Obj:120, Var:13)"},
{ AL_OBJ_SA_AUTH_UKCC,   "Authentication Update Key Change Confirmation (Obj:120, Var:15)"},
{ AL_OBJ_SA_SECSTAT,     "Security Statistics (Obj:121, Var:01)" },
{ AL_OBJ_SA_SECSTATEVT,  "Security Statistic Event (Obj:122, Var:01)" },
{ AL_OBJ_SA_SECSTATEVTT, "Security Statistic Event w/ Time (Obj:122, Var:02)" },
{ 0, NULL }
};
static value_string_ext dnp3_al_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_obj_vals);
static const value_string dnp3_al_ctlc_code_vals[] = {
{ AL_OBJCTLC_CODE0,     "NUL Operation" },
{ AL_OBJCTLC_CODE1,     "Pulse On" },
{ AL_OBJCTLC_CODE2,     "Pulse Off" },
{ AL_OBJCTLC_CODE3,     "Latch On" },
{ AL_OBJCTLC_CODE4,     "Latch Off" },
{ 0, NULL }
};
static const value_string dnp3_al_ctlc_misc_vals[] = {
{ AL_OBJCTLC_QUEUE,     "Queue" },
{ AL_OBJCTLC_CLEAR,     "Clear" },
{ AL_OBJCTLC_NOTSET,    "Not Set" },
{ AL_OBJCTLC_BOTHSET,   "Queue and Clear" },
{ 0, NULL }
};
static const value_string dnp3_al_ctlc_tc_vals[] = {
{ AL_OBJCTLC_TC0,     "NUL" },
{ AL_OBJCTLC_TC1,     "Close" },
{ AL_OBJCTLC_TC2,     "Trip" },
{ AL_OBJCTLC_TC3,     "Reserved" },
{ 0, NULL }
};
static const value_string dnp3_al_ctl_status_vals[] = {
{ AL_OBJCTL_STAT0,     "Req. Accepted/Init/Queued" },
{ AL_OBJCTL_STAT1,     "Req. Not Accepted; Arm-Timer Expired" },
{ AL_OBJCTL_STAT2,     "Req. Not Accepted; No 'SELECT' Received" },
{ AL_OBJCTL_STAT3,     "Req. Not Accepted; Format Err. in Ctl Req." },
{ AL_OBJCTL_STAT4,     "Ctl Oper. Not Supported For This Point" },
{ AL_OBJCTL_STAT5,     "Req. Not Accepted; Ctrl Queue Full/Point Active" },
{ AL_OBJCTL_STAT6,     "Req. Not Accepted; Ctrl Hardware Problems" },
{ AL_OBJCTL_STAT7,     "Req. Not Accepted; Local/Remote switch in Local" },
{ AL_OBJCTL_STAT8,     "Req. Not Accepted; Too many operations" },
{ AL_OBJCTL_STAT9,     "Req. Not Accepted; Insufficient authorization" },
{ AL_OBJCTL_STAT10,    "Req. Not Accepted; Local automation proc active" },
{ AL_OBJCTL_STAT11,    "Req. Not Accepted; Processing limited" },
{ AL_OBJCTL_STAT12,    "Req. Not Accepted; Out of range value" },
{ AL_OBJCTL_STAT126,   "Req. Not Accepted; Non-participating (NOP request)" },
{ AL_OBJCTL_STAT127,   "Req. Not Accepted; Undefined error" },
{ 0, NULL }
};
static value_string_ext dnp3_al_ctl_status_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_ctl_status_vals);
static const value_string dnp3_al_file_mode_vals[] = {
{ AL_OBJ_FILE_MODE_NULL,    "NULL" },
{ AL_OBJ_FILE_MODE_READ,    "READ" },
{ AL_OBJ_FILE_MODE_WRITE,   "WRITE" },
{ AL_OBJ_FILE_MODE_APPEND,  "APPEND" },
{ 0, NULL }
};
static const value_string dnp3_al_file_status_vals[] = {
{ 0,    "SUCCESS" },
{ 1,    "PERMISSION DENIED" },
{ 2,    "INVALID MODE" },
{ 3,    "FILE NOT FOUND" },
{ 4,    "FILE LOCKED" },
{ 5,    "TOO MANY OPEN" },
{ 6,    "INVALID HANDLE" },
{ 7,    "WRITE BLOCK SIZE" },
{ 8,    "COMM LOST" },
{ 9,    "CANNOT ABORT" },
{ 16,   "NOT OPENED" },
{ 17,   "HANDLE EXPIRED" },
{ 18,   "BUFFER OVERRUN" },
{ 19,   "FATAL" },
{ 20,   "BLOCK SEQUENCE" },
{ 255,  "UNDEFINED" },
{ 0, NULL }
};
static value_string_ext dnp3_al_file_status_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_file_status_vals);
static const value_string dnp3_al_data_type_vals[] = {
{ AL_DATA_TYPE_NONE,        "NONE (Placeholder)" },
{ AL_DATA_TYPE_VSTR,        "VSTR (Visible ASCII String)" },
{ AL_DATA_TYPE_UINT,        "UINT (Unsigned Integer)" },
{ AL_DATA_TYPE_INT,         "INT (Signed Integer)" },
{ AL_DATA_TYPE_FLT,         "FLT (Floating Point)" },
{ AL_DATA_TYPE_OSTR,        "OSTR (Octet String)" },
{ AL_DATA_TYPE_BSTR,        "BSTR (Bit String)" },
{ AL_DATA_TYPE_TIME,        "TIME (DNP3 Time UINT48)" },
{ AL_DATA_TYPE_UNCD,        "UNCD (Unicode String)" },
{ AL_DATA_TYPE_U8BS8LIST,   "U8BS8LIST (List of UINT8 - BSTR8 pairs)" },
{ AL_DATA_TYPE_U8BS8EXLIST, "U8BS8EXLIST (Extended List of UINT8 - BSTR8 pairs)" },
{ 0, NULL }
};
static const value_string dnp3_al_read_obj_vals[] = {
{ (AL_OBJ_DA_GRP     & 0xFF00),  "Device Attribute"            },
{ (AL_OBJ_BI_ALL     & 0xFF00),  "Binary Input"                },
{ (AL_OBJ_BIC_ALL    & 0xFF00),  "Binary Input Change"         },
{ (AL_OBJ_2BI_ALL    & 0xFF00),  "Double-bit Input"            },
{ (AL_OBJ_2BIC_ALL   & 0xFF00),  "Double-bit Input Change"     },
{ (AL_OBJ_BO_ALL     & 0xFF00),  "Binary Output"               },
{ (AL_OBJ_BOC_ALL    & 0xFF00),  "Binary Output Change"        },
{ (AL_OBJ_CTR_ALL    & 0xFF00),  "Counter"                     },
{ (AL_OBJ_FCTR_ALL   & 0xFF00),  "Frozen Counter"              },
{ (AL_OBJ_CTRC_ALL   & 0xFF00),  "Counter Change"              },
{ (AL_OBJ_FCTRC_ALL  & 0xFF00),  "Frozen Counter Change"       },
{ (AL_OBJ_AI_ALL     & 0xFF00),  "Analog Input"                },
{ (AL_OBJ_AIC_ALL    & 0xFF00),  "Analog Input Change"         },
{ (AL_OBJ_AO_ALL     & 0xFF00),  "Analog Output"               },
{ (AL_OBJ_AOC_ALL    & 0xFF00),  "Analog Output Change"        },
{ (AL_OBJ_TD_ALL     & 0xFF00),  "Time and Date"               },
{ (AL_OBJ_FILE_CMD   & 0xFF00),  "File Control"                },
{ (AL_OBJ_IIN        & 0xFF00),  "Internal Indications"        },
{ (AL_OBJ_OCT        & 0xFF00),  "Octet String"                },
{ (AL_OBJ_OCT_EVT    & 0xFF00),  "Octet String Event"          },
{ (AL_OBJ_VT_EVTD    & 0xFF00),  "Virtual Terminal Event Data" },
{ (AL_OBJ_SA_AUTH_CH & 0xFF00),  "Secure Authentication" },
{ 0, NULL }
};
static value_string_ext dnp3_al_read_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_read_obj_vals);
static const value_string dnp3_al_write_obj_vals[] = {
{ (AL_OBJ_TD_ALL     & 0xFF00),  "Time and Date"                 },
{ (AL_OBJ_FILE_CMD   & 0xFF00),  "File Control"                  },
{ (AL_OBJ_IIN        & 0xFF00),  "Internal Indications"          },
{ (AL_OBJ_OCT        & 0xFF00),  "Octet String"                  },
{ (AL_OBJ_OCT_EVT    & 0xFF00),  "Octet String Event"            },
{ (AL_OBJ_VT_OBLK    & 0xFF00),  "Virtual Terminal Output Block" },
{ (AL_OBJ_SA_AUTH_CH & 0xFF00),  "Secure Authentication" },
{ 0, NULL }
};
static value_string_ext dnp3_al_write_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_write_obj_vals);
static const value_string dnp3_al_sa_kwa_vals[] = {
{ 0,  "Unused"       },
{ 1,  "AES-128"      },
{ 2,  "AES-256"      },
{ 0, NULL }
};
static const value_string dnp3_al_sa_ks_vals[] = {
{ 0,  "Not Used"    },
{ 1,  "OK"          },
{ 2,  "NOT_INIT"    },
{ 3,  "COMM_FAIL"   },
{ 4,  "AUTH_FAIL"   },
{ 0, NULL }
};
static const value_string dnp3_al_sa_mal_vals[] = {
{ 0,  "No MAC value in this message"                     },
{ 1,  "HMAC SHA-1 truncated to 4 octets (serial)"        },
{ 2,  "HMAC SHA-1 truncated to 10 octets (networked)"    },
{ 3,  "HMAC SHA-256 truncated to 8 octets (serial)"      },
{ 4,  "HMAC SHA-256 truncated to 16 octets (networked)"  },
{ 5,  "HMAC SHA-1 truncated to 8 octets (serial)"        },
{ 6,  "AES-GMAC (output is 12 octets)"                   },
{ 0, NULL }
};
static const value_string dnp3_al_sa_err_vals[] = {
{ 0,  "Not used"                                 },
{ 1,  "Authentication failed"                    },
{ 2,  "Unexpected Response"                      },
{ 3,  "No response"                              },
{ 4,  "Aggressive Mode not supported"            },
{ 5,  "MAC Algorithm not supproted"              },
{ 6,  "Key Wrap Algorithm not supported"         },
{ 7,  "Authorization failed"                     },
{ 8,  "Update Key Change Method not permitted"   },
{ 9,  "Invalid Signature"                        },
{ 10, "Invalid Certification Data"               },
{ 11, "Unknown User"                             },
{ 12, "Max Session Key Status Requests Exceeded" },
{ 0, NULL }
};
static const value_string dnp3_al_sa_kcm_vals[] = {
{ 0,  "Not used"                                          },
{ 1,  "Obsolete. Do Not Use"                              },
{ 2,  "Obsolete. Do Not Use"                              },
{ 3,  "Symmetric ASE-128 / SHA-1-HMAC"                    },
{ 4,  "Symmetric ASE-256 / SHA-256-HMAC"                  },
{ 5,  "Symmetric ASE-256 / AES-GMAC"                      },
{ 64,  "Obsolete. Do Not Use"                             },
{ 65,  "Obsolete. Do Not Use"                             },
{ 66,  "Obsolete. Do Not Use"                             },
{ 67,  "Asymmetric RS-1024 / DSA SHA-1 / SHA-1-HMAC"      },
{ 68,  "Asymmetric RSA-2048 / DSA SHA-256 / SHA-256-HMAC" },
{ 69,  "Asymmetric RSA-3072 / DSA SHA-256 / SHA-256-HMAC" },
{ 70,  "Asymmetric RSA-2048 / DSA SHA-256 / AES-GMAC"     },
{ 71,  "Asymmetric RSA-3072 / DSA SHA-256 / AES-GMAC"     },
{ 0, NULL }
};
static const value_string dnp3_al_sa_rfc_vals[] = {
{ 0,  "Not Used"    },
{ 1,  "CRITICAL"    },
{ 0, NULL }
};
static const value_string dnp3_al_sa_secstat_vals[] = {
{ 0,  "(Unexpected Messages)"                   },
{ 1,  "(Authorization Failures)"                },
{ 2,  "(Authentication Failures)"               },
{ 3,  "(Reply Timeouts)"                        },
{ 4,  "(Rekeys Due to Authentication Failure)"  },
{ 5,  "(Total Messages Sent)"                   },
{ 6,  "(Total Messages Received)"               },
{ 7,  "(Critical Messages Sent)"                },
{ 8,  "(Critical Messages Received)"            },
{ 9,  "(Discarded Messages)"                    },
{ 10,  "(Error Messages Sent)"                  },
{ 11,  "(Error Messages Rxed)"                  },
{ 12,  "(Successful Authentications)"           },
{ 13,  "(Session Key Changes)"                  },
{ 14,  "(Failed Session Key Changes)"           },
{ 15,  "(Update Key Changes)"                   },
{ 16,  "(Failed Update Key Changes)"            },
{ 17,  "(Rekeys Due to Restarts)"               },
{ 0, NULL }
};
static value_string_ext dnp3_al_sa_secstat_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_sa_secstat_vals);
static gint ett_dnp3 = -1;
static gint ett_dnp3_dl = -1;
static gint ett_dnp3_dl_ctl = -1;
static gint ett_dnp3_tr_ctl = -1;
static gint ett_dnp3_dl_data = -1;
static gint ett_dnp3_dl_chunk = -1;
static gint ett_dnp3_al = -1;
static gint ett_dnp3_al_ctl = -1;
static gint ett_dnp3_al_obj_point_tcc = -1;
static gint ett_dnp3_al_iin = -1;
static gint ett_dnp3_al_obj = -1;
static gint ett_dnp3_al_obj_qualifier = -1;
static gint ett_dnp3_al_obj_range = -1;
static gint ett_dnp3_al_objdet = -1;
static gint ett_dnp3_al_obj_quality = -1;
static gint ett_dnp3_al_obj_point = -1;
static gint ett_dnp3_al_obj_point_perms = -1;
static expert_field ei_dnp_num_items_neg = EI_INIT;
static expert_field ei_dnp_invalid_length = EI_INIT;
static expert_field ei_dnp_iin_abnormal = EI_INIT;
static expert_field ei_dnp3_data_hdr_crc_incorrect = EI_INIT;
static expert_field ei_dnp3_data_chunk_crc_incorrect = EI_INIT;
static expert_field ei_dnp3_unknown_object = EI_INIT;
static expert_field ei_dnp3_unknown_group0_variation = EI_INIT;
static expert_field ei_dnp3_num_items_invalid = EI_INIT;
static reassembly_table al_reassembly_table;
static int   hf_al_frag_data   = -1;
static int   hf_dnp3_fragment  = -1;
static int   hf_dnp3_fragments = -1;
static int   hf_dnp3_fragment_overlap = -1;
static int   hf_dnp3_fragment_overlap_conflict = -1;
static int   hf_dnp3_fragment_multiple_tails = -1;
static int   hf_dnp3_fragment_too_long_fragment = -1;
static int   hf_dnp3_fragment_error = -1;
static int   hf_dnp3_fragment_count = -1;
static int   hf_dnp3_fragment_reassembled_in = -1;
static int   hf_dnp3_fragment_reassembled_length = -1;
static gint ett_dnp3_fragment  = -1;
static gint ett_dnp3_fragments = -1;
static dissector_handle_t dnp3_tcp_handle;
static dissector_handle_t dnp3_udp_handle;
static const fragment_items dnp3_frag_items = {
&ett_dnp3_fragment,
&ett_dnp3_fragments,
&hf_dnp3_fragments,
&hf_dnp3_fragment,
&hf_dnp3_fragment_overlap,
&hf_dnp3_fragment_overlap_conflict,
&hf_dnp3_fragment_multiple_tails,
&hf_dnp3_fragment_too_long_fragment,
&hf_dnp3_fragment_error,
&hf_dnp3_fragment_count,
&hf_dnp3_fragment_reassembled_in,
&hf_dnp3_fragment_reassembled_length,
NULL,
"DNP 3.0 fragments"
};
static gboolean dnp3_desegment = TRUE;
enum QUALITY_TYPE {
BIN_IN,
BIN_OUT,
ANA_IN,
ANA_OUT,
COUNTER
};
static guint16
calculateCRC(const void *buf, guint len) {
guint16 crc = crc16_0x3D65_seed((const guint8 *)buf, len, 0);
return ~crc;
}
static guint16
calculateCRCtvb(tvbuff_t *tvb, guint offset, guint len) {
guint16 crc = crc16_0x3D65_tvb_offset_seed(tvb, offset, len, 0);
return ~crc;
}
static void
dnp3_al_process_iin(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *al_tree)
{
guint16     al_iin;
proto_item *tiin;
static int* const indications[] = {
&hf_dnp3_al_iin_rst,
&hf_dnp3_al_iin_dt,
&hf_dnp3_al_iin_dol,
&hf_dnp3_al_iin_tsr,
&hf_dnp3_al_iin_cls3d,
&hf_dnp3_al_iin_cls2d,
&hf_dnp3_al_iin_cls1d,
&hf_dnp3_al_iin_bmsg,
&hf_dnp3_al_iin_cc,
&hf_dnp3_al_iin_oae,
&hf_dnp3_al_iin_ebo,
&hf_dnp3_al_iin_pioor,
&hf_dnp3_al_iin_obju,
&hf_dnp3_al_iin_fcni,
NULL
};
tiin = proto_tree_add_bitmask(al_tree, tvb, offset, hf_dnp3_al_iin, ett_dnp3_al_iin, indications, ENC_BIG_ENDIAN);
al_iin = tvb_get_ntohs(tvb, offset);
if ((al_iin & AL_IIN_DT) || (al_iin & AL_IIN_CC) || (al_iin & AL_IIN_OAE) || (al_iin & AL_IIN_EBO) ||
(al_iin & AL_IIN_PIOOR) || (al_iin & AL_IIN_OBJU) || (al_iin & AL_IIN_FCNI)) {
expert_add_info(pinfo, tiin, &ei_dnp_iin_abnormal);
}
}
static int
dnp3_al_obj_procprefix(tvbuff_t *tvb, int offset, guint8 al_objq_prefix, guint32 *al_ptaddr, proto_tree *item_tree)
{
int         prefixbytes = 0;
proto_item *prefix_item;
switch (al_objq_prefix)
{
case AL_OBJQL_PREFIX_NI:
prefixbytes = 0;
prefix_item = proto_tree_add_uint(item_tree, hf_dnp3_al_point_index, tvb, offset, 0, *al_ptaddr);
proto_item_set_generated(prefix_item);
break;
case AL_OBJQL_PREFIX_1O:
*al_ptaddr = tvb_get_guint8(tvb, offset);
proto_tree_add_item(item_tree, hf_dnp3_al_index8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
prefixbytes = 1;
break;
case AL_OBJQL_PREFIX_2O:
*al_ptaddr = tvb_get_letohs(tvb, offset);
proto_tree_add_item(item_tree, hf_dnp3_al_index16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
prefixbytes = 2;
break;
case AL_OBJQL_PREFIX_4O:
*al_ptaddr = tvb_get_letohl(tvb, offset);
proto_tree_add_item(item_tree, hf_dnp3_al_index32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
prefixbytes = 4;
break;
case AL_OBJQL_PREFIX_1OS:
*al_ptaddr = tvb_get_guint8(tvb, offset);
proto_tree_add_item(item_tree, hf_dnp3_al_size8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
prefixbytes = 1;
break;
case AL_OBJQL_PREFIX_2OS:
*al_ptaddr = tvb_get_letohs(tvb, offset);
proto_tree_add_item(item_tree, hf_dnp3_al_size16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
prefixbytes = 2;
break;
case AL_OBJQL_PREFIX_4OS:
*al_ptaddr = tvb_get_letohl(tvb, offset);
proto_tree_add_item(item_tree, hf_dnp3_al_size32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
prefixbytes = 4;
break;
}
return prefixbytes;
}
static void
dnp3_append_2item_text(proto_item *item1, proto_item *item2, const gchar *text)
{
proto_item_append_text(item1, "%s", text);
proto_item_append_text(item2, "%s", text);
}
static void
dnp3_al_obj_quality(tvbuff_t *tvb, int offset, guint8 al_ptflags, proto_tree *point_tree, proto_item *point_item, enum QUALITY_TYPE type)
{
proto_tree *quality_tree;
proto_item *quality_item;
int         hf0 = 0, hf1 = 0, hf2 = 0, hf3 = 0, hf4 = 0, hf5 = 0, hf6 = 0, hf7 = 0;
proto_item_append_text(point_item, " (Quality: ");
quality_tree = proto_tree_add_subtree(point_tree, tvb, offset, 1, ett_dnp3_al_obj_quality, &quality_item, "Quality: ");
if (al_ptflags & AL_OBJ_BI_FLAG0) {
dnp3_append_2item_text(point_item, quality_item, "Online");
}
else {
dnp3_append_2item_text(point_item, quality_item, "Offline");
}
if (al_ptflags & AL_OBJ_BI_FLAG1)
 dnp3_append_2item_text(point_item, quality_item, ", Restart");
if (al_ptflags & AL_OBJ_BI_FLAG2)
 dnp3_append_2item_text(point_item, quality_item, ", Comm Fail");
if (al_ptflags & AL_OBJ_BI_FLAG3)
 dnp3_append_2item_text(point_item, quality_item, ", Remote Force");
if (al_ptflags & AL_OBJ_BI_FLAG4)
 dnp3_append_2item_text(point_item, quality_item, ", Local Force");
switch (type) {
case BIN_IN:
if (al_ptflags & AL_OBJ_BI_FLAG5)
 dnp3_append_2item_text(point_item, quality_item, ", Chatter Filter");
hf0 = hf_dnp3_al_biq_b0;
hf1 = hf_dnp3_al_biq_b1;
hf2 = hf_dnp3_al_biq_b2;
hf3 = hf_dnp3_al_biq_b3;
hf4 = hf_dnp3_al_biq_b4;
hf5 = hf_dnp3_al_biq_b5;
hf6 = hf_dnp3_al_biq_b6;
hf7 = hf_dnp3_al_biq_b7;
break;
case BIN_OUT:
hf0 = hf_dnp3_al_boq_b0;
hf1 = hf_dnp3_al_boq_b1;
hf2 = hf_dnp3_al_boq_b2;
hf3 = hf_dnp3_al_boq_b3;
hf4 = hf_dnp3_al_boq_b4;
hf5 = hf_dnp3_al_boq_b5;
hf6 = hf_dnp3_al_boq_b6;
hf7 = hf_dnp3_al_boq_b7;
break;
case ANA_IN:
if (al_ptflags & AL_OBJ_AI_FLAG5)
 dnp3_append_2item_text(point_item, quality_item, ", Over-Range");
if (al_ptflags & AL_OBJ_AI_FLAG6)
 dnp3_append_2item_text(point_item, quality_item, ", Reference Check");
hf0 = hf_dnp3_al_aiq_b0;
hf1 = hf_dnp3_al_aiq_b1;
hf2 = hf_dnp3_al_aiq_b2;
hf3 = hf_dnp3_al_aiq_b3;
hf4 = hf_dnp3_al_aiq_b4;
hf5 = hf_dnp3_al_aiq_b5;
hf6 = hf_dnp3_al_aiq_b6;
hf7 = hf_dnp3_al_aiq_b7;
break;
case ANA_OUT:
hf0 = hf_dnp3_al_aoq_b0;
hf1 = hf_dnp3_al_aoq_b1;
hf2 = hf_dnp3_al_aoq_b2;
hf3 = hf_dnp3_al_aoq_b3;
hf4 = hf_dnp3_al_aoq_b4;
hf5 = hf_dnp3_al_aoq_b5;
hf6 = hf_dnp3_al_aoq_b6;
hf7 = hf_dnp3_al_aoq_b7;
break;
case COUNTER:
if (al_ptflags & AL_OBJ_CTR_FLAG5)
 dnp3_append_2item_text(point_item, quality_item, ", Roll-over");
if (al_ptflags & AL_OBJ_CTR_FLAG6)
 dnp3_append_2item_text(point_item, quality_item, ", Discontinuity");
hf0 = hf_dnp3_al_ctrq_b0;
hf1 = hf_dnp3_al_ctrq_b1;
hf2 = hf_dnp3_al_ctrq_b2;
hf3 = hf_dnp3_al_ctrq_b3;
hf4 = hf_dnp3_al_ctrq_b4;
hf5 = hf_dnp3_al_ctrq_b5;
hf6 = hf_dnp3_al_ctrq_b6;
hf7 = hf_dnp3_al_ctrq_b7;
break;
}
if (quality_tree != NULL) {
proto_tree_add_item(quality_tree, hf7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(quality_tree, hf0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}
proto_item_append_text(point_item, ")");
}
static void
dnp3_al_get_timestamp(nstime_t *timestamp, tvbuff_t *tvb, int data_pos)
{
guint32 hi, lo;
guint64 time_ms;
lo = tvb_get_letohs(tvb, data_pos);
hi = tvb_get_letohl(tvb, data_pos + 2);
time_ms = (guint64)hi * 0x10000 + lo;
timestamp->secs  = (long)(time_ms / 1000);
timestamp->nsecs = (int)(time_ms % 1000) * 1000000;
}
static gboolean
dnp3_al_empty_obj(guint16 al_obj)
{
switch (al_obj)
{
case AL_OBJ_BI_ALL:
case AL_OBJ_BIC_ALL:
case AL_OBJ_BOC_ALL:
case AL_OBJ_2BI_ALL:
case AL_OBJ_2BIC_ALL:
case AL_OBJ_CTR_ALL:
case AL_OBJ_CTRC_ALL:
case AL_OBJ_AI_ALL:
case AL_OBJ_AIC_ALL:
case AL_OBJ_AIDB_ALL:
case AL_OBJ_AOC_ALL:
case AL_OBJ_CLASS0:
case AL_OBJ_CLASS1:
case AL_OBJ_CLASS2:
case AL_OBJ_CLASS3:
return TRUE;
break;
default:
return FALSE;
break;
}
}
static int
dnp3_al_process_object(tvbuff_t *tvb, packet_info *pinfo, int offset,
proto_tree *robj_tree, gboolean header_only,
guint16 *al_objtype, nstime_t *al_cto)
{
guint8      al_objq, al_objq_prefix, al_objq_range, al_oct_len = 0, bitindex;
guint16     al_obj, temp;
guint32     al_ptaddr = 0;
int         num_items = 0;
int         orig_offset, rangebytes = 0;
proto_item *object_item, *range_item;
proto_tree *object_tree, *qualifier_tree, *range_tree;
const gchar  *sec_stat_str;
orig_offset = offset;
*al_objtype =al_obj = tvb_get_ntohs(tvb, offset);
temp = al_obj & 0xFF00;
if ((temp == AL_OBJ_OCT) || (temp == AL_OBJ_OCT_EVT )) {
al_oct_len = al_obj & 0xFF;
al_obj = temp;
}
if ((al_obj == AL_OBJ_SA_AUTH_AGMRQ) || (al_obj == AL_OBJ_SA_AUTH_MAC)) {
header_only = FALSE;
}
if (AL_OBJ_GROUP(al_obj) == 0x0) {
object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
"Object(s): %s (0x%04x)",
val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown group 0 Variation"),
al_obj);
if (try_val_to_str_ext(al_obj, &dnp3_al_obj_vals_ext) == NULL) {
expert_add_info(pinfo, object_item, &ei_dnp3_unknown_group0_variation);
}
}
else if ((AL_OBJ_GROUP(al_obj) == AL_OBJ_GROUP(AL_OBJ_OCT)) || (AL_OBJ_GROUP(al_obj) == AL_OBJ_GROUP(AL_OBJ_OCT_EVT))) {
object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
"Object(s): %s (0x%04x), Length: %d",
val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown Object\\Variation"),
al_obj, al_oct_len);
}
else {
object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
"Object(s): %s (0x%04x)",
val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown Object\\Variation"),
al_obj);
if (try_val_to_str_ext(al_obj, &dnp3_al_obj_vals_ext) == NULL) {
expert_add_info(pinfo, object_item, &ei_dnp3_unknown_object);
}
}
object_tree = proto_item_add_subtree(object_item, ett_dnp3_al_obj);
offset += 2;
al_objq = tvb_get_guint8(tvb, offset);
al_objq_prefix = al_objq & AL_OBJQ_PREFIX;
al_objq_prefix = al_objq_prefix >> 4;
al_objq_range = al_objq & AL_OBJQ_RANGE;
qualifier_tree = proto_tree_add_subtree_format(object_tree, tvb, offset, 1, ett_dnp3_al_obj_qualifier, NULL,
"Qualifier Field, Prefix: %s, Range: %s",
val_to_str_ext_const(al_objq_prefix, &dnp3_al_objq_prefix_vals_ext, "Unknown Prefix Type"),
val_to_str_ext_const(al_objq_range, &dnp3_al_objq_range_vals_ext, "Unknown Range Type"));
proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_range, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
range_tree = proto_tree_add_subtree(object_tree, tvb, offset, 0, ett_dnp3_al_obj_range, &range_item, "Number of Items: ");
switch (al_objq_range)
{
case AL_OBJQL_RANGE_SSI8:
num_items = ( tvb_get_guint8(tvb, offset+1) - tvb_get_guint8(tvb, offset) + 1);
proto_item_set_generated(range_item);
al_ptaddr = tvb_get_guint8(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_start8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(range_tree, hf_dnp3_al_range_stop8, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
rangebytes = 2;
break;
case AL_OBJQL_RANGE_SSI16:
num_items = ( tvb_get_letohs(tvb, offset+2) - tvb_get_letohs(tvb, (offset)) + 1);
proto_item_set_generated(range_item);
al_ptaddr = tvb_get_letohs(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_start16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(range_tree, hf_dnp3_al_range_stop16, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
rangebytes = 4;
break;
case AL_OBJQL_RANGE_SSI32:
num_items = ( tvb_get_letohl(tvb, offset+4) - tvb_get_letohl(tvb, offset) + 1);
proto_item_set_generated(range_item);
al_ptaddr = tvb_get_letohl(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_start32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
proto_tree_add_item(range_tree, hf_dnp3_al_range_stop32, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
rangebytes = 8;
break;
case AL_OBJQL_RANGE_AA8:
num_items = 1;
proto_item_set_generated(range_item);
al_ptaddr = tvb_get_guint8(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_abs8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
rangebytes = 1;
break;
case AL_OBJQL_RANGE_AA16:
num_items = 1;
proto_item_set_generated(range_item);
al_ptaddr = tvb_get_letohs(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_abs16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
rangebytes = 2;
break;
case AL_OBJQL_RANGE_AA32:
num_items = 1;
proto_item_set_generated(range_item);
al_ptaddr = tvb_get_letohl(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_abs32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
rangebytes = 4;
break;
case AL_OBJQL_RANGE_SF8:
num_items = tvb_get_guint8(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
rangebytes = 1;
proto_item_set_len(range_item, rangebytes);
break;
case AL_OBJQL_RANGE_SF16:
num_items = tvb_get_letohs(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_quant16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
rangebytes = 2;
proto_item_set_len(range_item, rangebytes);
break;
case AL_OBJQL_RANGE_SF32:
num_items = tvb_get_letohl(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_quant32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
rangebytes = 4;
proto_item_set_len(range_item, rangebytes);
break;
case AL_OBJQL_RANGE_FF:
num_items = tvb_get_guint8(tvb, offset);
proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
rangebytes = 1;
proto_item_set_len(range_item, rangebytes);
}
if (num_items > 0) {
proto_item_append_text(object_item, ", %d point%s", num_items, plurality(num_items, "", "s"));
}
proto_item_append_text(range_item, "%d", num_items);
if (num_items < 0) {
proto_item_append_text(range_item, " (bogus)");
expert_add_info(pinfo, range_item, &ei_dnp_num_items_neg);
return tvb_captured_length(tvb);
}
offset += rangebytes;
bitindex = 0;
if (!header_only || al_objq_prefix > 0) {
int item_num;
int start_offset;
start_offset = offset;
for (item_num = 0; item_num < num_items; item_num++)
{
proto_item *point_item;
proto_tree *point_tree;
guint       data_pos;
int         prefixbytes;
if (al_objq_prefix <= AL_OBJQL_PREFIX_4O) {
point_tree = proto_tree_add_subtree(object_tree, tvb, offset, -1, ett_dnp3_al_obj_point, &point_item, "Point Number");
}
else {
point_tree = proto_tree_add_subtree(object_tree, tvb, offset, -1, ett_dnp3_al_obj_point, &point_item, "Object: Size");
}
data_pos   = offset;
prefixbytes = dnp3_al_obj_procprefix(tvb, offset, al_objq_prefix, &al_ptaddr, point_tree);
if (dnp3_al_empty_obj(al_obj)) {
proto_item_append_text(range_item, " (bogus)");
expert_add_info(pinfo, range_item, &ei_dnp3_num_items_invalid);
num_items = 0;
}
proto_item_append_text(point_item, " %u", al_ptaddr);
proto_item_set_len(point_item, prefixbytes);
data_pos += prefixbytes;
if (!header_only || (AL_OBJQL_PREFIX_1OS <= al_objq_prefix && al_objq_prefix <= AL_OBJQL_PREFIX_4OS)) {
guint8       al_2bit, al_ptflags, al_bi_val, al_tcc_code, al_sa_mac_len;
gint16       al_val_int16;
guint16      al_val_uint16, al_ctlobj_stat;
guint16      al_relms, al_filename_len, al_file_ctrl_mode;
guint16      sa_username_len, sa_challengedata_len, sa_updatekey_len;
gint32       al_val_int32;
guint32      al_val_uint32, file_data_size;
nstime_t     al_reltime, al_abstime;
gboolean     al_bit;
gfloat       al_valflt;
gdouble      al_valdbl;
const gchar *ctl_status_str;
if (AL_OBJ_GROUP(al_obj) == 0x0) {
guint32 data_type;
guint8 da_len;
proto_tree_add_item_ret_uint(point_tree, hf_dnp3_al_datatype, tvb, data_pos, 1, ENC_LITTLE_ENDIAN, &data_type);
data_pos++;
if (try_val_to_str(data_type, dnp3_al_data_type_vals) != NULL) {
switch(data_type) {
case AL_DATA_TYPE_NONE:
break;
case AL_DATA_TYPE_VSTR:
da_len = tvb_get_guint8(tvb, data_pos);
proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos++;
const guint8* da_value;
proto_tree_add_item_ret_string(point_tree, hf_dnp3_al_da_value, tvb, data_pos, da_len, ENC_ASCII|ENC_NA, pinfo->pool, &da_value);
proto_item_append_text(object_item, ", Value: %s", da_value);
data_pos += da_len;
break;
case AL_DATA_TYPE_UINT:
da_len = tvb_get_guint8(tvb, data_pos);
proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos++;
if (da_len == 1) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_uint8, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %u", tvb_get_guint8(tvb, data_pos));
data_pos++;
}
else if (da_len == 2) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_uint16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %u", tvb_get_letohs(tvb, data_pos));
data_pos += 2;
}
else if (da_len == 4) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_uint32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %u", tvb_get_letohl(tvb, data_pos));
data_pos += 4;
}
break;
case AL_DATA_TYPE_INT:
da_len = tvb_get_guint8(tvb, data_pos);
proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos++;
if (da_len == 1) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_int8, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %d", tvb_get_guint8(tvb, data_pos));
data_pos++;
}
else if (da_len == 2) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_int16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %d", tvb_get_letohs(tvb, data_pos));
data_pos += 2;
}
else if (da_len == 4) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_int32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %d", tvb_get_letohl(tvb, data_pos));
data_pos += 4;
}
break;
case AL_DATA_TYPE_FLT:
da_len = tvb_get_guint8(tvb, data_pos);
proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos++;
if (da_len == 4) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_flt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %g", tvb_get_letohieee_float(tvb, data_pos));
data_pos += 4;
}
else if (da_len == 8) {
proto_tree_add_item(point_tree, hf_dnp3_al_da_dbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
proto_item_append_text(object_item, ", Value: %g", tvb_get_letohieee_double(tvb, data_pos));
data_pos += 8;
}
break;
case AL_DATA_TYPE_OSTR:
break;
case AL_DATA_TYPE_BSTR:
break;
case AL_DATA_TYPE_TIME:
break;
case AL_DATA_TYPE_UNCD:
break;
case AL_DATA_TYPE_U8BS8LIST:
break;
case AL_DATA_TYPE_U8BS8EXLIST:
break;
}
}
offset = data_pos;
}
else {
switch (al_obj)
{
case AL_OBJ_BI_ALL:
case AL_OBJ_BIC_ALL:
case AL_OBJ_BOC_ALL:
case AL_OBJ_2BI_ALL:
case AL_OBJ_2BIC_ALL:
case AL_OBJ_CTR_ALL:
case AL_OBJ_CTRC_ALL:
case AL_OBJ_AI_ALL:
case AL_OBJ_AIC_ALL:
case AL_OBJ_AIDB_ALL:
case AL_OBJ_AOC_ALL:
case AL_OBJ_CLASS0:
case AL_OBJ_CLASS1:
case AL_OBJ_CLASS2:
case AL_OBJ_CLASS3:
offset = data_pos;
break;
case AL_OBJ_BI_1BIT:
case AL_OBJ_BO:
case AL_OBJ_CTL_PMASK:
case AL_OBJ_IIN:
al_bi_val = tvb_get_guint8(tvb, data_pos);
al_bit = (al_bi_val & 1) > 0;
if (al_obj == AL_OBJ_IIN) {
guint16 iin_bit = 0;
if (al_ptaddr < 8) {
iin_bit = 0x100 << al_ptaddr;
}
else {
iin_bit = 1 << (al_ptaddr - 8);
}
proto_item_append_text(point_item, " (%s), Value: %u",
val_to_str_const(iin_bit, dnp3_al_iin_vals, "Invalid IIN bit"), al_bit);
}
else
{
if (al_objq_prefix != AL_OBJQL_PREFIX_NI) {
bitindex = 7;
}
else {
al_bit = (al_bi_val & (1 << bitindex)) > 0;
}
proto_item_append_text(point_item, ", Value: %u", al_bit);
}
proto_tree_add_boolean(point_tree, hf_dnp3_al_bit, tvb, data_pos, 1, al_bit);
proto_item_set_len(point_item, prefixbytes + 1);
bitindex++;
if ((bitindex > 7) || (item_num == (num_items-1)))
{
bitindex = 0;
offset += (prefixbytes + 1);
}
break;
case AL_OBJ_2BI_NF:
if (bitindex > 3)
{
bitindex = 0;
offset += (prefixbytes + 1);
}
al_bi_val = tvb_get_guint8(tvb, offset);
al_2bit = ((al_bi_val >> (bitindex << 1)) & 3);
proto_item_append_text(point_item, ", Value: %u", al_2bit);
proto_tree_add_uint(point_tree, hf_dnp3_al_2bit, tvb, offset, 1, al_2bit);
proto_item_set_len(point_item, prefixbytes + 1);
if (item_num == (num_items-1))
{
offset += (prefixbytes + 1);
}
bitindex++;
break;
case AL_OBJ_BI_STAT:
case AL_OBJ_BIC_NOTIME:
case AL_OBJ_BO_STAT:
case AL_OBJ_BOC_NOTIME:
al_ptflags = tvb_get_guint8(tvb, data_pos);
switch (al_obj) {
case AL_OBJ_BI_STAT:
case AL_OBJ_BIC_NOTIME:
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
break;
case AL_OBJ_BO_STAT:
case AL_OBJ_BOC_NOTIME:
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_OUT);
break;
}
data_pos += 1;
al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) > 0;
proto_item_append_text(point_item, ", Value: %u", al_bit);
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_2BI_STAT:
case AL_OBJ_2BIC_NOTIME:
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
data_pos += 1;
al_2bit = (al_ptflags >> 6) & 3;
proto_item_append_text(point_item, ", Value: %u", al_2bit);
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_BIC_TIME:
case AL_OBJ_BOC_TIME:
al_ptflags = tvb_get_guint8(tvb, data_pos);
switch (al_obj) {
case AL_OBJ_BIC_TIME:
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
break;
case AL_OBJ_BOC_TIME:
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_OUT);
break;
}
data_pos += 1;
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7;
proto_item_append_text(point_item, ", Value: %u, Timestamp: %s",
al_bit, abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_2BIC_TIME:
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, (offset+prefixbytes), al_ptflags, point_tree, point_item, BIN_IN);
data_pos += 1;
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
al_2bit = (al_ptflags >> 6) & 3;
proto_item_append_text(point_item, ", Value: %u, Timestamp: %s",
al_2bit, abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_BIC_RTIME:
case AL_OBJ_2BIC_RTIME:
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
data_pos += 1;
al_relms = tvb_get_letohs(tvb, data_pos);
al_reltime.secs = al_relms / 1000;
al_reltime.nsecs = (al_relms % 1000) * 1000000;
nstime_sum(&al_abstime, al_cto, &al_reltime);
proto_tree_add_time(point_tree, hf_dnp3_al_rel_timestamp, tvb, data_pos, 2, &al_reltime);
data_pos += 2;
switch (al_obj) {
case AL_OBJ_BIC_RTIME:
al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7;
proto_item_append_text(point_item, ", Value: %u, Timestamp: %s",
al_bit, abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_item_set_len(point_item, data_pos - offset);
break;
case AL_OBJ_2BIC_RTIME:
al_2bit = (al_ptflags >> 6) & 3;
proto_item_append_text(point_item, ", Value: %u, Timestamp: %s",
al_2bit, abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_item_set_len(point_item, data_pos - offset);
break;
}
offset = data_pos;
break;
case AL_OBJ_CTLOP_BLK:
case AL_OBJ_CTL_PCB:
{
proto_tree  *tcc_tree;
al_tcc_code = tvb_get_guint8(tvb, data_pos);
tcc_tree = proto_tree_add_subtree_format(point_tree, tvb, data_pos, 1,
ett_dnp3_al_obj_point_tcc, NULL, "Control Code [0x%02x]",al_tcc_code);
proto_item_append_text(point_item, " [%s]", val_to_str_const((al_tcc_code & AL_OBJCTLC_CODE),
dnp3_al_ctlc_code_vals,
"Invalid Operation"));
proto_item_append_text(point_item, " [%s]", val_to_str_const((al_tcc_code & AL_OBJCTLC_TC) >> 6,
dnp3_al_ctlc_tc_vals,
"Invalid Qualifier"));
proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_c, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_m, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_tc, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_tree_add_item(point_tree, hf_dnp3_al_count, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_tree_add_item(point_tree, hf_dnp3_al_on_time, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_off_time, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
}
case AL_OBJ_BOE_NOTIME:
case AL_OBJ_BOE_TIME:
case AL_OBJ_AOC_32EVNT:
case AL_OBJ_AOC_16EVNT:
case AL_OBJ_AOC_32EVTT:
case AL_OBJ_AOC_16EVTT:
case AL_OBJ_AOC_FLTEVNT:
case AL_OBJ_AOC_DBLEVNT:
case AL_OBJ_AOC_FLTEVTT:
case AL_OBJ_AOC_DBLEVTT:
{
al_ctlobj_stat = tvb_get_guint8(tvb, data_pos) & AL_OBJCTL_STATUS_MASK;
ctl_status_str = val_to_str_ext(al_ctlobj_stat, &dnp3_al_ctl_status_vals_ext, "Invalid Status (0x%02x)");
proto_item_append_text(point_item, " [Status: %s (0x%02x)]", ctl_status_str, al_ctlobj_stat);
proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
switch(al_obj)
{
case AL_OBJ_BOE_NOTIME:
case AL_OBJ_BOE_TIME:
proto_tree_add_item(point_tree, hf_dnp3_bocs_bit, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
break;
case AL_OBJ_AOC_32EVNT:
case AL_OBJ_AOC_32EVTT:
data_pos += 1;
al_val_int32 = tvb_get_letohl(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int32);
proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
break;
case AL_OBJ_AOC_16EVNT:
case AL_OBJ_AOC_16EVTT:
data_pos += 1;
al_val_int16 = tvb_get_letohs(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int16);
proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
break;
case AL_OBJ_AOC_FLTEVNT:
case AL_OBJ_AOC_FLTEVTT:
data_pos += 1;
al_valflt = tvb_get_letohieee_float(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valflt);
proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AOC_DBLEVNT:
case AL_OBJ_AOC_DBLEVTT:
data_pos += 1;
al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valdbl);
proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
data_pos += 8;
break;
}
switch(al_obj)
{
case AL_OBJ_BOE_TIME:
case AL_OBJ_AOC_32EVTT:
case AL_OBJ_AOC_16EVTT:
case AL_OBJ_AOC_FLTEVTT:
case AL_OBJ_AOC_DBLEVTT:
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
break;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
}
case AL_OBJ_AO_32OPB:
case AL_OBJ_AO_16OPB:
case AL_OBJ_AO_FLTOPB:
case AL_OBJ_AO_DBLOPB:
switch (al_obj)
{
case AL_OBJ_AO_32OPB:
al_val_int32 = tvb_get_letohl(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int32);
proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AO_16OPB:
al_val_int16 = tvb_get_letohs(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int16);
proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
break;
case AL_OBJ_AO_FLTOPB:
al_valflt = tvb_get_letohieee_float(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valflt);
proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AO_DBLOPB:
al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valdbl);
proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
data_pos += 8;
break;
}
al_ctlobj_stat = tvb_get_guint8(tvb, data_pos) & AL_OBJCTL_STATUS_MASK;
ctl_status_str = val_to_str_ext(al_ctlobj_stat, &dnp3_al_ctl_status_vals_ext, "Invalid Status (0x%02x)");
proto_item_append_text(point_item, " [Status: %s (0x%02x)]", ctl_status_str, al_ctlobj_stat);
proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_CTR_32:
case AL_OBJ_CTR_16:
case AL_OBJ_DCTR_32:
case AL_OBJ_DCTR_16:
case AL_OBJ_CTR_32NF:
case AL_OBJ_CTR_16NF:
case AL_OBJ_DCTR_32NF:
case AL_OBJ_DCTR_16NF:
case AL_OBJ_FCTR_32:
case AL_OBJ_FCTR_16:
case AL_OBJ_FDCTR_32:
case AL_OBJ_FDCTR_16:
case AL_OBJ_FCTR_32T:
case AL_OBJ_FCTR_16T:
case AL_OBJ_FDCTR_32T:
case AL_OBJ_FDCTR_16T:
case AL_OBJ_FCTR_32NF:
case AL_OBJ_FCTR_16NF:
case AL_OBJ_FDCTR_32NF:
case AL_OBJ_FDCTR_16NF:
case AL_OBJ_CTRC_32:
case AL_OBJ_CTRC_16:
case AL_OBJ_DCTRC_32:
case AL_OBJ_DCTRC_16:
case AL_OBJ_CTRC_32T:
case AL_OBJ_CTRC_16T:
case AL_OBJ_DCTRC_32T:
case AL_OBJ_DCTRC_16T:
case AL_OBJ_FCTRC_32:
case AL_OBJ_FCTRC_16:
case AL_OBJ_FDCTRC_32:
case AL_OBJ_FDCTRC_16:
case AL_OBJ_FCTRC_32T:
case AL_OBJ_FCTRC_16T:
case AL_OBJ_FDCTRC_32T:
case AL_OBJ_FDCTRC_16T:
switch (al_obj)
{
case AL_OBJ_CTR_32NF:
case AL_OBJ_CTR_16NF:
case AL_OBJ_DCTR_32NF:
case AL_OBJ_DCTR_16NF:
case AL_OBJ_FCTR_32NF:
case AL_OBJ_FCTR_16NF:
case AL_OBJ_FDCTR_32NF:
case AL_OBJ_FDCTR_16NF:
break;
default:
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, COUNTER);
data_pos += 1;
break;
}
switch (al_obj)
{
case AL_OBJ_CTR_32:
case AL_OBJ_DCTR_32:
case AL_OBJ_CTR_32NF:
case AL_OBJ_DCTR_32NF:
case AL_OBJ_FCTR_32:
case AL_OBJ_FDCTR_32:
case AL_OBJ_FCTR_32T:
case AL_OBJ_FDCTR_32T:
case AL_OBJ_FCTR_32NF:
case AL_OBJ_FDCTR_32NF:
case AL_OBJ_CTRC_32:
case AL_OBJ_DCTRC_32:
case AL_OBJ_CTRC_32T:
case AL_OBJ_DCTRC_32T:
case AL_OBJ_FCTRC_32:
case AL_OBJ_FDCTRC_32:
case AL_OBJ_FCTRC_32T:
case AL_OBJ_FDCTRC_32T:
al_val_uint32 = tvb_get_letohl(tvb, data_pos);
proto_item_append_text(point_item, ", Count: %u", al_val_uint32);
proto_tree_add_item(point_tree, hf_dnp3_al_cnt32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_CTR_16:
case AL_OBJ_DCTR_16:
case AL_OBJ_CTR_16NF:
case AL_OBJ_DCTR_16NF:
case AL_OBJ_FCTR_16:
case AL_OBJ_FDCTR_16:
case AL_OBJ_FCTR_16T:
case AL_OBJ_FDCTR_16T:
case AL_OBJ_FCTR_16NF:
case AL_OBJ_FDCTR_16NF:
case AL_OBJ_CTRC_16:
case AL_OBJ_DCTRC_16:
case AL_OBJ_CTRC_16T:
case AL_OBJ_DCTRC_16T:
case AL_OBJ_FCTRC_16:
case AL_OBJ_FDCTRC_16:
case AL_OBJ_FCTRC_16T:
case AL_OBJ_FDCTRC_16T:
al_val_uint16 = tvb_get_letohs(tvb, data_pos);
proto_item_append_text(point_item, ", Count: %u", al_val_uint16);
proto_tree_add_item(point_tree, hf_dnp3_al_cnt16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
break;
}
switch (al_obj)
{
case AL_OBJ_FCTR_32T:
case AL_OBJ_FCTR_16T:
case AL_OBJ_FDCTR_32T:
case AL_OBJ_FDCTR_16T:
case AL_OBJ_CTRC_32T:
case AL_OBJ_CTRC_16T:
case AL_OBJ_DCTRC_32T:
case AL_OBJ_DCTRC_16T:
case AL_OBJ_FCTRC_32T:
case AL_OBJ_FCTRC_16T:
case AL_OBJ_FDCTRC_32T:
case AL_OBJ_FDCTRC_16T:
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
break;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_AI_32:
case AL_OBJ_AI_16:
case AL_OBJ_AI_32NF:
case AL_OBJ_AI_16NF:
case AL_OBJ_AI_FLT:
case AL_OBJ_AI_DBL:
case AL_OBJ_AIF_FLT:
case AL_OBJ_AIF_DBL:
case AL_OBJ_AIC_32NT:
case AL_OBJ_AIC_16NT:
case AL_OBJ_AIC_32T:
case AL_OBJ_AIC_16T:
case AL_OBJ_AIC_FLTNT:
case AL_OBJ_AIC_DBLNT:
case AL_OBJ_AIC_FLTT:
case AL_OBJ_AIC_DBLT:
case AL_OBJ_AIFC_FLTNT:
case AL_OBJ_AIFC_DBLNT:
case AL_OBJ_AIFC_FLTT:
case AL_OBJ_AIFC_DBLT:
case AL_OBJ_AIDB_16:
case AL_OBJ_AIDB_32:
case AL_OBJ_AIDB_FLT:
switch (al_obj)
{
case AL_OBJ_AI_32NF:
case AL_OBJ_AI_16NF:
case AL_OBJ_AIDB_16:
case AL_OBJ_AIDB_32:
case AL_OBJ_AIDB_FLT:
break;
default:
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, ANA_IN);
data_pos += 1;
break;
}
switch (al_obj)
{
case AL_OBJ_AI_32:
case AL_OBJ_AI_32NF:
case AL_OBJ_AIC_32NT:
case AL_OBJ_AIC_32T:
case AL_OBJ_AIDB_32:
al_val_int32 = tvb_get_letohl(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int32);
proto_tree_add_item(point_tree, hf_dnp3_al_ana32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AI_16:
case AL_OBJ_AI_16NF:
case AL_OBJ_AIC_16NT:
case AL_OBJ_AIC_16T:
case AL_OBJ_AIDB_16:
al_val_int16 = tvb_get_letohs(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int16);
proto_tree_add_item(point_tree, hf_dnp3_al_ana16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
break;
case AL_OBJ_AI_FLT:
case AL_OBJ_AIF_FLT:
case AL_OBJ_AIC_FLTNT:
case AL_OBJ_AIC_FLTT:
case AL_OBJ_AIFC_FLTNT:
case AL_OBJ_AIFC_FLTT:
case AL_OBJ_AIDB_FLT:
al_valflt = tvb_get_letohieee_float(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valflt);
proto_tree_add_item(point_tree, hf_dnp3_al_anaflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AI_DBL:
case AL_OBJ_AIF_DBL:
case AL_OBJ_AIC_DBLNT:
case AL_OBJ_AIC_DBLT:
case AL_OBJ_AIFC_DBLNT:
case AL_OBJ_AIFC_DBLT:
al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valdbl);
proto_tree_add_item(point_tree, hf_dnp3_al_anadbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
data_pos += 8;
break;
}
switch (al_obj)
{
case AL_OBJ_AIC_32T:
case AL_OBJ_AIC_16T:
case AL_OBJ_AIC_FLTT:
case AL_OBJ_AIC_DBLT:
case AL_OBJ_AIFC_FLTT:
case AL_OBJ_AIFC_DBLT:
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
break;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_AO_32:
case AL_OBJ_AO_16:
case AL_OBJ_AO_FLT:
case AL_OBJ_AO_DBL:
case AL_OBJ_AOC_32NT:
case AL_OBJ_AOC_16NT:
case AL_OBJ_AOC_32T:
case AL_OBJ_AOC_16T:
case AL_OBJ_AOC_FLTNT:
case AL_OBJ_AOC_DBLNT:
case AL_OBJ_AOC_FLTT:
case AL_OBJ_AOC_DBLT:
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, ANA_OUT);
data_pos += 1;
switch (al_obj)
{
case AL_OBJ_AO_32:
case AL_OBJ_AOC_32NT:
case AL_OBJ_AOC_32T:
al_val_int32 = tvb_get_letohl(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int32);
proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AO_16:
case AL_OBJ_AOC_16NT:
case AL_OBJ_AOC_16T:
al_val_int16 = tvb_get_letohs(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %d", al_val_int16);
proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
break;
case AL_OBJ_AO_FLT:
case AL_OBJ_AOC_FLTNT:
case AL_OBJ_AOC_FLTT:
al_valflt = tvb_get_letohieee_float(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valflt);
proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
break;
case AL_OBJ_AO_DBL:
case AL_OBJ_AOC_DBLNT:
case AL_OBJ_AOC_DBLT:
al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
proto_item_append_text(point_item, ", Value: %g", al_valdbl);
proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
data_pos += 8;
break;
}
switch (al_obj)
{
case AL_OBJ_AOC_32T:
case AL_OBJ_AOC_16T:
case AL_OBJ_AOC_FLTT:
case AL_OBJ_AOC_DBLT:
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
break;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_TD:
case AL_OBJ_TDR:
case AL_OBJ_TDCTO:
case AL_OBJ_UTDCTO:
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_tree_add_time(object_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
proto_item_set_len(point_item, data_pos - offset);
if (al_obj == AL_OBJ_TDCTO) {
nstime_copy(al_cto, &al_abstime);
}
offset = data_pos;
break;
case AL_OBJ_TDELAYF:
proto_tree_add_item(object_tree, hf_dnp3_al_time_delay, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_FILE_CMD:
proto_tree_add_item(point_tree, hf_dnp3_al_file_string_offset, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
al_filename_len = tvb_get_letohs(tvb, data_pos);
proto_tree_add_item(point_tree, hf_dnp3_al_file_string_length, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
al_file_ctrl_mode = tvb_get_letohs(tvb, data_pos + 16);
if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE) {
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
}
data_pos += 6;
if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE) {
proto_item *perms_item;
proto_tree *perms_tree;
perms_item = proto_tree_add_item(point_tree, hf_dnp3_al_file_perms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
perms_tree = proto_item_add_subtree(perms_item, ett_dnp3_al_obj_point_perms);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_owner,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_owner,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_group,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_group,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_world,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_world, tvb, offset, 2, ENC_LITTLE_ENDIAN);
proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_world,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
}
data_pos += 2;
proto_tree_add_item(point_tree, hf_dnp3_al_file_auth, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE || al_file_ctrl_mode == AL_OBJ_FILE_MODE_APPEND) {
proto_tree_add_item(point_tree, hf_dnp3_al_file_size, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
}
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_file_mode, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(point_tree, hf_dnp3_al_file_maxblk, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(point_tree, hf_dnp3_al_file_reqID, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
if (al_filename_len > 0) {
proto_tree_add_item(point_tree, hf_dnp3_al_file_name, tvb, data_pos, al_filename_len, ENC_ASCII);
}
data_pos += al_filename_len;
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_FILE_STAT:
proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_file_size,   tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_file_maxblk, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(point_tree, hf_dnp3_al_file_reqID,  tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(point_tree, hf_dnp3_al_file_status, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
file_data_size = al_ptaddr - (data_pos - offset - prefixbytes);
if ((file_data_size) > 0) {
proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
data_pos += file_data_size;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_FILE_TRANS:
proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_file_blocknum,  tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
proto_tree_add_item(point_tree, hf_dnp3_al_file_lastblock, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
file_data_size = al_ptaddr - (data_pos - offset - prefixbytes);
if ((file_data_size) > 0) {
proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
data_pos += file_data_size;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_FILE_TRAN_ST:
proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_file_blocknum,  tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
proto_tree_add_item(point_tree, hf_dnp3_al_file_lastblock, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(point_tree, hf_dnp3_al_file_status, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
file_data_size = al_ptaddr - (data_pos - offset - prefixbytes);
if ((file_data_size) > 0) {
proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
data_pos += file_data_size;
}
proto_item_set_len(point_item, data_pos - offset);
offset = data_pos;
break;
case AL_OBJ_OCT:
case AL_OBJ_OCT_EVT:
if (al_oct_len > 0) {
proto_tree_add_item(object_tree, hf_dnp3_al_octet_string, tvb, data_pos, al_oct_len, ENC_NA);
data_pos += al_oct_len;
proto_item_set_len(point_item, data_pos - offset);
}
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_CH:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_csq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_mal, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_rfc, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, (al_ptaddr-8), ENC_NA);
data_pos += (al_ptaddr-8);
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_RP:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_csq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_mac, tvb, data_pos, (al_ptaddr-6), ENC_NA);
data_pos += (al_ptaddr-6);
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_AGMRQ:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_csq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_SKSR:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_SKS:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_ksq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_kwa, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_ks, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
temp = tvb_get_guint8(tvb, data_pos);
switch (temp) {
case 1:
al_sa_mac_len = 4;
break;
case 2:
al_sa_mac_len = 10;
break;
case 3:
case 5:
al_sa_mac_len = 8;
break;
case 4:
al_sa_mac_len = 16;
break;
case 6:
al_sa_mac_len = 12;
break;
default:
al_sa_mac_len = 0;
break;
}
proto_tree_add_item(object_tree, hf_dnp3_al_sa_mal, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
al_val_uint16 = tvb_get_letohs(tvb, data_pos);
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cdl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, al_val_uint16, ENC_NA);
data_pos += al_val_uint16;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_mac, tvb, data_pos, al_sa_mac_len, ENC_NA);
data_pos += al_sa_mac_len;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_SKC:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_ksq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_key, tvb, data_pos, (al_ptaddr-6), ENC_NA);
data_pos += (al_ptaddr-6);
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_ERR:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_seq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(point_tree, hf_dnp3_al_sa_assoc_id, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_err, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_tree_add_time(object_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_MAC:
case AL_OBJ_SA_AUTH_UKCC:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_mac, tvb, data_pos, al_ptaddr, ENC_NA);
data_pos += al_ptaddr;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_UKCR:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_kcm, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
data_pos += 1;
sa_username_len = tvb_get_letohs(tvb, data_pos);
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usrnl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
sa_challengedata_len = tvb_get_letohs(tvb, data_pos);
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cdl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usrn, tvb, data_pos, sa_username_len, ENC_ASCII);
data_pos += sa_username_len;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, sa_challengedata_len, ENC_NA);
data_pos += sa_challengedata_len;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_UKCRP:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_seq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
sa_challengedata_len = tvb_get_letohs(tvb, data_pos);
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cdl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, sa_challengedata_len, ENC_NA);
data_pos += sa_challengedata_len;
offset = data_pos;
break;
case AL_OBJ_SA_AUTH_UKC:
proto_tree_add_item(object_tree, hf_dnp3_al_sa_seq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
sa_updatekey_len = tvb_get_letohs(tvb, data_pos);
proto_tree_add_item(object_tree, hf_dnp3_al_sa_ukl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
proto_tree_add_item(object_tree, hf_dnp3_al_sa_uk, tvb, data_pos, sa_updatekey_len, ENC_NA);
data_pos += sa_updatekey_len;
offset = data_pos;
break;
case AL_OBJ_SA_SECSTAT:
case AL_OBJ_SA_SECSTATEVT:
case AL_OBJ_SA_SECSTATEVTT:
sec_stat_str = val_to_str_ext(al_ptaddr, &dnp3_al_sa_secstat_vals_ext, "Unknown statistic (%u)");
proto_item_append_text(point_item, " %s", sec_stat_str);
al_ptflags = tvb_get_guint8(tvb, data_pos);
dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, COUNTER);
data_pos += 1;
al_val_uint16 = tvb_get_letohs(tvb, data_pos);
proto_item_append_text(point_item, ", Association ID: %u", al_val_uint16);
proto_tree_add_item(point_tree, hf_dnp3_al_sa_assoc_id, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
data_pos += 2;
al_val_uint32 = tvb_get_letohl(tvb, data_pos);
proto_item_append_text(point_item, ", Count: %u", al_val_uint32);
proto_tree_add_item(point_tree, hf_dnp3_al_cnt32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
data_pos += 4;
if (al_obj == AL_OBJ_SA_SECSTATEVTT) {
dnp3_al_get_timestamp(&al_abstime, tvb, data_pos);
proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
proto_tree_add_time(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, &al_abstime);
data_pos += 6;
}
offset = data_pos;
break;
default:
proto_tree_add_item(object_tree, hf_dnp3_unknown_data_chunk, tvb, offset, -1, ENC_NA);
offset = tvb_captured_length(tvb);
break;
}
}
al_ptaddr++;
}
else {
offset = data_pos;
}
if (start_offset > offset) {
expert_add_info(pinfo, point_item, &ei_dnp_invalid_length);
offset = tvb_captured_length(tvb);
}
}
}
proto_item_set_len(object_item, offset - orig_offset);
return offset;
}
static int
dissect_dnp3_al(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
guint8        al_ctl, al_seq, al_func, al_class = 0, i;
guint16       bytes, obj_type = 0;
guint         data_len = 0, offset = 0;
proto_item   *ti, *tc;
proto_tree   *al_tree, *robj_tree;
const gchar  *func_code_str, *obj_type_str;
nstime_t      al_cto;
static int * const control_flags[] = {
&hf_dnp3_al_fir,
&hf_dnp3_al_fin,
&hf_dnp3_al_con,
&hf_dnp3_al_uns,
&hf_dnp3_al_seq,
NULL
};
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
  proto_item_append_text(ti, "FIR, ");
if (al_ctl & DNP3_AL_FIN)
  proto_item_append_text(ti, "FIN, ");
if (al_ctl & DNP3_AL_CON)
  proto_item_append_text(ti, "CON, ");
if (al_ctl & DNP3_AL_UNS)
  proto_item_append_text(ti, "UNS, ");
proto_item_append_text(ti, "Sequence %u, %s)", al_seq, func_code_str);
tc = proto_tree_add_bitmask(al_tree, tvb, offset, hf_dnp3_al_ctl, ett_dnp3_al_ctl, control_flags, ENC_BIG_ENDIAN);
proto_item_append_text(tc, "(");
if (al_ctl & DNP3_AL_FIR)
  proto_item_append_text(tc, "FIR, ");
if (al_ctl & DNP3_AL_FIN)
  proto_item_append_text(tc, "FIN, ");
if (al_ctl & DNP3_AL_CON)
  proto_item_append_text(tc, "CON, ");
if (al_ctl & DNP3_AL_UNS)
  proto_item_append_text(tc, "UNS, ");
proto_item_append_text(tc, "Sequence %u)", al_seq);
offset += 1;
proto_tree_add_uint_format(al_tree, hf_dnp3_al_func, tvb, offset, 1, al_func,
"Function Code: %s (0x%02x)", func_code_str, al_func);
offset += 1;
switch (al_func)
{
case AL_FUNC_CONFIRM:
if (data_len > 2) {
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "CONFIRM Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);
}
}
break;
case AL_FUNC_READ:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "READ Request Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);
switch(obj_type) {
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
if (al_class != 0) {
col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Class ");
for (i = 0; i < 4; i++) {
if (al_class & (1 << i)) {
col_append_fstr(pinfo->cinfo, COL_INFO, "%u", i);
}
}
}
break;
case AL_FUNC_WRITE:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "WRITE Request Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
obj_type_str = val_to_str_ext_const((obj_type & 0xFF00), &dnp3_al_write_obj_vals_ext, "Unknown Object Type");
col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, obj_type_str);
}
break;
case AL_FUNC_SELECT:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "SELECT Request Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_OPERATE:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "OPERATE Request Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_DIROP:
case AL_FUNC_DIROPNACK:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "DIRECT OPERATE Request Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_FRZ:
case AL_FUNC_FRZNACK:
case AL_FUNC_FRZCLR:
case AL_FUNC_FRZCLRNACK:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Freeze Request Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, TRUE, &obj_type, &al_cto);
}
break;
case AL_FUNC_ENSPMSG:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Enable Spontaneous Msg's Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_DISSPMSG:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Disable Spontaneous Msg's Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_DELAYMST:
break;
case AL_FUNC_OPENFILE:
case AL_FUNC_CLOSEFILE:
case AL_FUNC_DELETEFILE:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "File Data Objects");
while (offset <= (data_len-2))  {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
case AL_FUNC_AUTHREQ:
case AL_FUNC_AUTHERR:
robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Authentication Request Data Objects");
while (offset <= (data_len-2))  {
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
while (offset <= (data_len-2)) {
offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, FALSE, &obj_type, &al_cto);
}
break;
}
default:
break;
}
return 0;
}
static int
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
func_code_str = val_to_str(dl_func, dl_prm ? dnp3_ctl_func_pri_vals : dnp3_ctl_func_sec_vals,
"Unknown function (0x%02x)");
col_append_fstr(pinfo->cinfo, COL_INFO, "from %u to %u", dl_src, dl_dst);
col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "len=%u, %s", dl_len, func_code_str);
ti = proto_tree_add_item(tree, proto_dnp3, tvb, offset, -1, ENC_NA);
dnp3_tree = proto_item_add_subtree(ti, ett_dnp3);
dl_tree = proto_tree_add_subtree_format(dnp3_tree, tvb, offset, DNP_HDR_LEN, ett_dnp3_dl, &tdl,
"Data Link Layer, Len: %u, From: %u, To: %u, ", dl_len, dl_src, dl_dst);
if (dl_prm) {
if (dl_ctl & DNP3_CTL_DIR)
 proto_item_append_text(tdl, "DIR, ");
if (dl_ctl & DNP3_CTL_PRM)
 proto_item_append_text(tdl, "PRM, ");
if (dl_ctl & DNP3_CTL_FCB)
 proto_item_append_text(tdl, "FCB, ");
if (dl_ctl & DNP3_CTL_FCV)
 proto_item_append_text(tdl, "FCV, ");
}
else {
if (dl_ctl & DNP3_CTL_DIR)
 proto_item_append_text(tdl, "DIR, ");
if (dl_ctl & DNP3_CTL_PRM)
 proto_item_append_text(tdl, "PRM, ");
if (dl_ctl & DNP3_CTL_RES)
 proto_item_append_text(tdl, "RES, ");
if (dl_ctl & DNP3_CTL_DFC)
 proto_item_append_text(tdl, "DFC, ");
}
proto_item_append_text(tdl, "%s", func_code_str);
proto_tree_add_item(dl_tree, hf_dnp3_start, tvb, offset, 2, ENC_BIG_ENDIAN);
offset += 2;
proto_tree_add_item(dl_tree, hf_dnp3_len, tvb, offset, 1, ENC_BIG_ENDIAN);
offset += 1;
tc = proto_tree_add_uint_format_value(dl_tree, hf_dnp3_ctl, tvb, offset, 1, dl_ctl,
"0x%02x (", dl_ctl);
if (dl_prm) {
if (dl_ctl & DNP3_CTL_DIR)
 proto_item_append_text(tc, "DIR, ");
if (dl_ctl & DNP3_CTL_PRM)
 proto_item_append_text(tc, "PRM, ");
if (dl_ctl & DNP3_CTL_FCB)
 proto_item_append_text(tc, "FCB, ");
if (dl_ctl & DNP3_CTL_FCV)
 proto_item_append_text(tc, "FCV, ");
}
else {
if (dl_ctl & DNP3_CTL_DIR)
 proto_item_append_text(tc, "DIR, ");
if (dl_ctl & DNP3_CTL_PRM)
 proto_item_append_text(tc, "PRM, ");
if (dl_ctl & DNP3_CTL_RES)
 proto_item_append_text(tc, "RES, ");
if (dl_ctl & DNP3_CTL_DFC)
 proto_item_append_text(tc, "DFC, ");
}
proto_item_append_text(tc, "%s)", func_code_str );
field_tree = proto_item_add_subtree(tc, ett_dnp3_dl_ctl);
if (dl_prm) {
proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
proto_tree_add_item(field_tree, hf_dnp3_ctl_prifunc, tvb, offset, 1, ENC_BIG_ENDIAN);
}
else {
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
proto_tree_add_checksum(dl_tree, tvb, offset, hf_dnp3_data_hdr_crc,
hf_dnp3_data_hdr_crc_status, &ei_dnp3_data_hdr_crc_incorrect,
pinfo, calc_dl_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
offset += 2;
if ((dl_func != DL_FUNC_LINK_STAT) && (dl_func != DL_FUNC_STAT_LINK) &&
(dl_func != DL_FUNC_RESET_LINK) && (dl_func != DL_FUNC_ACK))
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
static int * const transport_flags[] = {
&hf_dnp3_tr_fin,
&hf_dnp3_tr_fir,
&hf_dnp3_tr_seq,
NULL
};
tr_ctl = tvb_get_guint8(tvb, offset);
tr_seq = tr_ctl & DNP3_TR_SEQ;
tr_fir = tr_ctl & DNP3_TR_FIR;
tr_fin = tr_ctl & DNP3_TR_FIN;
tc = proto_tree_add_bitmask(dnp3_tree, tvb, offset, hf_dnp3_tr_ctl, ett_dnp3_tr_ctl, transport_flags, ENC_BIG_ENDIAN);
proto_item_append_text(tc, "(");
if (tr_fir)
 proto_item_append_text(tc, "FIR, ");
if (tr_fin)
 proto_item_append_text(tc, "FIN, ");
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
proto_tree_add_checksum(chk_tree, tvb, offset, hf_dnp3_data_chunk_crc,
hf_dnp3_data_chunk_crc_status, &ei_dnp3_data_chunk_crc_incorrect,
pinfo, calc_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
act_crc  = tvb_get_letohs(tvb, offset);
offset  += 2;
crc_OK   = calc_crc == act_crc;
if (!crc_OK)
{
break;
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
frag_al = fragment_add_seq_single_aging(&al_reassembly_table,
al_tvb, 0, pinfo, tr_seq, NULL,
tvb_reported_length(al_tvb),
tr_fir, tr_fin,
al_max_fragments, al_fragment_aging);
}
else
{
frag_al = fragment_get_reassembled_id(&al_reassembly_table, pinfo, tr_seq);
}
next_tvb = process_reassembled_data(al_tvb, 0, pinfo,
"Reassembled DNP 3.0 Application Layer message", frag_al, &dnp3_frag_items,
NULL, dnp3_tree);
if (frag_al)
{
if (pinfo->num == frag_al->reassembled_in && pinfo->curr_layer_num == frag_al->reas_in_layer_num)
{
dissect_dnp3_al(next_tvb, pinfo, dnp3_tree);
}
else
{
col_set_fence(pinfo->cinfo, COL_INFO);
col_append_fstr(pinfo->cinfo, COL_INFO,
" (Application Layer fragment %u, reassembled in packet %u)",
tr_seq, frag_al->reassembled_in);
proto_tree_add_item(dnp3_tree, hf_al_frag_data, al_tvb, 0, -1, ENC_NA);
}
}
else
{
col_append_fstr(pinfo->cinfo, COL_INFO,
" (Application Layer Unreassembled fragment %u)",
tr_seq);
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
proto_item_set_len(ti, offset);
return offset;
}
static gboolean
check_dnp3_header(tvbuff_t *tvb, gboolean dnp3_heuristics)
{
gboolean goodCRC = FALSE;
gint length = tvb_captured_length(tvb);
if (length >= DNP_HDR_LEN) {
guint16 calc_crc = calculateCRCtvb(tvb, 0, DNP_HDR_LEN - 2);
goodCRC = (calc_crc == tvb_get_letohs(tvb, 8));
}
if (dnp3_heuristics) {
if ( !goodCRC || (tvb_get_ntohs(tvb, 0) != 0x0564)) {
return FALSE;
}
}
else {
if (tvb_get_guint8(tvb, 0) != 0x05) {
return FALSE;
}
if ((length > 1) && (tvb_get_guint8(tvb, 1) != 0x64)) {
return FALSE;
}
if ((length >= DNP_HDR_LEN) && !goodCRC) {
return FALSE;
}
}
return TRUE;
}
static guint
get_dnp3_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
int offset, void *data _U_)
{
guint16 message_len;
guint16 data_crc;
message_len = tvb_get_guint8(tvb, offset + 2);
data_crc = (guint16)(ceil((message_len - 5) / 16.0)) * 2;
message_len += 2 + 1 + 2 + data_crc;
return message_len;
}
static int
dissect_dnp3_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
if (!check_dnp3_header(tvb, FALSE)) {
return 0;
}
tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DNP_HDR_LEN,
get_dnp3_message_len, dissect_dnp3_message, data);
return tvb_captured_length(tvb);
}
static gboolean
dissect_dnp3_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
if (!check_dnp3_header(tvb, TRUE)) {
return FALSE;
}
tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DNP_HDR_LEN,
get_dnp3_message_len, dissect_dnp3_message, data);
return TRUE;
}
static gboolean
dnp3_udp_check_header(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
return check_dnp3_header(tvb, FALSE);
}
static gboolean
dnp3_udp_check_header_heur(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
return check_dnp3_header(tvb, TRUE);
}
static int
dissect_dnp3_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
return udp_dissect_pdus(tvb, pinfo, tree, DNP_HDR_LEN, dnp3_udp_check_header,
get_dnp3_message_len, dissect_dnp3_message, data);
}
static gboolean
dissect_dnp3_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
return (udp_dissect_pdus(tvb, pinfo, tree, DNP_HDR_LEN, dnp3_udp_check_header_heur,
get_dnp3_message_len, dissect_dnp3_message, data) != 0);
}
void
proto_register_dnp3(void)
{
static hf_register_info hf[] = {
{ &hf_dnp3_start,
{ "Start Bytes", "dnp3.start",
FT_UINT16, BASE_HEX, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_len,
{ "Length", "dnp3.len",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Frame Data Length", HFILL }
},
{ &hf_dnp3_ctl,
{ "Control", "dnp3.ctl",
FT_UINT8, BASE_HEX, NULL, 0x0,
"Frame Control Byte", HFILL }
},
{ &hf_dnp3_ctl_prifunc,
{ "Control Function Code", "dnp3.ctl.prifunc",
FT_UINT8, BASE_DEC, VALS(dnp3_ctl_func_pri_vals), DNP3_CTL_FUNC,
"Frame Control Function Code", HFILL }
},
{ &hf_dnp3_ctl_secfunc,
{ "Control Function Code", "dnp3.ctl.secfunc",
FT_UINT8, BASE_DEC, VALS(dnp3_ctl_func_sec_vals), DNP3_CTL_FUNC,
"Frame Control Function Code", HFILL }
},
{ &hf_dnp3_ctlobj_code_c,
{ "Operation Type", "dnp3.ctl.op",
FT_UINT8, BASE_DEC, VALS(dnp3_al_ctlc_code_vals), AL_OBJCTLC_CODE,
"Control Code, Operation Type", HFILL }
},
{ &hf_dnp3_ctlobj_code_m,
{ "Queue / Clear Field", "dnp3.ctl.clr",
FT_UINT8, BASE_DEC, VALS(dnp3_al_ctlc_misc_vals), AL_OBJCTLC_MISC,
"Control Code, Clear Field", HFILL }
},
{ &hf_dnp3_ctlobj_code_tc,
{ "Trip Control Code", "dnp3.ctl.trip",
FT_UINT8, BASE_DEC, VALS(dnp3_al_ctlc_tc_vals), AL_OBJCTLC_TC,
"Control Code, Trip Close Control", HFILL }
},
{ &hf_dnp3_ctl_dir,
{ "Direction", "dnp3.ctl.dir",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_DIR,
NULL, HFILL }
},
{ &hf_dnp3_ctl_prm,
{ "Primary", "dnp3.ctl.prm",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_PRM,
NULL, HFILL }
},
{ &hf_dnp3_ctl_fcb,
{ "Frame Count Bit", "dnp3.ctl.fcb",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_FCB,
NULL, HFILL }
},
{ &hf_dnp3_ctl_fcv,
{ "Frame Count Valid", "dnp3.ctl.fcv",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_FCV,
NULL, HFILL }
},
{ &hf_dnp3_ctl_dfc,
{ "Data Flow Control", "dnp3.ctl.dfc",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_DFC,
NULL, HFILL }
},
{ &hf_dnp3_dst,
{ "Destination", "dnp3.dst",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Destination Address", HFILL }
},
{ &hf_dnp3_src,
{ "Source", "dnp3.src",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Source Address", HFILL }
},
{ &hf_dnp3_addr,
{ "Address", "dnp3.addr",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Source or Destination Address", HFILL }
},
{ &hf_dnp3_data_hdr_crc,
{ "Data Link Header checksum", "dnp3.hdr.CRC",
FT_UINT16, BASE_HEX, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_data_hdr_crc_status,
{ "Data Link Header Checksum Status", "dnp.hdr.CRC.status",
FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
NULL, HFILL }
},
{ &hf_dnp3_tr_ctl,
{ "Transport Control", "dnp3.tr.ctl",
FT_UINT8, BASE_HEX, NULL, 0x0,
"Transport Layer Control Byte", HFILL }
},
{ &hf_dnp3_tr_fin,
{ "Final", "dnp3.tr.fin",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_TR_FIN,
NULL, HFILL }
},
{ &hf_dnp3_tr_fir,
{ "First", "dnp3.tr.fir",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_TR_FIR,
NULL, HFILL }
},
{ &hf_dnp3_tr_seq,
{ "Sequence", "dnp3.tr.seq",
FT_UINT8, BASE_DEC, NULL, DNP3_TR_SEQ,
"Frame Sequence Number", HFILL }
},
{ &hf_dnp3_data_chunk,
{ "Data Chunk", "dnp.data_chunk",
FT_BYTES, BASE_NONE, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_data_chunk_len,
{ "Data Chunk length", "dnp.data_chunk_len",
FT_UINT16, BASE_DEC, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_data_chunk_crc,
{ "Data Chunk checksum", "dnp.data_chunk.CRC",
FT_UINT16, BASE_HEX, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_data_chunk_crc_status,
{ "Data Chunk Checksum Status", "dnp.data_chunk.CRC.status",
FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_ctl,
{ "Application Control", "dnp3.al.ctl",
FT_UINT8, BASE_HEX, NULL, 0x0,
"Application Layer Control Byte", HFILL }
},
{ &hf_dnp3_al_fir,
{ "First", "dnp3.al.fir",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_FIR,
NULL, HFILL }
},
{ &hf_dnp3_al_fin,
{ "Final", "dnp3.al.fin",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_FIN,
NULL, HFILL }
},
{ &hf_dnp3_al_con,
{ "Confirm", "dnp3.al.con",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_CON,
NULL, HFILL }
},
{ &hf_dnp3_al_uns,
{ "Unsolicited", "dnp3.al.uns",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_UNS,
NULL, HFILL }
},
{ &hf_dnp3_al_seq,
{ "Sequence", "dnp3.al.seq",
FT_UINT8, BASE_DEC, NULL, DNP3_AL_SEQ,
"Frame Sequence Number", HFILL }
},
{ &hf_dnp3_al_func,
{ "Application Layer Function Code", "dnp3.al.func",
FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_func_vals_ext, DNP3_AL_FUNC,
"Application Function Code", HFILL }
},
{ &hf_dnp3_al_iin,
{ "Internal Indications", "dnp3.al.iin",
FT_UINT16, BASE_HEX, NULL, 0x0,
"Application Layer IIN", HFILL }
},
{ &hf_dnp3_al_iin_bmsg,
{ "Broadcast Msg Rx", "dnp3.al.iin.bmsg",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_BMSG,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_cls1d,
{ "Class 1 Data Available", "dnp3.al.iin.cls1d",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS1D,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_cls2d,
{ "Class 2 Data Available", "dnp3.al.iin.cls2d",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS2D,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_cls3d,
{ "Class 3 Data Available", "dnp3.al.iin.cls3d",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS3D,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_tsr,
{ "Time Sync Required", "dnp3.al.iin.tsr",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_TSR,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_dol,
{ "Digital Outputs in Local", "dnp3.al.iin.dol",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_DOL,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_dt,
{ "Device Trouble", "dnp3.al.iin.dt",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_DT,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_rst,
{ "Device Restart", "dnp3.al.iin.rst",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_RST,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_fcni,
{ "Function Code not implemented", "dnp3.al.iin.fcni",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_FCNI,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_obju,
{ "Requested Objects Unknown", "dnp3.al.iin.obju",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_OBJU,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_pioor,
{ "Parameters Invalid or Out of Range", "dnp3.al.iin.pioor",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_PIOOR,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_ebo,
{ "Event Buffer Overflow", "dnp3.al.iin.ebo",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_EBO,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_oae,
{ "Operation Already Executing", "dnp3.al.iin.oae",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_OAE,
NULL, HFILL }
},
{ &hf_dnp3_al_iin_cc,
{ "Configuration Corrupt", "dnp3.al.iin.cc",
FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CC,
NULL, HFILL }
},
{ &hf_dnp3_al_obj,
{ "Object", "dnp3.al.obj",
FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dnp3_al_obj_vals_ext, 0x0,
"Application Layer Object", HFILL }
},
{ &hf_dnp3_al_objq_prefix,
{ "Prefix Code", "dnp3.al.objq.prefix",
FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_objq_prefix_vals_ext, AL_OBJQ_PREFIX,
"Object Prefix Code", HFILL }
},
{ &hf_dnp3_al_objq_range,
{ "Range Code", "dnp3.al.objq.range",
FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_objq_range_vals_ext, AL_OBJQ_RANGE,
"Object Range Specifier Code", HFILL }
},
{ &hf_dnp3_al_range_start8,
{ "Start (8 bit)", "dnp3.al.range.start",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Object Start Index", HFILL }
},
{ &hf_dnp3_al_range_stop8,
{ "Stop (8 bit)", "dnp3.al.range.stop",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Object Stop Index", HFILL }
},
{ &hf_dnp3_al_range_start16,
{ "Start (16 bit)", "dnp3.al.range.start",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Object Start Index", HFILL }
},
{ &hf_dnp3_al_range_stop16,
{ "Stop (16 bit)", "dnp3.al.range.stop",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Object Stop Index", HFILL }
},
{ &hf_dnp3_al_range_start32,
{ "Start (32 bit)", "dnp3.al.range.start",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Object Start Index", HFILL }
},
{ &hf_dnp3_al_range_stop32,
{ "Stop (32 bit)", "dnp3.al.range.stop",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Object Stop Index", HFILL }
},
{ &hf_dnp3_al_range_abs8,
{ "Address (8 bit)", "dnp3.al.range.abs",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Object Absolute Address", HFILL }
},
{ &hf_dnp3_al_range_abs16,
{ "Address (16 bit)", "dnp3.al.range.abs",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Object Absolute Address", HFILL }
},
{ &hf_dnp3_al_range_abs32,
{ "Address (32 bit)", "dnp3.al.range.abs",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Object Absolute Address", HFILL }
},
{ &hf_dnp3_al_range_quant8,
{ "Quantity (8 bit)", "dnp3.al.range.quantity",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Object Quantity", HFILL }
},
{ &hf_dnp3_al_range_quant16,
{ "Quantity (16 bit)", "dnp3.al.range.quantity",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Object Quantity", HFILL }
},
{ &hf_dnp3_al_range_quant32,
{ "Quantity (32 bit)", "dnp3.al.range.quantity",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Object Quantity", HFILL }
},
{ &hf_dnp3_al_index8,
{ "Index (8 bit)", "dnp3.al.index",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Object Index", HFILL }
},
{ &hf_dnp3_al_index16,
{ "Index (16 bit)", "dnp3.al.index",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Object Index", HFILL }
},
{ &hf_dnp3_al_index32,
{ "Index (32 bit)", "dnp3.al.index",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Object Index", HFILL }
},
{ &hf_dnp3_al_size8,
{ "Size (8 bit)", "dnp3.al.size",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Object Size", HFILL }
},
{ &hf_dnp3_al_size16,
{ "Size (16 bit)", "dnp3.al.size",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Object Size", HFILL }
},
{ &hf_dnp3_al_size32,
{ "Size (32 bit)", "dnp3.al.size",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Object Size", HFILL }
},
{ &hf_dnp3_bocs_bit,
{ "Commanded State", "dnp3.al.bocs",
FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
"Binary Output Commanded state", HFILL }
},
{ &hf_dnp3_al_bit,
{ "Value (bit)", "dnp3.al.bit",
FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x1,
"Digital Value (1 bit)", HFILL }
},
{ &hf_dnp3_al_2bit,
{ "Value (two bit)", "dnp3.al.2bit",
FT_UINT8, BASE_DEC, NULL, 0x0,
"Digital Value (2 bit)", HFILL }
},
{ &hf_dnp3_al_ana16,
{ "Value (16 bit)", "dnp3.al.ana.int",
FT_INT16, BASE_DEC, NULL, 0x0,
"Analog Value (16 bit)", HFILL }
},
{ &hf_dnp3_al_ana32,
{ "Value (32 bit)", "dnp3.al.ana.int",
FT_INT32, BASE_DEC, NULL, 0x0,
"Analog Value (32 bit)", HFILL }
},
{ &hf_dnp3_al_anaflt,
{ "Value (float)", "dnp3.al.ana.float",
FT_FLOAT, BASE_NONE, NULL, 0x0,
"Analog Value (float)", HFILL }
},
{ &hf_dnp3_al_anadbl,
{ "Value (double)", "dnp3.al.ana.double",
FT_DOUBLE, BASE_NONE, NULL, 0x0,
"Analog Value (double)", HFILL }
},
{ &hf_dnp3_al_anaout16,
{ "Output Value (16 bit)", "dnp3.al.anaout.int",
FT_INT16, BASE_DEC, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_anaout32,
{ "Output Value (32 bit)", "dnp3.al.anaout.int",
FT_INT32, BASE_DEC, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_anaoutflt,
{ "Output Value (float)", "dnp3.al.anaout.float",
FT_FLOAT, BASE_NONE, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_anaoutdbl,
{ "Output (double)", "dnp3.al.anaout.double",
FT_DOUBLE, BASE_NONE, NULL, 0x0,
"Output Value (double)", HFILL }
},
{ &hf_dnp3_al_cnt16,
{ "Counter (16 bit)", "dnp3.al.cnt",
FT_UINT16, BASE_DEC, NULL, 0x0,
"Counter Value (16 bit)", HFILL }
},
{ &hf_dnp3_al_cnt32,
{ "Counter (32 bit)", "dnp3.al.cnt",
FT_UINT32, BASE_DEC, NULL, 0x0,
"Counter Value (32 bit)", HFILL }
},
{ &hf_dnp3_al_ctrlstatus,
{ "Control Status", "dnp3.al.ctrlstatus",
FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_ctl_status_vals_ext, AL_OBJCTL_STATUS_MASK,
NULL, HFILL }
},
{ &hf_dnp3_al_file_mode,
{ "File Control Mode", "dnp3.al.file.mode",
FT_UINT16, BASE_DEC, VALS(dnp3_al_file_mode_vals), 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_auth,
{ "File Authentication Key", "dnp3.al.file.auth",
FT_UINT32, BASE_HEX, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_size,
{ "File Size", "dnp3.al.file.size",
FT_UINT32, BASE_HEX, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_maxblk,
{ "File Max Block Size", "dnp3.al.file.maxblock",
FT_UINT16, BASE_DEC, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_reqID,
{ "File Request Identifier", "dnp3.al.file.reqID",
FT_UINT16, BASE_DEC, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_status,
{ "File Control Status", "dnp3.al.file.status",
FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_file_status_vals_ext, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_handle,
{ "File Handle", "dnp3.al.file.handle",
FT_UINT32, BASE_HEX, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_blocknum,
{ "File Block Number", "dnp3.al.file.blocknum",
FT_UINT32, BASE_HEX, NULL, 0x7fffffff,
NULL, HFILL }
},
{ &hf_dnp3_al_file_lastblock,
{ "File Last Block", "dnp3.al.file.lastblock",
FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
NULL, HFILL }
},
{ &hf_dnp3_al_file_data,
{ "File Data", "dnp3.al.file.data",
FT_BYTES, BASE_NONE, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b0,
{ "Online", "dnp3.al.biq.b0",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG0,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b1,
{ "Restart", "dnp3.al.biq.b1",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG1,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b2,
{ "Comm Fail", "dnp3.al.biq.b2",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG2,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b3,
{ "Remote Force", "dnp3.al.biq.b3",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG3,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b4,
{ "Local Force", "dnp3.al.biq.b4",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG4,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b5,
{ "Chatter Filter", "dnp3.al.biq.b5",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG5,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b6,
{ "Reserved", "dnp3.al.biq.b6",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG6,
NULL, HFILL }
},
{ &hf_dnp3_al_biq_b7,
{ "Point Value", "dnp3.al.biq.b7",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG7,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b0,
{ "Online", "dnp3.al.boq.b0",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG0,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b1,
{ "Restart", "dnp3.al.boq.b1",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG1,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b2,
{ "Comm Fail", "dnp3.al.boq.b2",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG2,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b3,
{ "Remote Force", "dnp3.al.boq.b3",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG3,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b4,
{ "Local Force", "dnp3.al.boq.b4",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG4,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b5,
{ "Reserved", "dnp3.al.boq.b5",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG5,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b6,
{ "Reserved", "dnp3.al.boq.b6",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG6,
NULL, HFILL }
},
{ &hf_dnp3_al_boq_b7,
{ "Point Value", "dnp3.al.boq.b7",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG7,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b0,
{ "Online", "dnp3.al.ctrq.b0",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG0,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b1,
{ "Restart", "dnp3.al.ctrq.b1",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG1,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b2,
{ "Comm Fail", "dnp3.al.ctrq.b2",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG2,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b3,
{ "Remote Force", "dnp3.al.ctrq.b3",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG3,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b4,
{ "Local Force", "dnp3.al.ctrq.b4",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG4,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b5,
{ "Roll-Over", "dnp3.al.ctrq.b5",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG5,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b6,
{ "Discontinuity", "dnp3.al.ctrq.b6",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG6,
NULL, HFILL }
},
{ &hf_dnp3_al_ctrq_b7,
{ "Reserved", "dnp3.al.ctrq.b7",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG7,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b0,
{ "Online", "dnp3.al.aiq.b0",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG0,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b1,
{ "Restart", "dnp3.al.aiq.b1",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG1,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b2,
{ "Comm Fail", "dnp3.al.aiq.b2",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG2,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b3,
{ "Remote Force", "dnp3.al.aiq.b3",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG3,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b4,
{ "Local Force", "dnp3.al.aiq.b4",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG4,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b5,
{ "Over-Range", "dnp3.al.aiq.b5",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG5,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b6,
{ "Reference Check", "dnp3.al.aiq.b6",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG6,
NULL, HFILL }
},
{ &hf_dnp3_al_aiq_b7,
{ "Reserved", "dnp3.al.aiq.b7",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG7,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b0,
{ "Online", "dnp3.al.aoq.b0",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG0,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b1,
{ "Restart", "dnp3.al.aoq.b1",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG1,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b2,
{ "Comm Fail", "dnp3.al.aoq.b2",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG2,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b3,
{ "Remote Force", "dnp3.al.aoq.b3",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG3,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b4,
{ "Local Force", "dnp3.al.aoq.b4",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG4,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b5,
{ "Reserved", "dnp3.al.aoq.b5",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG5,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b6,
{ "Reserved", "dnp3.al.aoq.b6",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG6,
NULL, HFILL }
},
{ &hf_dnp3_al_aoq_b7,
{ "Reserved", "dnp3.al.aoq.b7",
FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG7,
NULL, HFILL }
},
{ &hf_dnp3_al_timestamp,
{ "Timestamp", "dnp3.al.timestamp",
FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
"Object Timestamp", HFILL }
},
{ &hf_dnp3_al_file_perms,
{ "Permissions", "dnp3.al.file.perms",
FT_UINT16, BASE_OCT, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_read_owner,
{ "Read permission for owner", "dnp3.al.file.perms.read_owner",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0400,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_write_owner,
{ "Write permission for owner", "dnp3.al.file.perms.write_owner",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0200,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_exec_owner,
{ "Execute permission for owner", "dnp3.al.file.perms.exec_owner",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0100,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_read_group,
{ "Read permission for group", "dnp3.al.file.perms.read_group",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 040,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_write_group,
{ "Write permission for group", "dnp3.al.file.perms.write_group",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 020,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_exec_group,
{ "Execute permission for group", "dnp3.al.file.perms.exec_group",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 010,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_read_world,
{ "Read permission for world", "dnp3.al.file.perms.read_world",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 04,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_write_world,
{ "Write permission for world", "dnp3.al.file.perms.write_world",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 02,
NULL, HFILL }
},
{ &hf_dnp3_al_file_perms_exec_world,
{ "Execute permission for world", "dnp3.al.file.perms.exec_world",
FT_BOOLEAN, 16, TFS(&tfs_yes_no), 01,
NULL, HFILL }
},
{ &hf_dnp3_al_rel_timestamp,
{ "Relative Timestamp", "dnp3.al.reltimestamp",
FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
"Object Relative Timestamp", HFILL }
},
{ &hf_dnp3_al_datatype,
{ "Data Type", "dnp3.al.datatype",
FT_UINT8, BASE_HEX, VALS(dnp3_al_data_type_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_length,
{ "Device Attribute Length", "dnp3.al.da.length",
FT_UINT8, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_uint8,
{ "Device Attribute 8-Bit Unsigned Integer Value", "dnp3.al.da.uint8",
FT_UINT8, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_uint16,
{ "Device Attribute 16-Bit Unsigned Integer Value", "dnp3.al.da.uint16",
FT_UINT16, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_uint32,
{ "Device Attribute 32-Bit Unsigned Integer Value", "dnp3.al.da.uint32",
FT_UINT32, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_int8,
{ "Device Attribute 8-Bit Integer Value", "dnp3.al.da.int8",
FT_INT8, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_int16,
{ "Device Attribute 16-Bit Integer Value", "dnp3.al.da.int16",
FT_INT16, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_int32,
{ "Device Attribute 32-Bit Integer Value", "dnp3.al.da.int32",
FT_INT32, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_flt,
{ "Device Attribute Float Value", "dnp3.al.da.float",
FT_FLOAT, BASE_NONE, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_da_dbl,
{ "Device Attribute Double Value", "dnp3.al.da.double",
FT_DOUBLE, BASE_NONE, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_assoc_id,
{ "Association ID" , "dnp3.al.sa.assoc_id",
FT_UINT16, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_cd,
{"Challenge Data", "dnp3.al.sa.cd",
FT_BYTES, BASE_NONE, NULL, 0x00,
NULL, HFILL }},
{ &hf_dnp3_al_sa_cdl,
{ "Challenge Data Length", "dnp3.al.sa.cdl",
FT_UINT16, BASE_HEX, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_csq,
{ "Challenge Sequence Number" , "dnp3.al.sa.csq",
FT_UINT32, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_err,
{ "Error Code", "dnp3.al.sa.err",
FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_err_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_kcm,
{ "Key Change Method", "dnp3.al.sa.kcm",
FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_kcm_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_key,
{"Key Data", "dnp3.al.sa.key",
FT_BYTES, BASE_NONE, NULL, 0x00,
NULL, HFILL }},
{ &hf_dnp3_al_sa_ks,
{ "Key Status", "dnp3.al.sa.kw",
FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_ks_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_ksq,
{ "Key Change Sequence Number" , "dnp3.al.sa.ksq",
FT_UINT32, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_kwa,
{ "Key Wrap Algorithm", "dnp3.al.sa.kwa",
FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_kwa_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_mac,
{"MAC Value", "dnp3.al.sa.mac",
FT_BYTES, BASE_NONE, NULL, 0x00,
NULL, HFILL }},
{ &hf_dnp3_al_sa_mal,
{ "MAC Algorithm", "dnp3.al.sa.mal",
FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_mal_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_rfc,
{ "Reason for Challenge", "dnp3.al.sa.rfc",
FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_rfc_vals), 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_seq,
{ "Sequence Number" , "dnp3.al.sa.seq",
FT_UINT32, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_uk,
{"Encrypted Update Key Data", "dnp3.al.sa.uk",
FT_BYTES, BASE_NONE, NULL, 0x00,
NULL, HFILL }},
{ &hf_dnp3_al_sa_ukl,
{ "Encrypted Update Key Length", "dnp3.al.sa.ukl",
FT_UINT16, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_usr,
{ "User Number" , "dnp3.al.sa.usr",
FT_UINT16, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_dnp3_al_sa_usrn,
{ "User Name", "dnp3.al.sa.usrn",
FT_STRING, BASE_NONE, NULL, 0x0,
NULL, HFILL }},
{ &hf_dnp3_al_sa_usrnl,
{ "User name Length", "dnp3.al.sa.usrnl",
FT_UINT16, BASE_DEC, NULL, 0,
NULL, HFILL }
},
{ &hf_al_frag_data,
{"DNP3.0 AL Fragment Data", "dnp3.al.frag_data",
FT_BYTES, BASE_NONE, NULL, 0x00,
"DNP 3.0 Application Layer Fragment Data", HFILL }},
{ &hf_dnp3_fragment,
{ "DNP 3.0 AL Fragment", "dnp3.al.fragment",
FT_FRAMENUM, BASE_NONE, NULL, 0x0,
"DNP 3.0 Application Layer Fragment", HFILL }
},
{ &hf_dnp3_fragments,
{ "DNP 3.0 AL Fragments", "dnp3.al.fragments",
FT_NONE, BASE_NONE, NULL, 0x0,
"DNP 3.0 Application Layer Fragments", HFILL }
},
{ &hf_dnp3_fragment_overlap,
{ "Fragment overlap", "dnp3.al.fragment.overlap",
FT_BOOLEAN, BASE_NONE, NULL, 0x0,
"Fragment overlaps with other fragments", HFILL }
},
{ &hf_dnp3_fragment_overlap_conflict,
{ "Conflicting data in fragment overlap", "dnp3.al.fragment.overlap.conflict",
FT_BOOLEAN, BASE_NONE, NULL, 0x0,
"Overlapping fragments contained conflicting data", HFILL }
},
{ &hf_dnp3_fragment_multiple_tails,
{ "Multiple tail fragments found", "dnp3.al.fragment.multipletails",
FT_BOOLEAN, BASE_NONE, NULL, 0x0,
"Several tails were found when defragmenting the packet", HFILL }
},
{ &hf_dnp3_fragment_too_long_fragment,
{ "Fragment too long", "dnp3.al.fragment.toolongfragment",
FT_BOOLEAN, BASE_NONE, NULL, 0x0,
"Fragment contained data past end of packet", HFILL }
},
{ &hf_dnp3_fragment_error,
{ "Defragmentation error", "dnp3.al.fragment.error",
FT_FRAMENUM, BASE_NONE, NULL, 0x0,
"Defragmentation error due to illegal fragments", HFILL }
},
{ &hf_dnp3_fragment_count,
{ "Fragment count", "dnp3.al.fragment.count",
FT_UINT32, BASE_DEC, NULL, 0x0,
NULL, HFILL }
},
{ &hf_dnp3_fragment_reassembled_in,
{ "Reassembled PDU In Frame", "dnp3.al.fragment.reassembled_in",
FT_FRAMENUM, BASE_NONE, NULL, 0x0,
"This PDU is reassembled in this frame", HFILL }
},
{ &hf_dnp3_fragment_reassembled_length,
{ "Reassembled DNP length", "dnp3.al.fragment.reassembled.length",
FT_UINT32, BASE_DEC, NULL, 0x0,
"The total length of the reassembled payload", HFILL }
},
{ &hf_dnp3_al_point_index, { "Point Index", "dnp3.al.point_index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_da_value, { "Value", "dnp3.al.da.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_count, { "Count", "dnp3.al.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_on_time, { "On Time", "dnp3.al.on_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_off_time, { "Off Time", "dnp3.al.off_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_time_delay, { "Time Delay", "dnp3.al.time_delay", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_file_string_offset, { "File String Offset", "dnp3.al.file_string_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_file_string_length, { "File String Length", "dnp3.al.file_string_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_file_name, { "File Name", "dnp3.al.file_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_al_octet_string, { "Octet String", "dnp3.al.octet_string", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
{ &hf_dnp3_unknown_data_chunk, { "Unknown Data Chunk", "dnp3.al.unknown_data_chunk", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
};
static gint *ett[] = {
&ett_dnp3,
&ett_dnp3_dl,
&ett_dnp3_dl_ctl,
&ett_dnp3_tr_ctl,
&ett_dnp3_dl_data,
&ett_dnp3_dl_chunk,
&ett_dnp3_al,
&ett_dnp3_al_ctl,
&ett_dnp3_al_obj_point_tcc,
&ett_dnp3_al_iin,
&ett_dnp3_al_obj,
&ett_dnp3_al_obj_qualifier,
&ett_dnp3_al_obj_range,
&ett_dnp3_al_objdet,
&ett_dnp3_al_obj_quality,
&ett_dnp3_al_obj_point,
&ett_dnp3_al_obj_point_perms,
&ett_dnp3_fragment,
&ett_dnp3_fragments
};
static ei_register_info ei[] = {
{ &ei_dnp_num_items_neg, { "dnp3.num_items_neg", PI_MALFORMED, PI_ERROR, "Negative number of items", EXPFILL }},
{ &ei_dnp_invalid_length, { "dnp3.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
{ &ei_dnp_iin_abnormal, { "dnp3.iin_abnormal", PI_PROTOCOL, PI_WARN, "IIN Abnormality", EXPFILL }},
{ &ei_dnp3_data_hdr_crc_incorrect, { "dnp3.hdr.CRC.incorrect", PI_CHECKSUM, PI_WARN, "Data Link Header Checksum incorrect", EXPFILL }},
{ &ei_dnp3_data_chunk_crc_incorrect, { "dnp3.data_chunk.CRC.incorrect", PI_CHECKSUM, PI_WARN, "Data Chunk Checksum incorrect", EXPFILL }},
{ &ei_dnp3_unknown_object, { "dnp3.unknown_object", PI_PROTOCOL, PI_WARN, "Unknown Object\\Variation", EXPFILL }},
{ &ei_dnp3_unknown_group0_variation, { "dnp3.unknown_group0_variation", PI_PROTOCOL, PI_WARN, "Unknown Group 0 Variation", EXPFILL }},
{ &ei_dnp3_num_items_invalid, { "dnp3.num_items_invalid", PI_MALFORMED, PI_ERROR, "Number of items is invalid for normally empty object.  Potentially malicious packet", EXPFILL }},
};
module_t *dnp3_module;
expert_module_t* expert_dnp3;
reassembly_table_register(&al_reassembly_table,
&addresses_reassembly_table_functions);
proto_dnp3 = proto_register_protocol("Distributed Network Protocol 3.0", "DNP 3.0", "dnp3");
dnp3_tcp_handle = register_dissector("dnp3.tcp", dissect_dnp3_tcp, proto_dnp3);
dnp3_udp_handle = register_dissector("dnp3.udp", dissect_dnp3_udp, proto_dnp3);
proto_register_field_array(proto_dnp3, hf, array_length(hf));
proto_register_subtree_array(ett, array_length(ett));
expert_dnp3 = expert_register_protocol(proto_dnp3);
expert_register_field_array(expert_dnp3, ei, array_length(ei));
dnp3_module = prefs_register_protocol(proto_dnp3, NULL);
prefs_register_obsolete_preference(dnp3_module, "heuristics");
prefs_register_bool_preference(dnp3_module, "desegment",
"Reassemble DNP3 messages spanning multiple TCP segments",
"Whether the DNP3 dissector should reassemble messages spanning multiple TCP segments."
" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
&dnp3_desegment);
}
void
proto_reg_handoff_dnp3(void)
{
heur_dissector_add("tcp", dissect_dnp3_tcp_heur, "DNP 3.0 over TCP", "dnp3_tcp", proto_dnp3, HEURISTIC_DISABLE);
heur_dissector_add("udp", dissect_dnp3_udp_heur, "DNP 3.0 over UDP", "dnp3_udp", proto_dnp3, HEURISTIC_DISABLE);
dissector_add_uint_with_preference("tcp.port", TCP_PORT_DNP, dnp3_tcp_handle);
dissector_add_uint_with_preference("udp.port", UDP_PORT_DNP, dnp3_udp_handle);
dissector_add_for_decode_as("rtacser.data", dnp3_udp_handle);
ssl_dissector_add(TCP_PORT_DNP_TLS, dnp3_tcp_handle);
}
