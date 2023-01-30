/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file rrc_gNB.c
 * \brief rrc procedures for gNB
 * \author Navid Nikaein and  Raymond Knopp , WEI-TAI CHEN
 * \date 2011 - 2014 , 2018
 * \version 1.0
 * \company Eurecom, NTUST
 * \email: navid.nikaein@eurecom.fr and raymond.knopp@eurecom.fr, kroempa@gmail.com
 */
#define RRC_GNB_C
#define RRC_GNB_C

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nr_rrc_config.h"
#include "nr_rrc_defs.h"
#include "nr_rrc_extern.h"
#include "assertions.h"
#include "common/ran_context.h"
#include "oai_asn1.h"
#include "rrc_gNB_radio_bearers.h"

#include "RRC/L2_INTERFACE/openair_rrc_L2_interface.h"
#include "LAYER2/RLC/rlc.h"
#include "LAYER2/NR_MAC_gNB/mac_proto.h"
#include "common/utils/LOG/log.h"
#include "COMMON/mac_rrc_primitives.h"
#include "RRC/NR/MESSAGES/asn1_msg.h"

#include "NR_BCCH-BCH-Message.h"
#include "NR_UL-DCCH-Message.h"
#include "NR_DL-DCCH-Message.h"
#include "NR_DL-CCCH-Message.h"
#include "NR_UL-CCCH-Message.h"
#include "NR_RRCReject.h"
#include "NR_RejectWaitTime.h"
#include "NR_RRCSetup.h"

#include "NR_CellGroupConfig.h"
#include "NR_MeasResults.h"
#include "LTE_UECapabilityInformation.h"
#include "LTE_UL-DCCH-Message.h"
#include "NR_UL-CCCH-Message.h"
#include "NR_RRCSetupRequest-IEs.h"
#include "NR_RRCSetupComplete-IEs.h"
#include "NR_RRCReestablishmentRequest-IEs.h"
#include "NR_MIB.h"

#include "rlc.h"
#include "rrc_eNB_UE_context.h"
#include "platform_types.h"
#include "common/utils/LOG/vcd_signal_dumper.h"

#include "T.h"

#include "RRC/NAS/nas_config.h"
#include "RRC/NAS/rb_config.h"
#include "OCG.h"
#include "OCG_extern.h"

#include "UTIL/OSA/osa_defs.h"

#include "rrc_eNB_S1AP.h"
#include "rrc_gNB_NGAP.h"

#include "rrc_gNB_GTPV1U.h"

#include "nr_pdcp/nr_pdcp_entity.h"
#include "pdcp.h"

#include "intertask_interface.h"
#include "SIMULATION/TOOLS/sim.h" // for taus

#include "executables/softmodem-common.h"
#include <openair2/RRC/NR/rrc_gNB_UE_context.h>
#include <openair2/X2AP/x2ap_eNB.h>
#include <openair3/ocp-gtpu/gtp_itf.h>
#include <openair2/RRC/NR/nr_rrc_proto.h>
#include "LAYER2/nr_rlc/nr_rlc_oai_api.h"
#include "openair2/LAYER2/nr_pdcp/nr_pdcp_e1_api.h"
#include "openair2/F1AP/f1ap_common.h"
#include "openair2/SDAP/nr_sdap/nr_sdap_entity.h"
#include "cucp_cuup_if.h"

#include "BIT_STRING.h"
#include "assertions.h"

//#define XER_PRINT

extern RAN_CONTEXT_t RC;

static inline uint64_t bitStr_to_uint64(BIT_STRING_t *asn);

mui_t                               rrc_gNB_mui = 0;
uint8_t first_rrcreconfiguration = 0;

///---------------------------------------------------------------------------------------------------------------///
///---------------------------------------------------------------------------------------------------------------///

bool DURecvCb(protocol_ctxt_t  *ctxt_pP,
              const srb_flag_t     srb_flagP,
              const rb_id_t        rb_idP,
              const mui_t          muiP,
              const confirm_t      confirmP,
              const sdu_size_t     sdu_buffer_sizeP,
              unsigned char *const sdu_buffer_pP,
              const pdcp_transmission_mode_t modeP,
              const uint32_t *sourceL2Id,
              const uint32_t *destinationL2Id) {
  // The buffer comes from the stack in gtp-u thread, we have a make a separate buffer to enqueue in a inter-thread message queue
  mem_block_t *sdu=get_free_mem_block(sdu_buffer_sizeP, __func__);
  memcpy(sdu->data,  sdu_buffer_pP,  sdu_buffer_sizeP);
  du_rlc_data_req(ctxt_pP,srb_flagP, false,  rb_idP,muiP, confirmP,  sdu_buffer_sizeP, sdu);
  return true;
}

static void openair_nr_rrc_on(gNB_RRC_INST *rrc)
{
  NR_SRB_INFO *si = &rrc->carrier.SI;
  si->Rx_buffer.payload_size = 0;
  si->Tx_buffer.payload_size = 0;
  si->Active = 1;
}

///---------------------------------------------------------------------------------------------------------------///
///---------------------------------------------------------------------------------------------------------------///

static void init_NR_SI(gNB_RRC_INST *rrc, gNB_RrcConfigurationReq *configuration) {
  LOG_D(RRC,"%s()\n\n\n\n",__FUNCTION__);
  if (NODE_IS_DU(rrc->node_type) || NODE_IS_MONOLITHIC(rrc->node_type)) {
    rrc->carrier.MIB             = (uint8_t *) malloc16(4);
    rrc->carrier.sizeof_MIB      = do_MIB_NR(rrc,0);
  }

  if ((get_softmodem_params()->sa) && ((NODE_IS_DU(rrc->node_type) || NODE_IS_MONOLITHIC(rrc->node_type)))) {
    rrc->carrier.sizeof_SIB1 = do_SIB1_NR(&rrc->carrier,configuration);
  }

  if (!NODE_IS_DU(rrc->node_type)) {
    rrc->carrier.SIB23 = (uint8_t *) malloc16(100);
    AssertFatal(rrc->carrier.SIB23 != NULL, "cannot allocate memory for SIB");
    rrc->carrier.sizeof_SIB23 = do_SIB23_NR(&rrc->carrier, configuration);
    LOG_I(NR_RRC,"do_SIB23_NR, size %d \n ", rrc->carrier.sizeof_SIB23);
    AssertFatal(rrc->carrier.sizeof_SIB23 != 255,"FATAL, RC.nrrrc[mod].carrier[CC_id].sizeof_SIB23 == 255");
  }

  LOG_I(NR_RRC,"Done init_NR_SI\n");

  if (NODE_IS_MONOLITHIC(rrc->node_type) || NODE_IS_DU(rrc->node_type)){
    rrc_mac_config_req_gNB(rrc->module_id,
                           rrc->configuration.pdsch_AntennaPorts,
                           rrc->configuration.pusch_AntennaPorts,
                           rrc->configuration.sib1_tda,
                           rrc->configuration.minRXTXTIME,
                           rrc->carrier.servingcellconfigcommon,
                           &rrc->carrier.mib,
                           rrc->carrier.siblock1,
                           0,
                           0, // WIP hardcoded rnti
                           NULL);
  }

  /* set flag to indicate that cell information is configured. This is required
   * in DU to trigger F1AP_SETUP procedure */
  pthread_mutex_lock(&rrc->cell_info_mutex);
  rrc->cell_info_configured=1;
  pthread_mutex_unlock(&rrc->cell_info_mutex);

  if (get_softmodem_params()->phy_test > 0 || get_softmodem_params()->do_ra > 0) {
    struct rrc_gNB_ue_context_s *ue_context_p = rrc_gNB_allocate_new_UE_context(rrc);
    ue_context_p->ue_context.spCellConfig = calloc(1, sizeof(struct NR_SpCellConfig));
    ue_context_p->ue_context.spCellConfig->spCellConfigDedicated = configuration->scd;
    LOG_I(NR_RRC,"Adding new user (%p)\n",ue_context_p);
    if (!NODE_IS_CU(RC.nrrrc[0]->node_type)) {
      rrc_add_nsa_user(rrc,ue_context_p,NULL);
    }
  }
}

static void rrc_gNB_CU_DU_init(gNB_RRC_INST *rrc)
{
  switch (rrc->node_type) {
    case ngran_gNB_CUCP:
      mac_rrc_dl_f1ap_init(&rrc->mac_rrc);
      cucp_cuup_message_transfer_e1ap_init(rrc);
      break;
    case ngran_gNB_CU:
      mac_rrc_dl_f1ap_init(&rrc->mac_rrc);
      cucp_cuup_message_transfer_direct_init(rrc);
      break;
    case ngran_gNB:
      mac_rrc_dl_direct_init(&rrc->mac_rrc);
      cucp_cuup_message_transfer_direct_init(rrc);
      break;
    case ngran_gNB_DU:
      /* silently drop this, as we currently still need the RRC at the DU. As
       * soon as this is not the case anymore, we can add the AssertFatal() */
      // AssertFatal(1==0,"nothing to do for DU\n");
      break;
    default:
      AssertFatal(0 == 1, "Unknown node type %d\n", rrc->node_type);
      break;
  }
}

static void openair_rrc_gNB_configuration(const module_id_t gnb_mod_idP, gNB_RrcConfigurationReq *configuration)
{
  protocol_ctxt_t      ctxt = { 0 };
  gNB_RRC_INST         *rrc=RC.nrrrc[gnb_mod_idP];
  PROTOCOL_CTXT_SET_BY_MODULE_ID(&ctxt, gnb_mod_idP, GNB_FLAG_YES, NOT_A_RNTI, 0, 0,gnb_mod_idP);
  LOG_I(NR_RRC,
        PROTOCOL_NR_RRC_CTXT_FMT" Init...\n",
        PROTOCOL_NR_RRC_CTXT_ARGS(&ctxt));
  AssertFatal(rrc != NULL, "RC.nrrrc not initialized!");
  AssertFatal(NUMBER_OF_UE_MAX < (module_id_t)0xFFFFFFFFFFFFFFFF, " variable overflow");
  AssertFatal(configuration!=NULL,"configuration input is null\n");
  rrc->module_id = gnb_mod_idP;
  rrc_gNB_CU_DU_init(rrc);
  uid_linear_allocator_init(&rrc->uid_allocator);
  rrc->initial_id2_s1ap_ids = hashtable_create (NUMBER_OF_UE_MAX * 2, NULL, NULL);
  rrc->s1ap_id2_s1ap_ids = hashtable_create(NUMBER_OF_UE_MAX * 2, NULL, NULL);
  rrc->configuration = *configuration;
  rrc->carrier.servingcellconfigcommon = configuration->scc;
  rrc->carrier.servingcellconfig = configuration->scd;
  nr_rrc_config_ul_tda(configuration->scc,configuration->minRXTXTIME);
  /// System Information INIT
  pthread_mutex_init(&rrc->cell_info_mutex,NULL);
  rrc->cell_info_configured = 0;
  LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_FMT" Checking release \n",PROTOCOL_NR_RRC_CTXT_ARGS(&ctxt));
  init_NR_SI(rrc, configuration);
  openair_nr_rrc_on(rrc);
  return;
} // END openair_rrc_gNB_configuration

static void rrc_gNB_process_AdditionRequestInformation(const module_id_t gnb_mod_idP, x2ap_ENDC_sgnb_addition_req_t *m)
{
  struct NR_CG_ConfigInfo *cg_configinfo = NULL;
  asn_dec_rval_t dec_rval = uper_decode_complete(NULL, &asn_DEF_NR_CG_ConfigInfo, (void **)&cg_configinfo, (uint8_t *)m->rrc_buffer,
                                                 (int)m->rrc_buffer_size); // m->rrc_buffer_size);
  gNB_RRC_INST         *rrc=RC.nrrrc[gnb_mod_idP];

  if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
    AssertFatal(1==0,"NR_UL_DCCH_MESSAGE decode error\n");
    // free the memory
    SEQUENCE_free(&asn_DEF_NR_CG_ConfigInfo, cg_configinfo, 1);
    return;
  }

  xer_fprint(stdout,&asn_DEF_NR_CG_ConfigInfo, cg_configinfo);
  // recreate enough of X2 EN-DC Container
  AssertFatal(cg_configinfo->criticalExtensions.choice.c1->present == NR_CG_ConfigInfo__criticalExtensions__c1_PR_cg_ConfigInfo,
              "ueCapabilityInformation not present\n");
  parse_CG_ConfigInfo(rrc,cg_configinfo,m);
  LOG_A(NR_RRC, "Successfully parsed CG_ConfigInfo of size %zu bits. (%zu bytes)\n",
        dec_rval.consumed, (dec_rval.consumed +7/8));
}

//-----------------------------------------------------------------------------
unsigned int rrc_gNB_get_next_transaction_identifier(module_id_t gnb_mod_idP)
//-----------------------------------------------------------------------------
{
  static unsigned int transaction_id[NUMBER_OF_gNB_MAX] = {0};
  // used also in NGAP thread, so need thread safe operation
  unsigned int tmp = __atomic_add_fetch(&transaction_id[gnb_mod_idP], 1, __ATOMIC_SEQ_CST);
  tmp %= NR_RRC_TRANSACTION_IDENTIFIER_NUMBER;
  LOG_T(NR_RRC, "generated xid is %d\n", tmp);
  return tmp;
}

static void apply_macrlc_config(gNB_RRC_INST *rrc, rrc_gNB_ue_context_t *const ue_context_pP, const protocol_ctxt_t *const ctxt_pP)
{
  NR_CellGroupConfig_t *cgc = get_softmodem_params()->sa ? ue_context_pP->ue_context.masterCellGroup : NULL;
  rrc_mac_config_req_gNB(rrc->module_id,
                         rrc->configuration.pdsch_AntennaPorts,
                         rrc->configuration.pusch_AntennaPorts,
                         rrc->configuration.sib1_tda,
                         rrc->configuration.minRXTXTIME,
                         NULL,
                         NULL,
                         NULL,
                         0,
                         ue_context_pP->ue_context.rnti,
                         cgc);
  NR_DRB_ToAddModList_t DRB_configList = {0};
  NR_SRB_ToAddModList_t SRB_configList = {0};
  fill_DRB_configList(ctxt_pP, ue_context_pP, &DRB_configList, setUE);
  fill_SRB_configList(ue_context_pP, &SRB_configList);
  nr_rrc_rlc_config_asn1_req(ctxt_pP, &SRB_configList, &DRB_configList, NULL, NULL, get_softmodem_params()->sa ? cgc->rlc_BearerToAddModList : NULL);
}

//-----------------------------------------------------------------------------
static void rrc_gNB_generate_RRCSetup(const protocol_ctxt_t *const ctxt_pP,
                                      rrc_gNB_ue_context_t *const ue_context_pP,
                                      const uint8_t *masterCellGroup,
                                      int masterCellGroup_len,
                                      NR_ServingCellConfigCommon_t *scc)
//-----------------------------------------------------------------------------
{
  LOG_I(NR_RRC, "rrc_gNB_generate_RRCSetup for RNTI %04lx\n", ctxt_pP->rntiMaybeUEid);

  gNB_RRC_UE_t *ue_p = &ue_context_pP->ue_context;
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt_pP->module_id];
  unsigned char buf[1024];
  const NR_ServingCellConfig_t *sccd = rrc->configuration.scd;
  int size = do_RRCSetup(ue_context_pP,
                         buf,
                         rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id),
                         masterCellGroup,
                         masterCellGroup_len,
                         scc,
                         sccd,
                         &rrc->configuration);
  AssertFatal(size > 0, "do_RRCSetup failed\n");
  AssertFatal(size <= 1024, "memory corruption\n");

  LOG_DUMPMSG(NR_RRC, DEBUG_RRC,
              (char *)buf,
              size,
              "[MSG] RRC Setup\n");

  // activate release timer, if RRCSetupComplete not received after 100 frames, remove UE
  ue_context_pP->ue_context.ue_release_timer = 1;
  // remove UE after 10 frames after RRCConnectionRelease is triggered
  ue_context_pP->ue_context.ue_release_timer_thres = 1000;

  NR_SRB_ToAddModList_t SRB_configList = {0};
  fill_SRB_configList(ue_context_pP, &SRB_configList);
  nr_pdcp_add_srbs(ctxt_pP->enb_flag, ctxt_pP->rntiMaybeUEid, &SRB_configList, 0, NULL, NULL);

  f1ap_dl_rrc_message_t dl_rrc = {
    .old_gNB_DU_ue_id = 0xFFFFFF,
    .rrc_container = buf,
    .rrc_container_length = size,
    .rnti = ue_p->rnti,
    .srb_id = CCCH
  };
  rrc->mac_rrc.dl_rrc_message_transfer(ctxt_pP->module_id, &dl_rrc);
}

//-----------------------------------------------------------------------------
static void rrc_gNB_generate_RRCSetup_for_RRCReestablishmentRequest(const protocol_ctxt_t *const ctxt_pP, const int CC_id)
//-----------------------------------------------------------------------------
{
  LOG_I(NR_RRC, "generate RRCSetup for RRCReestablishmentRequest \n");
  rrc_gNB_ue_context_t         *ue_context_pP   = NULL;
  gNB_RRC_INST                 *rrc_instance_p = RC.nrrrc[ctxt_pP->module_id];
  const NR_ServingCellConfigCommon_t *scc=rrc_instance_p->carrier.servingcellconfigcommon;
  const NR_ServingCellConfig_t       *sccd = rrc_instance_p->configuration.scd;

  // fixme: error here: the UE id is 0 so multi UE reestablisments will collide
  ue_context_pP = rrc_gNB_new_ue_context(0, rrc_instance_p, 0);

  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  unsigned char buf[1024];
  int size = do_RRCSetup(ue_context_pP,
                         buf,
                         rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id),
                         NULL,
                         0,
                         scc,
                         sccd,
                         &rrc_instance_p->configuration);
  AssertFatal(size > 0, "do_RRCSetup failed\n");
  AssertFatal(size <= 1024, "memory corruption\n");

  AssertFatal(size>0,"Error generating RRCSetup for RRCReestablishmentRequest\n");

  LOG_DUMPMSG(NR_RRC, DEBUG_RRC,
              (char *)buf,
              size,
              "[MSG] RRC Setup\n");

  LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " RRC_gNB --- MAC_CONFIG_REQ  (SRB1) ---> MAC_gNB\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));

  rrc_mac_config_req_gNB(rrc_instance_p->module_id,
                         rrc_instance_p->configuration.pdsch_AntennaPorts,
                         rrc_instance_p->configuration.pusch_AntennaPorts,
                         rrc_instance_p->configuration.sib1_tda,
                         rrc_instance_p->configuration.minRXTXTIME,
                         rrc_instance_p->carrier.servingcellconfigcommon,
                         &rrc_instance_p->carrier.mib,
                         rrc_instance_p->carrier.siblock1,
                         0,
                         ue_context_pP->ue_context.rnti,
                         NULL);

  LOG_I(NR_RRC,
        PROTOCOL_NR_RRC_CTXT_UE_FMT" [RAPROC] Logical Channel DL-CCCH, Generating RRCSetup (bytes %d)\n",
        PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
        size);
  // activate release timer, if RRCSetupComplete not received after 100 frames, remove UE
  ue_context_pP->ue_context.ue_release_timer = 1;
  // remove UE after 10 frames after RRCConnectionRelease is triggered
  ue_context_pP->ue_context.ue_release_timer_thres = 1000;
  /* init timers */
  //   ue_context_pP->ue_context.ue_rrc_inactivity_timer = 0;

  f1ap_dl_rrc_message_t dl_rrc = {.old_gNB_DU_ue_id = 0xFFFFFF, .rrc_container = buf, .rrc_container_length = size, .rnti = UE->rnti, .srb_id = CCCH};
  rrc_instance_p->mac_rrc.dl_rrc_message_transfer(ctxt_pP->module_id, &dl_rrc);
}

static void rrc_gNB_generate_RRCReject(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *const ue_context_pP)
//-----------------------------------------------------------------------------
{
  LOG_I(NR_RRC, "rrc_gNB_generate_RRCReject \n");
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt_pP->module_id];
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;

  unsigned char buf[1024];
  int size = do_RRCReject(ctxt_pP->module_id, buf);
  AssertFatal(size > 0, "do_RRCReject failed\n");
  AssertFatal(size <= 1024, "memory corruption\n");

  LOG_DUMPMSG(NR_RRC, DEBUG_RRC,
              (char *)buf,
              size,
              "[MSG] RRCReject \n");
  LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " [RAPROC] Logical Channel DL-CCCH, Generating NR_RRCReject (bytes %d)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size);

  f1ap_dl_rrc_message_t dl_rrc = {.gNB_CU_ue_id = 0,
                                  .gNB_DU_ue_id = 0,
                                  .old_gNB_DU_ue_id = 0xFFFFFF,
                                  .rrc_container = buf,
                                  .rrc_container_length = size,
                                  .rnti = UE->rnti,
                                  .srb_id = CCCH,
                                  .execute_duplication = 1,
                                  .RAT_frequency_priority_information.en_dc = 0};
  rrc->mac_rrc.dl_rrc_message_transfer(ctxt_pP->module_id, &dl_rrc);
}

//-----------------------------------------------------------------------------
/*
 * Process the rrc setup complete message from UE (SRB1 Active)
 */
static void rrc_gNB_process_RRCSetupComplete(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *ue_context_pP, NR_RRCSetupComplete_IEs_t *rrcSetupComplete)
//-----------------------------------------------------------------------------
{
  LOG_A(NR_RRC,
        PROTOCOL_NR_RRC_CTXT_UE_FMT
        " [RAPROC] Logical Channel UL-DCCH, "
        "processing NR_RRCSetupComplete from UE (SRB1 Active)\n",
        PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
  ue_context_pP->ue_context.Srb[1].Active = 1;
  ue_context_pP->ue_context.Srb[1].Srb_info.Srb_id = 1;
  ue_context_pP->ue_context.StatusRrc = NR_RRC_CONNECTED;

  if (get_softmodem_params()->sa) {
    rrc_gNB_send_NGAP_NAS_FIRST_REQ(ctxt_pP, ue_context_pP, rrcSetupComplete);
  } else {
    rrc_gNB_generate_SecurityModeCommand(ctxt_pP, ue_context_pP);
  }
}

//-----------------------------------------------------------------------------
static void rrc_gNB_generate_defaultRRCReconfiguration(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *ue_context_pP)
//-----------------------------------------------------------------------------
{
  struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList *dedicatedNAS_MessageList = NULL;

  uint8_t xid = rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id);
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;

  /******************** Radio Bearer Config ********************/

  dedicatedNAS_MessageList = CALLOC(1, sizeof(struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList));

  /* Add all NAS PDUs to the list */
  for (int i = 0; i < sizeofArray(UE->pduSession); i++) {
    if (UE->pduSession[i].nas_pdu.buffer != NULL) {
      asn1cSequenceAdd(dedicatedNAS_MessageList->list, NR_DedicatedNAS_Message_t, dedicatedNAS_Message);
      OCTET_STRING_fromBuf(dedicatedNAS_Message, (char *)UE->pduSession[i].nas_pdu.buffer, UE->pduSession[i].nas_pdu.length);
      free(UE->pduSession[i].nas_pdu.buffer);
      UE->pduSession[i].nas_pdu = (ngap_pdu_t){0};
      LOG_D(NR_RRC, "setting the status for the default DRB (index %d) to sent to UE\n", i);
    }
  }

  if (UE->nas_pdu.length) {
    asn1cSequenceAdd(dedicatedNAS_MessageList->list, NR_DedicatedNAS_Message_t, dedicatedNAS_Message);
    OCTET_STRING_fromBuf(dedicatedNAS_Message, (char *)UE->nas_pdu.buffer, UE->nas_pdu.length);
  }

  /* If list is empty free the list and reset the address */
  if (dedicatedNAS_MessageList->list.count == 0) {
    free(dedicatedNAS_MessageList);
    dedicatedNAS_MessageList = NULL;
  }

  gNB_RRC_INST *rrc = RC.nrrrc[ctxt_pP->module_id];
  NR_MeasConfig_t *measconfig = get_defaultMeasConfig(&rrc->configuration);

  uint8_t buffer[RRC_BUF_SIZE] = {0};
  int size = do_RRCReconfiguration(ctxt_pP,
                                   buffer,
                                   sizeof(buffer),
                                   xid,
                                   NULL, //*SRB_configList2,
                                   NULL, //*DRB_configList,
                                   NULL,
                                   NULL,
                                   NULL,
                                   measconfig,
                                   dedicatedNAS_MessageList,
                                   ue_context_pP,
                                   &rrc->carrier,
                                   &rrc->configuration,
                                   NULL,
                                   UE->masterCellGroup);
  AssertFatal(size > 0, "cannot encode RRCReconfiguration in %s()\n", __func__);
  LOG_W(RRC, "do_RRCReconfiguration(): size %d\n", size);

  if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
    xer_fprint(stdout, &asn_DEF_NR_CellGroupConfig, UE->masterCellGroup);
  }

  // suspicious if it is always malloced before ?
  free(UE->nas_pdu.buffer);

  LOG_DUMPMSG(NR_RRC, DEBUG_RRC,(char *)buffer, size, "[MSG] RRC Reconfiguration\n");

  LOG_I(NR_RRC, "[gNB %d] Frame %d, Logical Channel DL-DCCH, Generate NR_RRCReconfiguration (bytes %d, UE id %x)\n", ctxt_pP->module_id, ctxt_pP->frame, size, UE->rnti);
  switch (RC.nrrrc[ctxt_pP->module_id]->node_type) {
    case ngran_gNB_CU:
    case ngran_gNB_CUCP:
    case ngran_gNB:
      nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);
      // rrc_pdcp_config_asn1_req

      break;

    case ngran_gNB_DU:
      // nothing to do for DU
      AssertFatal(1 == 0, "nothing to do for DU\n");
      break;

    default:
      LOG_W(NR_RRC, "Unknown node type %d\n", RC.nrrrc[ctxt_pP->module_id]->node_type);
  }

  if (NODE_IS_DU(rrc->node_type) || NODE_IS_MONOLITHIC(rrc->node_type)) {
    gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
    rrc_mac_config_req_gNB(rrc->module_id,
                           rrc->configuration.pdsch_AntennaPorts,
                           rrc->configuration.pusch_AntennaPorts,
                           rrc->configuration.sib1_tda,
                           rrc->configuration.minRXTXTIME,
                           NULL,
                           NULL,
                           NULL,
                           0,
                           UE->rnti,
                           UE->masterCellGroup);

    uint32_t delay_ms = UE->masterCellGroup && UE->masterCellGroup->spCellConfig && UE->masterCellGroup->spCellConfig->spCellConfigDedicated
                                && UE->masterCellGroup->spCellConfig->spCellConfigDedicated->downlinkBWP_ToAddModList
                            ? NR_RRC_RECONFIGURATION_DELAY_MS + NR_RRC_BWP_SWITCHING_DELAY_MS
                            : NR_RRC_RECONFIGURATION_DELAY_MS;

    nr_mac_enable_ue_rrc_processing_timer(ctxt_pP->module_id, UE->rnti, *rrc->carrier.servingcellconfigcommon->ssbSubcarrierSpacing, delay_ms);
  }
}

void fill_DRB_configList(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *ue_context_pP, NR_DRB_ToAddModList_t *DRB_configList, enum drbPurpose purpose)
{
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt_pP->module_id];
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  uint8_t nb_drb_to_setup = rrc->configuration.drbs;

  uint8_t xid = rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id);

  for (int i = 0; i < sizeofArray(UE->pduSession); i++) {
    rrc_pdu_session_param_t *session = &UE->pduSession[i];
    pdu_session_status_t *status;
    if (purpose == setE1)
      status = &session->statusE1;
    else
      status = &session->statusF1;

    // the DRB is already made
    if (*status != PDU_SESSION_toCreate)
      continue;

    // if needed, we will set in to failed hereafter
    *status = PDU_SESSION_createSent;

    for (long drb_id_add = 1; drb_id_add <= nb_drb_to_setup; drb_id_add++) {
      // Reference TS23501 Table 5.7.4-1: Standardized 5QI to QoS characteristics mapping
      /* FIXXX
         uint8_t drb_id;
         for (qos_flow_index = 0; qos_flow_index < session->param.nb_qos; qos_flow_index++) {
         switch (session->param.qos[qos_flow_index].fiveQI) {
         case 1 ... 4: // GBR
         drb_id = next_available_drb(UE, session->param.pdusession_id, GBR_FLOW);
         break;
         case 5 ... 9: // Non-GBR
         if (rrc->configuration.drbs > 1) // Force the creation from gNB Conf file - Should be used only in noS1 mode and rfsim for testing purposes.
         drb_id = next_available_drb(UE, session->param.pdusession_id, GBR_FLOW);
         else
         drb_id = next_available_drb(UE, session->param.pdusession_id, NONGBR_FLOW);
         break;

         default:
         LOG_E(NR_RRC, "not supported 5qi %lu\n", session->param.qos[qos_flow_index].fiveQI);
         *status = PDU_SESSION_failed;
         // UE->pduSession[i].xid = xid;
         pdu_sessions_done++;
         continue;
         }

         switch (UE->pduSession[i].param.qos[qos_flow_index].allocation_retention_priority.priority_level) {
         case NGAP_PRIORITY_LEVEL_HIGHEST:
         case NGAP_PRIORITY_LEVEL_2:
         case NGAP_PRIORITY_LEVEL_3:
         case NGAP_PRIORITY_LEVEL_4:
         case NGAP_PRIORITY_LEVEL_5:
         case NGAP_PRIORITY_LEVEL_6:
         case NGAP_PRIORITY_LEVEL_7:
         case NGAP_PRIORITY_LEVEL_8:
         case NGAP_PRIORITY_LEVEL_9:
         case NGAP_PRIORITY_LEVEL_10:
         case NGAP_PRIORITY_LEVEL_11:
         case NGAP_PRIORITY_LEVEL_12:
         case NGAP_PRIORITY_LEVEL_13:
         case NGAP_PRIORITY_LEVEL_LOWEST:
         case NGAP_PRIORITY_LEVEL_NO_PRIORITY:
         drb_priority[drb_id - 1] = session->param.qos[qos_flow_index].allocation_retention_priority.priority_level;
         break;

         default:
         LOG_E(NR_RRC, "Not supported priority level\n");
         break;
         }

         if (drb_is_active(UE, drb_id)) { // Non-GBR flow using the same DRB or a GBR flow with no available DRBs
         nb_drb_to_setup--;
         } else {
         NR_DRB_ToAddMod_t *DRB_config = generateDRB(UE, drb_id, session, rrc->configuration.enable_sdap, rrc->security.do_drb_integrity, rrc->security.do_drb_ciphering);
         if (drb_id_to_setup_start == 0)
         drb_id_to_setup_start = DRB_config->drb_Identity;
         asn1cSeqAdd(&DRB_configList->list, DRB_config);
         }
         LOG_D(RRC, "DRB Priority %ld\n", drb_priority[drb_id]); // To supress warning for now
         }
      */
    }

    UE->pduSession[i].xid = xid;
  }
}

//-----------------------------------------------------------------------------
void rrc_gNB_generate_dedicatedRRCReconfiguration(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *ue_context_pP, NR_CellGroupConfig_t *cell_groupConfig_from_DU)
//-----------------------------------------------------------------------------
{
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt_pP->module_id];
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  long drb_priority[1] = {13}; // For now, we assume only one drb per pdu sessions with a default preiority (will be dynamique in future)
  NR_CellGroupConfig_t *cellGroupConfig = NULL;
  uint8_t buffer[RRC_BUF_SIZE];
  uint16_t size;
  int xid = rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id);

  int drb_id_to_setup_start = 1;
  NR_DRB_ToAddModList_t DRB_configList = {0};
  fill_DRB_configList(ctxt_pP, ue_context_pP, &DRB_configList, setUE);
  int nb_drb_to_setup = DRB_configList.list.count;

  struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList *dedicatedNAS_MessageList = NULL;
  dedicatedNAS_MessageList = CALLOC(1, sizeof(struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList));

  for (int i = 0; i < nb_drb_to_setup; i++) {
    NR_DRB_ToAddMod_t *DRB_config = DRB_configList.list.array[i];
    if (drb_id_to_setup_start == 1)
      drb_id_to_setup_start = DRB_config->drb_Identity;
    ngap_pdu_t *pdu = &UE->pduSession[i].nas_pdu;
    if (pdu->buffer != NULL) {
      asn1cSequenceAdd(dedicatedNAS_MessageList->list, NR_DedicatedNAS_Message_t, dedicatedNAS_Message);
      OCTET_STRING_fromBuf(dedicatedNAS_Message, (char *)pdu->buffer, pdu->length);
      /* Free the NAS PDU buffer and invalidate it */
      free(pdu->buffer);
      *pdu = (ngap_pdu_t){0};

      LOG_I(NR_RRC, "add NAS info with size %d (pdusession id %d)\n", pdu->length, i);
    } else {
      // TODO
      LOG_E(NR_RRC, "no NAS info (pdusession id %d)\n", i);
    }
  }

  /* If list is empty free the list and reset the address */
  if (dedicatedNAS_MessageList->list.count == 0) {
    free(dedicatedNAS_MessageList);
    dedicatedNAS_MessageList = NULL;
  }

  memset(buffer, 0, sizeof(buffer));
  if (cell_groupConfig_from_DU == NULL) {
    cellGroupConfig = calloc(1, sizeof(NR_CellGroupConfig_t));
    // FIXME: fill_mastercellGroupConfig() won't fill the right priorities or
    // bearer IDs for the DRBs
    fill_mastercellGroupConfig(cellGroupConfig, UE->masterCellGroup, rrc->um_on_default_drb, (drb_id_to_setup_start < 2) ? 1 : 0, drb_id_to_setup_start, nb_drb_to_setup, drb_priority);
  } else {
    LOG_I(NR_RRC, "Master cell group originating from the DU \n");
    cellGroupConfig = cell_groupConfig_from_DU;
  }

  AssertFatal(xid > -1, "Invalid xid %d. No PDU sessions setup to configure.\n", xid);
  NR_SRB_ToAddModList_t SRB_configList = {0};
  fill_SRB_configList(ue_context_pP, &SRB_configList);
  // SRBFixme SRB_configList2 = UE->SRB_configList2[xid];

  size = do_RRCReconfiguration(ctxt_pP,
                               buffer,
                               sizeof(buffer),
                               xid,
                               &SRB_configList,
                               &DRB_configList,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               dedicatedNAS_MessageList,
                               ue_context_pP,
                               &rrc->carrier,
                               &rrc->configuration,
                               NULL,
                               cellGroupConfig);
  LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)buffer, size, "[MSG] RRC Reconfiguration\n");

  LOG_I(NR_RRC, "[gNB %d] Frame %d, Logical Channel DL-DCCH, Generate RRCReconfiguration (bytes %d, UE RNTI %x)\n", ctxt_pP->module_id, ctxt_pP->frame, size, UE->rnti);
  LOG_D(NR_RRC,
        "[FRAME %05d][RRC_gNB][MOD %u][][--- PDCP_DATA_REQ/%d Bytes (rrcReconfiguration to UE %x MUI %d) --->][PDCP][MOD %u][RB %u]\n",
        ctxt_pP->frame,
        ctxt_pP->module_id,
        size,
        UE->rnti,
        rrc_gNB_mui,
        ctxt_pP->module_id,
        DCCH);

  nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);

  if (NODE_IS_DU(rrc->node_type) || NODE_IS_MONOLITHIC(rrc->node_type)) {
    rrc_mac_config_req_gNB(rrc->module_id,
                           rrc->configuration.pdsch_AntennaPorts,
                           rrc->configuration.pusch_AntennaPorts,
                           rrc->configuration.sib1_tda,
                           rrc->configuration.minRXTXTIME,
                           NULL,
                           NULL,
                           NULL,
                           0,
                           UE->rnti,
                           UE->masterCellGroup);

    uint32_t delay_ms = UE->masterCellGroup && UE->masterCellGroup->spCellConfig && UE->masterCellGroup->spCellConfig->spCellConfigDedicated
                                && UE->masterCellGroup->spCellConfig->spCellConfigDedicated->downlinkBWP_ToAddModList
                            ? NR_RRC_RECONFIGURATION_DELAY_MS + NR_RRC_BWP_SWITCHING_DELAY_MS
                            : NR_RRC_RECONFIGURATION_DELAY_MS;

    nr_mac_enable_ue_rrc_processing_timer(ctxt_pP->module_id, UE->rnti, *rrc->carrier.servingcellconfigcommon->ssbSubcarrierSpacing, delay_ms);
  }
}

//-----------------------------------------------------------------------------
void rrc_gNB_modify_dedicatedRRCReconfiguration(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *ue_context_pP)
//-----------------------------------------------------------------------------
{
  NR_DRB_ToAddMod_t *DRB_config = NULL;
  struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList *dedicatedNAS_MessageList = NULL;
  uint8_t buffer[RRC_BUF_SIZE];
  uint16_t size;
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  uint8_t xid = rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id);

  NR_DRB_ToAddModList_t DRB_configList = {0};
  fill_DRB_configList(ctxt_pP, ue_context_pP, &DRB_configList, setUE);

  dedicatedNAS_MessageList = CALLOC(1, sizeof(struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList));

  for (int i = 0; i < sizeofArray(UE->pduSession); i++) {
    // bypass the new and already configured pdu sessions
    rrc_pdu_session_param_t *session = &UE->pduSession[i];
    if (session->statusF1 == PDU_SESSION_toModify) {
      session->xid = xid;
      continue;
    }

    // search exist DRB_config
    for (int j = 0; j < DRB_configList.list.count; j++) {
      if (DRB_configList.list.array[j]->cnAssociation->choice.sdap_Config->pdu_Session == i) {
        DRB_config = DRB_configList.list.array[j];
        break;
      }
    }

    if (DRB_config == NULL) {
      session->xid = xid;
      session->cause = NGAP_CAUSE_RADIO_NETWORK;
      session->cause_value = NGAP_CauseRadioNetwork_unspecified;
      session->statusF1 = PDU_SESSION_failed;
      continue;
    }

#if 0 // FIXXX
      // Reference TS23501 Table 5.7.4-1: Standardized 5QI to QoS characteristics mapping
    for (qos_flow_index = 0; qos_flow_index < session->param.nb_qos; qos_flow_index++) {
      switch (session->param.qos[qos_flow_index].fiveQI) {
      case 1: // 100ms
      case 2: // 150ms
      case 3: // 50ms
      case 4: // 300ms
      case 5: // 100ms
      case 6: // 300ms
      case 7: // 100ms
      case 8: // 300ms
      case 9: // 300ms Video (Buffered Streaming)TCP-based (e.g., www, e-mail, chat, ftp, p2p file sharing, progressive video, etc.)
        // TODO
        break;

      default:
        LOG_E(NR_RRC, "not supported 5qi %lu\n", session->param.qos[qos_flow_index].fiveQI);
        session->xid = xid;
        session->cause = NGAP_CAUSE_RADIO_NETWORK;
        sessioncause_value = NGAP_CauseRadioNetwork_not_supported_5QI_value;
        UE->nb_of_failed_pdusessions++;
        continue;
      }

      LOG_I(NR_RRC,
            "PDU SESSION ID %ld, DRB ID %ld (index %d), QOS flow %d, 5QI %ld \n",
            DRB_config->cnAssociation->choice.sdap_Config->pdu_Session,
            DRB_config->drb_Identity,
            i,
            qos_flow_index,
            session->param.qos[qos_flow_index].fiveQI);
    }
#endif
    session->statusF1 = PDU_SESSION_modifySent;
    session->xid = xid;

    if (session->nas_pdu.buffer != NULL) {
      asn1cSequenceAdd(dedicatedNAS_MessageList->list, NR_DedicatedNAS_Message_t, dedicatedNAS_Message);
      OCTET_STRING_fromBuf(dedicatedNAS_Message, (char *)session->nas_pdu.buffer, session->nas_pdu.length);
      free(session->nas_pdu.buffer);
      session->nas_pdu = (ngap_pdu_t){0};
      LOG_I(NR_RRC, "add NAS info with size %d (pdusession id %d)\n", session->nas_pdu.length, i);

    } else {
      // TODO
      LOG_E(NR_RRC, "no NAS info (pdusession id %d)\n", i);
    }
  }

  /* If list is empty free the list and reset the address */
  if (dedicatedNAS_MessageList->list.count == 0) {
    free(dedicatedNAS_MessageList);
    dedicatedNAS_MessageList = NULL;
  }

  memset(buffer, 0, sizeof(buffer));
  size = do_RRCReconfiguration(ctxt_pP, buffer, sizeof(buffer), xid, NULL, &DRB_configList, NULL, NULL, NULL, NULL, dedicatedNAS_MessageList, NULL, NULL, NULL, NULL, NULL);
  LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)buffer, size, "[MSG] RRC Reconfiguration\n");
  LOG_I(NR_RRC, "[gNB %d] Frame %d, Logical Channel DL-DCCH, Generate RRCReconfiguration (bytes %d, UE RNTI %x)\n", ctxt_pP->module_id, ctxt_pP->frame, size, UE->rnti);
  LOG_D(NR_RRC,
        "[FRAME %05d][RRC_gNB][MOD %u][][--- PDCP_DATA_REQ/%d Bytes (rrcReconfiguration to UE %x MUI %d) --->][PDCP][MOD %u][RB %u]\n",
        ctxt_pP->frame,
        ctxt_pP->module_id,
        size,
        UE->rnti,
        rrc_gNB_mui,
        ctxt_pP->module_id,
        DCCH);

  nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);

  if (NODE_IS_DU(RC.nrrrc[ctxt_pP->module_id]->node_type) || NODE_IS_MONOLITHIC(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
    uint32_t delay_ms = UE->masterCellGroup && UE->masterCellGroup->spCellConfig && UE->masterCellGroup->spCellConfig->spCellConfigDedicated
                                && UE->masterCellGroup->spCellConfig->spCellConfigDedicated->downlinkBWP_ToAddModList
                            ? NR_RRC_RECONFIGURATION_DELAY_MS + NR_RRC_BWP_SWITCHING_DELAY_MS
                            : NR_RRC_RECONFIGURATION_DELAY_MS;

    nr_mac_enable_ue_rrc_processing_timer(ctxt_pP->module_id, UE->rnti, *RC.nrrrc[ctxt_pP->module_id]->carrier.servingcellconfigcommon->ssbSubcarrierSpacing, delay_ms);
  }
}

//-----------------------------------------------------------------------------
void rrc_gNB_generate_dedicatedRRCReconfiguration_release(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *const ue_context_pP, uint8_t xid, uint32_t nas_length, uint8_t *nas_buffer)
//-----------------------------------------------------------------------------
{
  uint8_t buffer[RRC_BUF_SIZE];
  uint16_t size = 0;
  NR_DRB_ToReleaseList_t *DRB_Release_configList = NULL;
  struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList *dedicatedNAS_MessageList = NULL;
  NR_DedicatedNAS_Message_t *dedicatedNAS_Message = NULL;
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;

  // generateDRB(&ue_context_pP->ue_context, rrc->configuration.enable_sdap, rrc->security.do_drb_integrity, rrc->security.do_drb_ciphering);
  /* If list is empty free the list and reset the address */
  if (nas_length > 0) {
    dedicatedNAS_MessageList = CALLOC(1, sizeof(struct NR_RRCReconfiguration_v1530_IEs__dedicatedNAS_MessageList));
    dedicatedNAS_Message = CALLOC(1, sizeof(NR_DedicatedNAS_Message_t));
    memset(dedicatedNAS_Message, 0, sizeof(OCTET_STRING_t));
    OCTET_STRING_fromBuf(dedicatedNAS_Message, (char *)nas_buffer, nas_length);
    asn1cSeqAdd(&dedicatedNAS_MessageList->list, dedicatedNAS_Message);
    LOG_I(NR_RRC, "add NAS info with size %d\n", nas_length);
  } else {
    LOG_W(NR_RRC, "dedlicated NAS list is empty\n");
  }

  memset(buffer, 0, sizeof(buffer));
  size = do_RRCReconfiguration(ctxt_pP, buffer, sizeof(buffer), xid, NULL, NULL, DRB_Release_configList, NULL, NULL, NULL, dedicatedNAS_MessageList, NULL, NULL, NULL, NULL, NULL);

  UE->pdu_session_release_command_flag = 1;

  LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)buffer, size, "[MSG] RRC Reconfiguration\n");

  /* Free all NAS PDUs */
  if (nas_length > 0) {
    /* Free the NAS PDU buffer and invalidate it */
    free(nas_buffer);
  }

  LOG_I(NR_RRC, "[gNB %d] Frame %d, Logical Channel DL-DCCH, Generate NR_RRCReconfiguration (bytes %d, UE RNTI %x)\n", ctxt_pP->module_id, ctxt_pP->frame, size, UE->rnti);
  LOG_D(NR_RRC,
        "[FRAME %05d][RRC_gNB][MOD %u][][--- PDCP_DATA_REQ/%d Bytes (rrcReconfiguration to UE %x MUI %d) --->][PDCP][MOD %u][RB %u]\n",
        ctxt_pP->frame,
        ctxt_pP->module_id,
        size,
        UE->rnti,
        rrc_gNB_mui,
        ctxt_pP->module_id,
        DCCH);
  nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);

  if (NODE_IS_DU(RC.nrrrc[ctxt_pP->module_id]->node_type) || NODE_IS_MONOLITHIC(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
    uint32_t delay_ms = UE->masterCellGroup && UE->masterCellGroup->spCellConfig && UE->masterCellGroup->spCellConfig->spCellConfigDedicated
                                && UE->masterCellGroup->spCellConfig->spCellConfigDedicated->downlinkBWP_ToAddModList
                            ? NR_RRC_RECONFIGURATION_DELAY_MS + NR_RRC_BWP_SWITCHING_DELAY_MS
                            : NR_RRC_RECONFIGURATION_DELAY_MS;

    nr_mac_enable_ue_rrc_processing_timer(ctxt_pP->module_id, UE->rnti, *RC.nrrrc[ctxt_pP->module_id]->carrier.servingcellconfigcommon->ssbSubcarrierSpacing, delay_ms);
  }
}

//-----------------------------------------------------------------------------
/*
 * Process the RRC Reconfiguration Complete from the UE
 */
void rrc_gNB_process_RRCReconfigurationComplete(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *ue_context_pP, const uint8_t xid)
{
  NR_SRB_ToAddModList_t SRB_configList = {0}; // SRBFixme: was UE->SRB_configList2[xid];
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  NR_DRB_ToReleaseList_t *DRB_Release_configList;
  //  uint8_t                             nr_DRB2LCHAN[8];

  UE->ue_reestablishment_timer = 0;
  NR_DRB_ToAddModList_t DRB_configList = {0};
  fill_DRB_configList(ctxt_pP, ue_context_pP, &DRB_configList, setUE);
  fill_SRB_configList(ue_context_pP, &SRB_configList);

  /* Refresh SRBs/DRBs */
  if (!NODE_IS_CU(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
    LOG_D(NR_RRC, "Configuring RLC DRBs/SRBs for UE %x\n", UE->rnti);
    nr_rrc_rlc_config_asn1_req(ctxt_pP,
                               &SRB_configList, // NULL,
                               &DRB_configList,
                               DRB_Release_configList,
                               NULL,
                               get_softmodem_params()->sa ? UE->masterCellGroup->rlc_BearerToAddModList : NULL);
  }
}

//-----------------------------------------------------------------------------
void rrc_gNB_generate_RRCReestablishment(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *const ue_context_pP, const int CC_id)
//-----------------------------------------------------------------------------
{
  gNB_RRC_UE_t *ue_context = NULL;
  module_id_t module_id = ctxt_pP->module_id;
  // uint16_t                    rnti = ctxt_pP->rnti;
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt_pP->module_id];

  ue_context = &(ue_context_pP->ue_context);
  unsigned char buf[1024];
  int size = do_RRCReestablishment(ctxt_pP,
                                   ue_context_pP,
                                   CC_id,
                                   buf,
                                   sizeof(buf),
                                   //(uint8_t) carrier->p_gNB, // at this point we do not have the UE capability information, so it can only be TM1 or TM2
                                   rrc_gNB_get_next_transaction_identifier(module_id));

  LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " [RAPROC] Logical Channel DL-DCCH, Generating NR_RRCReestablishment (bytes %d)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size);
#if(0)
  /* TODO : It may be needed if gNB goes into full stack working. */
  UE = find_nr_UE(module_id, rnti);
  if (UE_id != -1) {
    /* Activate reject timer, if RRCComplete not received after 10 frames, reject UE */
    RC.nrmac[module_id]->UE_info.UE_sched_ctrl[UE_id].ue_reestablishment_reject_timer = 1;
    /* Reject UE after 10 frames, LTE_RRCConnectionReestablishmentReject is triggered */
    RC.nrmac[module_id]->UE_info.UE_sched_ctrl[UE_id].ue_reestablishment_reject_timer_thres = 100;
  } else {
    LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Generating NR_RRCReestablishment without UE_id(MAC) rnti %x\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), rnti);
  }
#endif

  /* correct? specs say RRCReestablishment goes through srb1... */
  f1ap_dl_rrc_message_t dl_rrc = {
    .old_gNB_DU_ue_id = 0xFFFFFF,
    .rrc_container = buf,
    .rrc_container_length = size,
    .rnti = ue_context->rnti,
    .srb_id = CCCH
  };
  rrc->mac_rrc.dl_rrc_message_transfer(ctxt_pP->module_id, &dl_rrc);
}

//-----------------------------------------------------------------------------
void rrc_gNB_process_RRCConnectionReestablishmentComplete(const protocol_ctxt_t *const ctxt_pP, const rnti_t reestablish_rnti, rrc_gNB_ue_context_t *ue_context_pP, const uint8_t old_xid)
//-----------------------------------------------------------------------------
{
  LOG_I(NR_RRC,
        PROTOCOL_RRC_CTXT_UE_FMT" [RAPROC] Logical Channel UL-DCCH, processing NR_RRCConnectionReestablishmentComplete from UE (SRB1 Active)\n",
        PROTOCOL_RRC_CTXT_UE_ARGS(ctxt_pP));
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  NR_DRB_ToAddModList_t DRB_configList = {0};
  fill_DRB_configList(ctxt_pP, ue_context_pP, &DRB_configList, setUE);

  //NR_SDAP_Config_t                      *sdap_config     = NULL;
  int i = 0;
  uint8_t                             buffer[RRC_BUF_SIZE];
  uint16_t                            size;

  uint8_t new_xid = rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id);
  UE->StatusRrc = NR_RRC_CONNECTED;
  UE->ue_rrc_inactivity_timer = 1; // set rrc inactivity when UE goes into RRC_CONNECTED
  UE->reestablishment_xid = new_xid;

  // SRBFixxxME get old configuration of SRB2
  /*
    if (*SRB_configList2 != NULL) {
    if((*SRB_configList2)->list.count!=0) {
    LOG_D(NR_RRC, "SRB_configList2(%p) count is %d\n           SRB_configList2->list.array[0] addr is %p",
    SRB_configList2, (*SRB_configList2)->list.count,  (*SRB_configList2)->list.array[0]);
    }

    for (i = 0; (i < (*SRB_configList2)->list.count) && (i < 3); i++) {
    if ((*SRB_configList2)->list.array[i]->srb_Identity == 2 ) {
    SRB2_config = (*SRB_configList2)->list.array[i];
    break;
    }
    }
    }
  */
  // UE->Srb2.Srb_info.Srb_id = 2;
  NR_SRB_ToAddModList_t SRB_configList = {0}; // SRBFIXME was: UE->SRB_configList;
  UE->Srb[1].Active = true;
  UE->Srb[1].Srb_info.Srb_id = 1;
  fill_SRB_configList(ue_context_pP, &SRB_configList);

  if (get_softmodem_params()->sa) {
    int j;

    gtpv1u_gnb_create_tunnel_req_t  create_tunnel_req={0};
    /* Save e RAB information for later */

    for (j = 0, i = 0; i < sizeofArray(UE->pduSession); i++) {
      if (UE->pduSession[i].statusE1 == PDU_SESSION_existing) {
        create_tunnel_req.pdusession_id[j] = i;
        create_tunnel_req.outgoing_teid[j] = UE->pduSession[i].gtp_teid;
        // to be developped, use the first QFI only
        create_tunnel_req.outgoing_qfi[j] = UE->pduSession[i].qos[0].qfi;
        memcpy(create_tunnel_req.dst_addr[j].buffer, UE->pduSession[i].upf_addr.buffer, sizeof(uint8_t) * 20);
        create_tunnel_req.dst_addr[j].length = UE->pduSession[i].upf_addr.length;
        j++;
      }
    }

    create_tunnel_req.ue_id = ctxt_pP->rntiMaybeUEid; // warning put zero above
    create_tunnel_req.num_tunnels    = j;
    int ret = gtpv1u_update_ngu_tunnel(ctxt_pP->instance, &create_tunnel_req, reestablish_rnti);

    UE->ue_release_timer_s1 = 1;
    UE->ue_release_timer_thres_s1 = 100;
    UE->ue_release_timer = 0;
    UE->ue_reestablishment_timer = 0;
    UE->ul_failure_timer = 20000; // set ul_failure to 20000 for triggering rrc_eNB_send_S1AP_UE_CONTEXT_RELEASE_REQ
    UE->ul_failure_timer = 0;
    return;
  }

  /* Update RNTI in ue_context */
  ue_context_pP->ue_id_rnti = ctxt_pP->rntiMaybeUEid; // here ue_id_rnti is just a key, may be something else
  UE->rnti = ctxt_pP->rntiMaybeUEid;

  if (get_softmodem_params()->sa) {
    uint8_t send_security_mode_command = false;
    nr_rrc_pdcp_config_security(ctxt_pP, ue_context_pP, send_security_mode_command ? 0 : 1);
    LOG_D(NR_RRC, "set security successfully \n");
  }

  /* Add all NAS PDUs to the list */
  for (i = 0; i < sizeofArray(UE->pduSession); i++) {
    /* TODO parameters yet to process ... */
    /* TODO should test if pdu session are Ok before! */
    UE->pduSession[i].statusF1 = PDU_SESSION_existing;
    UE->pduSession[i].xid = old_xid;
  }

  memset(buffer, 0, sizeof(buffer));

  size = do_RRCReconfiguration(ctxt_pP,
                               buffer,
                               sizeof(buffer),
                               old_xid,
                               &SRB_configList,
                               &DRB_configList,
                               NULL,
                               NULL,
                               NULL,
                               NULL, // MeasObj_list,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL);

  LOG_DUMPMSG(NR_RRC,DEBUG_RRC,(char *)buffer,size, "[MSG] RRC Reconfiguration\n");

  if(size==65535) {
    LOG_E(NR_RRC,"RRC decode err!!! do_RRCReconfiguration\n");
    return;
  } else {
    LOG_I(NR_RRC, "[gNB %d] Frame %d, Logical Channel DL-DCCH, Generate NR_RRCConnectionReconfiguration (bytes %d, UE id %x)\n", ctxt_pP->module_id, ctxt_pP->frame, size, UE->rnti);
    LOG_D(NR_RRC,
          "[FRAME %05d][RRC_gNB][MOD %u][][--- PDCP_DATA_REQ/%d Bytes (rrcConnectionReconfiguration to UE %x MUI %d) --->][PDCP][MOD %u][RB %u]\n",
          ctxt_pP->frame,
          ctxt_pP->module_id,
          size,
          UE->rnti,
          rrc_gNB_mui,
          ctxt_pP->module_id,
          DCCH);
    nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);
  }

  if (NODE_IS_DU(RC.nrrrc[ctxt_pP->module_id]->node_type) || NODE_IS_MONOLITHIC(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
    uint32_t delay_ms = UE->masterCellGroup && UE->masterCellGroup->spCellConfig && UE->masterCellGroup->spCellConfig->spCellConfigDedicated
                                && UE->masterCellGroup->spCellConfig->spCellConfigDedicated->downlinkBWP_ToAddModList
                            ? NR_RRC_RECONFIGURATION_DELAY_MS + NR_RRC_BWP_SWITCHING_DELAY_MS
                            : NR_RRC_RECONFIGURATION_DELAY_MS;

    nr_mac_enable_ue_rrc_processing_timer(ctxt_pP->module_id, UE->rnti, *RC.nrrrc[ctxt_pP->module_id]->carrier.servingcellconfigcommon->ssbSubcarrierSpacing, delay_ms);
  }
}
//-----------------------------------------------------------------------------

int nr_rrc_reconfiguration_req(rrc_gNB_ue_context_t         *const ue_context_pP,
                               protocol_ctxt_t              *const ctxt_pP,
                               const int                    dl_bwp_id,
                               const int                    ul_bwp_id) {

  uint8_t buffer[RRC_BUF_SIZE];
  memset(buffer, 0, sizeof(buffer));
  uint8_t xid = rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id);
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;

  NR_CellGroupConfig_t *masterCellGroup = UE->masterCellGroup;
  if (dl_bwp_id > 0) {
    *masterCellGroup->spCellConfig->spCellConfigDedicated->firstActiveDownlinkBWP_Id = dl_bwp_id;
    *masterCellGroup->spCellConfig->spCellConfigDedicated->defaultDownlinkBWP_Id = dl_bwp_id;
  }
  if (ul_bwp_id > 0) {
    *masterCellGroup->spCellConfig->spCellConfigDedicated->uplinkConfig->firstActiveUplinkBWP_Id = ul_bwp_id;
  }

  uint16_t  size = do_RRCReconfiguration(ctxt_pP,
                                         buffer,
                                         sizeof(buffer),
                                         xid,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         ue_context_pP,
                                         NULL,
                                         NULL,
                                         NULL,
                                         masterCellGroup);

  gNB_RrcConfigurationReq *configuration = &RC.nrrrc[ctxt_pP->module_id]->configuration;
  rrc_mac_config_req_gNB(
      ctxt_pP->module_id, configuration->pdsch_AntennaPorts, configuration->pusch_AntennaPorts, configuration->sib1_tda, configuration->minRXTXTIME, NULL, NULL, NULL, 0, UE->rnti, masterCellGroup);

  nr_rrc_data_req(ctxt_pP,
                  DCCH,
                  rrc_gNB_mui++,
                  SDU_CONFIRM_NO,
                  size,
                  buffer,
                  PDCP_TRANSMISSION_MODE_CONTROL);

  if (NODE_IS_DU(RC.nrrrc[ctxt_pP->module_id]->node_type) || NODE_IS_MONOLITHIC(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
    uint32_t delay_ms = UE->masterCellGroup && UE->masterCellGroup->spCellConfig && UE->masterCellGroup->spCellConfig->spCellConfigDedicated
                                && UE->masterCellGroup->spCellConfig->spCellConfigDedicated->downlinkBWP_ToAddModList
                            ? NR_RRC_RECONFIGURATION_DELAY_MS + NR_RRC_BWP_SWITCHING_DELAY_MS
                            : NR_RRC_RECONFIGURATION_DELAY_MS;

    nr_mac_enable_ue_rrc_processing_timer(ctxt_pP->module_id, UE->rnti, *RC.nrrrc[ctxt_pP->module_id]->carrier.servingcellconfigcommon->ssbSubcarrierSpacing, delay_ms);
  }

  return 0;
}

/*------------------------------------------------------------------------------*/
int nr_rrc_gNB_decode_ccch(protocol_ctxt_t    *const ctxt_pP,
                           const uint8_t      *buffer,
                           int                buffer_length,
                           const uint8_t      *du_to_cu_rrc_container,
                           int                du_to_cu_rrc_container_len)
{
  module_id_t                                       Idx;
  asn_dec_rval_t                                    dec_rval;
  NR_UL_CCCH_Message_t                             *ul_ccch_msg = NULL;
  struct rrc_gNB_ue_context_s                      *ue_context_p = NULL;
  gNB_RRC_INST                                     *gnb_rrc_inst = RC.nrrrc[ctxt_pP->module_id];
  NR_RRCSetupRequest_IEs_t                         *rrcSetupRequest = NULL;
  NR_RRCReestablishmentRequest_IEs_t                rrcReestablishmentRequest;
  uint64_t                                          random_value = 0;

  LOG_I(NR_RRC, "Decoding CCCH: RNTI %04lx, inst %ld, payload_size %d\n", ctxt_pP->rntiMaybeUEid, ctxt_pP->instance, buffer_length);
  dec_rval = uper_decode(NULL, &asn_DEF_NR_UL_CCCH_Message, (void **) &ul_ccch_msg, buffer, buffer_length, 0, 0);

  if (dec_rval.code != RC_OK || dec_rval.consumed == 0) {
    LOG_E(NR_RRC,
          PROTOCOL_NR_RRC_CTXT_UE_FMT" FATAL Error in receiving CCCH\n",
          PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
    return -1;
  }

  if (ul_ccch_msg->message.present == NR_UL_CCCH_MessageType_PR_c1) {
    switch (ul_ccch_msg->message.choice.c1->present) {
      case NR_UL_CCCH_MessageType__c1_PR_NOTHING:
        /* TODO */
        LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_FMT " Received PR_NOTHING on UL-CCCH-Message\n", PROTOCOL_NR_RRC_CTXT_ARGS(ctxt_pP));
        break;

      case NR_UL_CCCH_MessageType__c1_PR_rrcSetupRequest:
        LOG_D(NR_RRC, "Received RRCSetupRequest on UL-CCCH-Message (UE rnti %lx)\n", ctxt_pP->rntiMaybeUEid);
        ue_context_p = rrc_gNB_get_ue_context(gnb_rrc_inst, ctxt_pP->rntiMaybeUEid);
        if (ue_context_p != NULL) {
          rrc_gNB_free_mem_UE_context(ue_context_p);
        } else {
          rrcSetupRequest = &ul_ccch_msg->message.choice.c1->choice.rrcSetupRequest->rrcSetupRequest;
          if (NR_InitialUE_Identity_PR_randomValue == rrcSetupRequest->ue_Identity.present) {
            /* randomValue                         BIT STRING (SIZE (39)) */
            if (rrcSetupRequest->ue_Identity.choice.randomValue.size != 5) { // 39-bit random value
              LOG_E(NR_RRC, "wrong InitialUE-Identity randomValue size, expected 5, provided %lu", (long unsigned int)rrcSetupRequest->ue_Identity.choice.randomValue.size);
              return -1;
            }

            memcpy(((uint8_t *)&random_value) + 3, rrcSetupRequest->ue_Identity.choice.randomValue.buf, rrcSetupRequest->ue_Identity.choice.randomValue.size);

            /* if there is already a registered UE (with another RNTI) with this random_value,
             * the current one must be removed from MAC/PHY (zombie UE)
             */
            if ((ue_context_p = rrc_gNB_ue_context_random_exist(RC.nrrrc[ctxt_pP->module_id], random_value))) {
              LOG_W(NR_RRC, "new UE rnti %lx (coming with random value) is already there \n", ctxt_pP->rntiMaybeUEid);
              ue_context_p->ue_context.ul_failure_timer = 20000;
            }

            ue_context_p = rrc_gNB_new_ue_context(random_value, RC.nrrrc[ctxt_pP->module_id], random_value);
          } else if (NR_InitialUE_Identity_PR_ng_5G_S_TMSI_Part1 == rrcSetupRequest->ue_Identity.present) {
            /* TODO */
            /* <5G-S-TMSI> = <AMF Set ID><AMF Pointer><5G-TMSI> 48-bit */
            /* ng-5G-S-TMSI-Part1                  BIT STRING (SIZE (39)) */
            if (rrcSetupRequest->ue_Identity.choice.ng_5G_S_TMSI_Part1.size != 5) {
              LOG_E(NR_RRC, "wrong ng_5G_S_TMSI_Part1 size, expected 5, provided %lu \n", (long unsigned int)rrcSetupRequest->ue_Identity.choice.ng_5G_S_TMSI_Part1.size);
              return -1;
            }

            uint64_t s_tmsi_part1 = bitStr_to_uint64(&rrcSetupRequest->ue_Identity.choice.ng_5G_S_TMSI_Part1);

            // memcpy(((uint8_t *) & random_value) + 3,
            //         rrcSetupRequest->ue_Identity.choice.ng_5G_S_TMSI_Part1.buf,
            //         rrcSetupRequest->ue_Identity.choice.ng_5G_S_TMSI_Part1.size);

            if ((ue_context_p = rrc_gNB_ue_context_5g_s_tmsi_exist(RC.nrrrc[ctxt_pP->module_id], s_tmsi_part1))) {
              LOG_I(NR_RRC, " 5G-S-TMSI-Part1 exists, %lx\n", ctxt_pP->rntiMaybeUEid);

              // TODO: MAC structures should not be accessed directly from the RRC! An implementation using the F1 interface should be developed.
              gNB_MAC_INST *nrmac = RC.nrmac[ctxt_pP->module_id]; // WHAT A BEAUTIFULL RACE CONDITION !!!
              mac_remove_nr_ue(nrmac, ue_context_p->ue_context.rnti);

              /* replace rnti in the context */
              /* for that, remove the context from the RB tree */
              rrc_gNB_remove_ue_context(RC.nrrrc[ctxt_pP->module_id], ue_context_p);
              /* and insert again, after changing rnti everywhere it has to be changed */
              ue_context_p->ue_id_rnti = ctxt_pP->rntiMaybeUEid;
              UE->rnti = ctxt_pP->rntiMaybeUEid;
              rrc_gNB_insert_ue_context(ue_context_p);
              /* reset timers */
              UE->ul_failure_timer = 0;
              UE->ue_release_timer = 0;
              UE->ue_reestablishment_timer = 0;
              UE->ue_release_timer_s1 = 0;
              UE->ue_release_timer_rrc = 0;
            } else {
              LOG_I(NR_RRC, " 5G-S-TMSI-Part1 doesn't exist, setting ng_5G_S_TMSI_Part1 to %p => %ld\n", ue_context_p, s_tmsi_part1);

              ue_context_p = rrc_gNB_new_ue_context(ctxt_pP->rntiMaybeUEid, RC.nrrrc[ctxt_pP->module_id], s_tmsi_part1);

              if (ue_context_p == NULL) {
                LOG_E(RRC, "%s:%d:%s: rrc_gNB_get_new_ue_context returned NULL\n", __FILE__, __LINE__, __FUNCTION__);
              }

              if (ue_context_p != NULL) {
                UE->Initialue_identity_5g_s_TMSI.presence = true;
                UE->ng_5G_S_TMSI_Part1 = s_tmsi_part1;
              }
            }
          } else {
            /* TODO */
            memcpy(((uint8_t *)&random_value) + 3, rrcSetupRequest->ue_Identity.choice.randomValue.buf, rrcSetupRequest->ue_Identity.choice.randomValue.size);

            rrc_gNB_new_ue_context(ctxt_pP->rntiMaybeUEid, RC.nrrrc[ctxt_pP->module_id], random_value);
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " RRCSetupRequest without random UE identity or S-TMSI not supported, let's reject the UE\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
            rrc_gNB_generate_RRCReject(ctxt_pP, rrc_gNB_get_ue_context(gnb_rrc_inst, ctxt_pP->rntiMaybeUEid));
            break;
          }

          UE->establishment_cause = rrcSetupRequest->establishmentCause;

          rrc_gNB_generate_RRCSetup(
              ctxt_pP, rrc_gNB_get_ue_context(gnb_rrc_inst, ctxt_pP->rntiMaybeUEid), du_to_cu_rrc_container, du_to_cu_rrc_container_len, gnb_rrc_inst->carrier.servingcellconfigcommon);
        }
        break;

      case NR_UL_CCCH_MessageType__c1_PR_rrcResumeRequest:
        LOG_I(NR_RRC, "receive rrcResumeRequest message \n");
        break;

      case NR_UL_CCCH_MessageType__c1_PR_rrcReestablishmentRequest:
        LOG_I(NR_RRC, "receive rrcReestablishmentRequest message \n");
        LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)(buffer), buffer_length, "[MSG] RRC Reestablishment Request\n");
        LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT "MAC_gNB--- MAC_DATA_IND (rrcReestablishmentRequest on SRB0) --> RRC_gNB\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));

        rrcReestablishmentRequest = ul_ccch_msg->message.choice.c1->choice.rrcReestablishmentRequest->rrcReestablishmentRequest;
        LOG_I(NR_RRC,
              PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCReestablishmentRequest cause %s\n",
              PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
              ((rrcReestablishmentRequest.reestablishmentCause == NR_ReestablishmentCause_otherFailure)      ? "Other Failure"
               : (rrcReestablishmentRequest.reestablishmentCause == NR_ReestablishmentCause_handoverFailure) ? "Handover Failure"
                                                                                                             : "reconfigurationFailure"));
        {
          uint16_t c_rnti = 0;
          if (rrcReestablishmentRequest.ue_Identity.physCellId != RC.nrrrc[ctxt_pP->module_id]->carrier.physCellId) {
            /* UE was moving from previous cell so quickly that RRCReestablishment for previous cell was recieved in this cell */
            LOG_E(NR_RRC,
                  PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCReestablishmentRequest ue_Identity.physCellId(%ld) is not equal to current physCellId(%d), fallback to RRC establishment\n",
                  PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
                  rrcReestablishmentRequest.ue_Identity.physCellId,
                  RC.nrrrc[ctxt_pP->module_id]->carrier.physCellId);
            rrc_gNB_generate_RRCSetup_for_RRCReestablishmentRequest(ctxt_pP, 0);
            break;
          }

          LOG_D(NR_RRC, "physCellId is %ld\n", rrcReestablishmentRequest.ue_Identity.physCellId);

          for (int i = 0; i < rrcReestablishmentRequest.ue_Identity.shortMAC_I.size; i++) {
            LOG_D(NR_RRC, "rrcReestablishmentRequest.ue_Identity.shortMAC_I.buf[%d] = %x\n", i, rrcReestablishmentRequest.ue_Identity.shortMAC_I.buf[i]);
          }

          if (rrcReestablishmentRequest.ue_Identity.c_RNTI < 0 || rrcReestablishmentRequest.ue_Identity.c_RNTI > 65535) {
            /* c_RNTI range error should not happen */
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCReestablishmentRequest c_RNTI range error, fallback to RRC establishment\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
            rrc_gNB_generate_RRCSetup_for_RRCReestablishmentRequest(ctxt_pP, 0);
            break;
          }

          c_rnti = rrcReestablishmentRequest.ue_Identity.c_RNTI;
          LOG_I(NR_RRC, "c_rnti is %x\n", c_rnti);
          ue_context_p = rrc_gNB_get_ue_context(gnb_rrc_inst, c_rnti);

          if (ue_context_p == NULL) {
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCReestablishmentRequest without UE context, fallback to RRC establishment\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
            rrc_gNB_generate_RRCSetup_for_RRCReestablishmentRequest(ctxt_pP, 0);
            break;
          }
#if(0)
          /* TODO : It may be needed if gNB goes into full stack working. */
          int UE_id = find_nr_UE_id(ctxt_pP->module_id, c_rnti);

          if (UE_id == -1) {
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCReestablishmentRequest without UE_id(MAC) rnti %x, fallback to RRC establishment\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), c_rnti);
            rrc_gNB_generate_RRCSetup_for_RRCReestablishmentRequest(ctxt_pP, 0);
            break;
          }

          // previous rnti
          rnti_t previous_rnti = 0;

          for (int i = 0; i < MAX_MOBILES_PER_ENB; i++) {
            if (reestablish_rnti_map[i][1] == c_rnti) {
              previous_rnti = reestablish_rnti_map[i][0];
              break;
            }
          }

          if (previous_rnti != 0) {
            UE_id = find_nr_UE_id(ctxt_pP->module_id, previous_rnti);

            if (UE_id == -1) {
              LOG_E(NR_RRC,
                    PROTOCOL_NR_RRC_CTXT_UE_FMT " RRCReestablishmentRequest without UE_id(MAC) previous rnti %x, fallback to RRC establishment\n",
                    PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
                    previous_rnti);
              rrc_gNB_generate_RRCSetup_for_RRCReestablishmentRequest(ctxt_pP, 0);
              break;
            }
          }
#endif
          // c-plane not end
          if ((UE->StatusRrc != NR_RRC_RECONFIGURED) && (UE->reestablishment_cause == NR_ReestablishmentCause_spare1)) {
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCReestablishmentRequest (UE %x c-plane is not end), RRC establishment failed \n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), c_rnti);
            /* TODO RRC Release ? */
            break;
          }

          if (UE->ue_reestablishment_timer > 0) {
            LOG_E(NR_RRC,
                  PROTOCOL_NR_RRC_CTXT_UE_FMT " RRRCReconfigurationComplete(Previous) don't receive, delete the Previous UE,\nprevious Status %d, new Status NR_RRC_RECONFIGURED\n",
                  PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
                  UE->StatusRrc);
            UE->StatusRrc = NR_RRC_RECONFIGURED;
            protocol_ctxt_t ctxt_old_p;
            PROTOCOL_CTXT_SET_BY_INSTANCE(&ctxt_old_p, ctxt_pP->instance, GNB_FLAG_YES, c_rnti, ctxt_pP->frame, ctxt_pP->subframe);
            rrc_gNB_process_RRCReconfigurationComplete(&ctxt_old_p, ue_context_p, UE->reestablishment_xid);

            for (uint8_t pdusessionid = 0; pdusessionid < sizeofArray(UE->pduSession); pdusessionid++) {
              if (UE->pduSession[pdusessionid].statusF1 == PDU_SESSION_toCreate) {
                UE->pduSession[pdusessionid].status = PDU_SESSION_existing;
              } else {
                UE->pduSession[pdusessionid].status = PDU_SESSION_failed;
              }
            }
          }
          /* reset timers */
          UE->ul_failure_timer = 0;
          UE->ue_release_timer = 0;
          UE->ue_reestablishment_timer = 0;
          // UE->ue_release_timer_s1 = 0;
          UE->ue_release_timer_rrc = 0;
          UE->reestablishment_xid = -1;

          // insert C-RNTI to map
          for (int i = 0; i < MAX_MOBILES_PER_ENB; i++) {
            if (reestablish_rnti_map[i][0] == 0) {
              reestablish_rnti_map[i][0] = ctxt_pP->rntiMaybeUEid;
              reestablish_rnti_map[i][1] = c_rnti;
              LOG_D(NR_RRC, "reestablish_rnti_map[%d] [0] %x, [1] %x\n", i, reestablish_rnti_map[i][0], reestablish_rnti_map[i][1]);
              break;
            }
          }

          UE->reestablishment_cause = rrcReestablishmentRequest.reestablishmentCause;
          LOG_D(NR_RRC,
                PROTOCOL_NR_RRC_CTXT_UE_FMT " Accept reestablishment request from UE physCellId %ld cause %ld\n",
                PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
                rrcReestablishmentRequest.ue_Identity.physCellId,
                UE->reestablishment_cause);

          UE->primaryCC_id = 0;
          // LG COMMENT Idx = (ue_mod_idP * NB_RB_MAX) + DCCH;
          Idx = DCCH;
          // SRB1
          UE->Srb[Idx].Active = true;
          UE->Srb[Idx].Srb_info.Srb_id = Idx;
          rrc_init_nr_srb_param(&UE->Srb[1].Srb_info.Lchan_desc[0]);
          rrc_init_nr_srb_param(&UE->Srb[1].Srb_info.Lchan_desc[1]);
          // SRB2: set  it to go through SRB1 with id 1 (DCCH)//SRBFixme: check if this is 3GPP correct
          UE->Srb[2].Active = true;
          UE->Srb[2].Srb_info.Srb_id = Idx;
          rrc_init_nr_srb_param(&UE->Srb[2].Srb_info.Lchan_desc[0]);
          rrc_init_nr_srb_param(&UE->Srb[2].Srb_info.Lchan_desc[1]);

          rrc_gNB_generate_RRCReestablishment(ctxt_pP, ue_context_p, 0);

          LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT "CALLING RLC CONFIG SRB1 (rbid %d)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), Idx);
        }
        break;

      case NR_UL_CCCH_MessageType__c1_PR_rrcSystemInfoRequest:
        LOG_I(NR_RRC, "receive rrcSystemInfoRequest message \n");
        /* TODO */
        break;

      default:
        LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Unknown message\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
        break;
    }
  }
  return 0;
}

/*! \fn uint64_t bitStr_to_uint64(BIT_STRING_t *)
 *\brief  This function extract at most a 64 bits value from a BIT_STRING_t object, the exact bits number depend on the BIT_STRING_t contents.
 *\param[in] pointer to the BIT_STRING_t object.
 *\return the extracted value.
 */
static inline uint64_t bitStr_to_uint64(BIT_STRING_t *asn) {
  uint64_t result = 0;
  int index;
  int shift;

  DevCheck ((asn->size > 0) && (asn->size <= 8), asn->size, 0, 0);

  shift = ((asn->size - 1) * 8) - asn->bits_unused;
  for (index = 0; index < (asn->size - 1); index++) {
    result |= (uint64_t)asn->buf[index] << shift;
    shift -= 8;
  }

  result |= asn->buf[index] >> asn->bits_unused;

  return result;
}

static void rrc_gNB_process_MeasurementReport(rrc_gNB_ue_context_t *ue_context, const NR_MeasurementReport_t *measurementReport)
{
  if (LOG_DEBUGFLAG(DEBUG_ASN1))
    xer_fprint(stdout, &asn_DEF_NR_MeasurementReport, (void *)measurementReport);

  DevAssert(measurementReport->criticalExtensions.present == NR_MeasurementReport__criticalExtensions_PR_measurementReport
            && measurementReport->criticalExtensions.choice.measurementReport != NULL);

  gNB_RRC_UE_t *ue_ctxt = &ue_context->ue_context;
  if (ue_ctxt->measResults != NULL) {
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NR_MeasResults, ue_ctxt->measResults);
    ue_ctxt->measResults = NULL;
  }

  const NR_MeasId_t id = measurementReport->criticalExtensions.choice.measurementReport->measResults.measId;
  AssertFatal(id, "unexpected MeasResult for MeasurementId %ld received\n", id);
  asn1cCallocOne(ue_ctxt->measResults, measurementReport->criticalExtensions.choice.measurementReport->measResults);
}

//-----------------------------------------------------------------------------
int rrc_gNB_decode_dcch(const protocol_ctxt_t *const ctxt_pP, const rb_id_t Srb_id, const uint8_t *const Rx_sdu, const sdu_size_t sdu_sizeP)
//-----------------------------------------------------------------------------
{
  asn_dec_rval_t                      dec_rval;
  NR_UL_DCCH_Message_t                *ul_dcch_msg  = NULL;
  struct rrc_gNB_ue_context_s         *ue_context_p = NULL;
  uint8_t                             xid;

  int i;

  if ((Srb_id != 1) && (Srb_id != 2)) {
    LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT" Received message on SRB%ld, should not have ...\n",
          PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
          Srb_id);
  } else {
    LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Received message on SRB%ld\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), Srb_id);
  }

  LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Decoding UL-DCCH Message\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));

  //for (int i=0;i<sdu_sizeP;i++) printf("%02x ",Rx_sdu[i]);
  //printf("\n");

  dec_rval = uper_decode(NULL, &asn_DEF_NR_UL_DCCH_Message, (void **)&ul_dcch_msg, Rx_sdu, sdu_sizeP, 0, 0);

  if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
    xer_fprint(stdout, &asn_DEF_NR_UL_DCCH_Message, (void *)ul_dcch_msg);
  }

  {
    for (i = 0; i < sdu_sizeP; i++) {
      LOG_T(NR_RRC, "%x.", Rx_sdu[i]);
    }

    LOG_T(NR_RRC, "\n");
  }

  if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
    LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Failed to decode UL-DCCH (%zu bytes)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), dec_rval.consumed);
    return -1;
  }

  ue_context_p = rrc_gNB_get_ue_context(RC.nrrrc[ctxt_pP->module_id], ctxt_pP->rntiMaybeUEid);
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;

  if (ul_dcch_msg->message.present == NR_UL_DCCH_MessageType_PR_c1) {
    switch (ul_dcch_msg->message.choice.c1->present) {
      case NR_UL_DCCH_MessageType__c1_PR_NOTHING:
        LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_FMT " Received PR_NOTHING on UL-DCCH-Message\n", PROTOCOL_NR_RRC_CTXT_ARGS(ctxt_pP));
        break;

      case NR_UL_DCCH_MessageType__c1_PR_rrcReconfigurationComplete:
        LOG_I(NR_RRC, "Receive RRC Reconfiguration Complete message UE %lx\n", ctxt_pP->rntiMaybeUEid);
        if (!ue_context_p) {
          LOG_E(NR_RRC, "Processing NR_RRCReconfigurationComplete UE %lx, ue_context_p is NULL\n", ctxt_pP->rntiMaybeUEid);
          break;
        }

        LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)(Rx_sdu), sdu_sizeP, "[MSG] RRC Connection Reconfiguration Complete\n");
        LOG_D(NR_RRC,
              PROTOCOL_NR_RRC_CTXT_UE_FMT
              " RLC RB %02d --- RLC_DATA_IND %d bytes "
              "(RRCReconfigurationComplete) ---> RRC_gNB]\n",
              PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH,
              sdu_sizeP);

        if (ul_dcch_msg->message.choice.c1->present == NR_UL_DCCH_MessageType__c1_PR_rrcReconfigurationComplete) {
          if (ul_dcch_msg->message.choice.c1->choice.rrcReconfigurationComplete->criticalExtensions.present == NR_RRCReconfigurationComplete__criticalExtensions_PR_rrcReconfigurationComplete)
            rrc_gNB_process_RRCReconfigurationComplete(ctxt_pP, ue_context_p, ul_dcch_msg->message.choice.c1->choice.rrcReconfigurationComplete->rrc_TransactionIdentifier);
        }

        if (get_softmodem_params()->sa) {
          if (UE->pdu_session_release_command_flag == 1) {
            xid = ul_dcch_msg->message.choice.c1->choice.rrcReconfigurationComplete->rrc_TransactionIdentifier;
            UE->pdu_session_release_command_flag = 0;
            // gtp tunnel delete
            gtpv1u_gnb_delete_tunnel_req_t req = {0};
            for (i = 0; i < NB_RB_MAX; i++) {
              if (xid == UE->pduSession[i].xid) {
                req.pdusession_id[req.num_pdusession++] = UE->gnb_gtp_psi[i];
                UE->gnb_gtp_teid[i] = 0;
                memset(&UE->gnb_gtp_addrs[i], 0, sizeof(UE->gnb_gtp_addrs[i]));
                UE->gnb_gtp_psi[i] = 0;
              }
            }
            gtpv1u_delete_ngu_tunnel(ctxt_pP->instance, &req);
            // NGAP_PDUSESSION_RELEASE_RESPONSE
            rrc_gNB_send_NGAP_PDUSESSION_RELEASE_RESPONSE(ctxt_pP, ue_context_p, xid);
            rrc_gNB_send_NGAP_PDUSESSION_SETUP_RESP(ctxt_pP, ue_context_p, ul_dcch_msg->message.choice.c1->choice.rrcReconfigurationComplete->rrc_TransactionIdentifier);
            rrc_gNB_send_NGAP_PDUSESSION_MODIFY_RESP(ctxt_pP, ue_context_p, ul_dcch_msg->message.choice.c1->choice.rrcReconfigurationComplete->rrc_TransactionIdentifier);
          }
        }
        if (first_rrcreconfiguration == 0) {
          first_rrcreconfiguration = 1;
          rrc_gNB_send_NGAP_INITIAL_CONTEXT_SETUP_RESP(ctxt_pP, ue_context_p);
        }

        break;

      case NR_UL_DCCH_MessageType__c1_PR_rrcSetupComplete:
        if(!ue_context_p) {
          LOG_I(NR_RRC, "Processing NR_RRCSetupComplete UE %lx, ue_context_p is NULL\n", ctxt_pP->rntiMaybeUEid);
          break;
        }

        LOG_DUMPMSG(NR_RRC, DEBUG_RRC,(char *)Rx_sdu,sdu_sizeP,
                    "[MSG] RRC SetupComplete\n");
        LOG_D(NR_RRC,
              PROTOCOL_NR_RRC_CTXT_UE_FMT
              " RLC RB %02d --- RLC_DATA_IND %d bytes "
              "(RRCSetupComplete) ---> RRC_gNB\n",
              PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH,
              sdu_sizeP);

        if (ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.present == NR_RRCSetupComplete__criticalExtensions_PR_rrcSetupComplete) {
          if (ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value != NULL) {
            if (ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->present
                == NR_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value_PR_ng_5G_S_TMSI_Part2) {
              // ng-5G-S-TMSI-Part2                  BIT STRING (SIZE (9))
              if (ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->choice.ng_5G_S_TMSI_Part2.size != 2) {
                LOG_E(NR_RRC,
                      "wrong ng_5G_S_TMSI_Part2 size, expected 2, provided %lu",
                      (long unsigned int)ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->choice.ng_5G_S_TMSI_Part2.size);
                return -1;
              }

              if (UE->ng_5G_S_TMSI_Part1 != 0) {
                UE->ng_5G_S_TMSI_Part2 =
                    BIT_STRING_to_uint16(&ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->choice.ng_5G_S_TMSI_Part2);
              }

              /* TODO */
            } else if (ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->present
                       == NR_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value_PR_ng_5G_S_TMSI) {
              // NG-5G-S-TMSI ::=                         BIT STRING (SIZE (48))
              if (ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->choice.ng_5G_S_TMSI.size != 6) {
                LOG_E(NR_RRC,
                      "wrong ng_5G_S_TMSI size, expected 6, provided %lu",
                      (long unsigned int)ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->choice.ng_5G_S_TMSI.size);
                return -1;
              }

              uint64_t fiveg_s_TMSI = bitStr_to_uint64(&ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value->choice.ng_5G_S_TMSI);
              LOG_I(NR_RRC,
                    "Received rrcSetupComplete, 5g_s_TMSI: 0x%lX, amf_set_id: 0x%lX(%ld), amf_pointer: 0x%lX(%ld), 5g TMSI: 0x%X \n",
                    fiveg_s_TMSI,
                    fiveg_s_TMSI >> 38,
                    fiveg_s_TMSI >> 38,
                    (fiveg_s_TMSI >> 32) & 0x3F,
                    (fiveg_s_TMSI >> 32) & 0x3F,
                    (uint32_t)fiveg_s_TMSI);
              if (UE->Initialue_identity_5g_s_TMSI.presence == true) {
                UE->Initialue_identity_5g_s_TMSI.amf_set_id = fiveg_s_TMSI >> 38;
                UE->Initialue_identity_5g_s_TMSI.amf_pointer = (fiveg_s_TMSI >> 32) & 0x3F;
                UE->Initialue_identity_5g_s_TMSI.fiveg_tmsi = (uint32_t)fiveg_s_TMSI;
              }
            }
          }

          rrc_gNB_process_RRCSetupComplete(ctxt_pP, ue_context_p, ul_dcch_msg->message.choice.c1->choice.rrcSetupComplete->criticalExtensions.choice.rrcSetupComplete);
          LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " UE State = NR_RRC_CONNECTED \n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
        }

        UE->ue_release_timer = 0;
        break;

      case NR_UL_DCCH_MessageType__c1_PR_measurementReport:
        DevAssert(ul_dcch_msg != NULL
                  && ul_dcch_msg->message.present == NR_UL_DCCH_MessageType_PR_c1
                  && ul_dcch_msg->message.choice.c1
                  && ul_dcch_msg->message.choice.c1->present == NR_UL_DCCH_MessageType__c1_PR_measurementReport);
        rrc_gNB_process_MeasurementReport(ue_context_p, ul_dcch_msg->message.choice.c1->choice.measurementReport);
        break;

      case NR_UL_DCCH_MessageType__c1_PR_ulInformationTransfer:
        LOG_I(NR_RRC, "Recived RRC GNB UL Information Transfer \n");
        if (!ue_context_p) {
          LOG_I(NR_RRC, "Processing ulInformationTransfer UE %lx, ue_context_p is NULL\n", ctxt_pP->rntiMaybeUEid);
          break;
        }

        LOG_D(NR_RRC, "[MSG] RRC UL Information Transfer \n");
        LOG_DUMPMSG(RRC, DEBUG_RRC, (char *)Rx_sdu, sdu_sizeP, "[MSG] RRC UL Information Transfer \n");

        if (get_softmodem_params()->sa) {
          rrc_gNB_send_NGAP_UPLINK_NAS(ctxt_pP, ue_context_p, ul_dcch_msg);
        }
        break;

      case NR_UL_DCCH_MessageType__c1_PR_securityModeComplete:
        // to avoid segmentation fault
        if (!ue_context_p) {
          LOG_I(NR_RRC, "Processing securityModeComplete UE %lx, ue_context_p is NULL\n", ctxt_pP->rntiMaybeUEid);
          break;
        }

        LOG_I(NR_RRC,
              PROTOCOL_NR_RRC_CTXT_UE_FMT" received securityModeComplete on UL-DCCH %d from UE\n",
              PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH);
        LOG_D(NR_RRC,
              PROTOCOL_NR_RRC_CTXT_UE_FMT" RLC RB %02d --- RLC_DATA_IND %d bytes "
              "(securityModeComplete) ---> RRC_eNB\n",
              PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH,
              sdu_sizeP);

        if ( LOG_DEBUGFLAG(DEBUG_ASN1) ) {
          xer_fprint(stdout, &asn_DEF_NR_UL_DCCH_Message, (void *)ul_dcch_msg);
        }

        /* configure ciphering */
        nr_rrc_pdcp_config_security(ctxt_pP, ue_context_p, 1);

        rrc_gNB_generate_UECapabilityEnquiry(ctxt_pP, ue_context_p);
        break;
      case NR_UL_DCCH_MessageType__c1_PR_securityModeFailure:
        LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)Rx_sdu, sdu_sizeP, "[MSG] NR RRC Security Mode Failure\n");
        LOG_W(NR_RRC,
              PROTOCOL_RRC_CTXT_UE_FMT
              " RLC RB %02d --- RLC_DATA_IND %d bytes "
              "(securityModeFailure) ---> RRC_gNB\n",
              PROTOCOL_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH,
              sdu_sizeP);

        if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
          xer_fprint(stdout, &asn_DEF_NR_UL_DCCH_Message, (void *)ul_dcch_msg);
        }

        rrc_gNB_generate_UECapabilityEnquiry(ctxt_pP, ue_context_p);
        break;

      case NR_UL_DCCH_MessageType__c1_PR_ueCapabilityInformation:
        if(!ue_context_p) {
          LOG_I(NR_RRC, "Processing ueCapabilityInformation UE %lx, ue_context_p is NULL\n", ctxt_pP->rntiMaybeUEid);
          break;
        }

        LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)Rx_sdu, sdu_sizeP, "[MSG] NR_RRC UECapablility Information\n");
        LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " received ueCapabilityInformation on UL-DCCH %d from UE\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), DCCH);
        LOG_D(RRC,
              PROTOCOL_NR_RRC_CTXT_UE_FMT
              " RLC RB %02d --- RLC_DATA_IND %d bytes "
              "(UECapabilityInformation) ---> RRC_eNB\n",
              PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH,
              sdu_sizeP);
        if ( LOG_DEBUGFLAG(DEBUG_ASN1) ) {
          xer_fprint(stdout, &asn_DEF_NR_UL_DCCH_Message, (void *)ul_dcch_msg);
        }
        LOG_I(NR_RRC, "got UE capabilities for UE %lx\n", ctxt_pP->rntiMaybeUEid);
        int eutra_index = -1;

        if (ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.present == NR_UECapabilityInformation__criticalExtensions_PR_ueCapabilityInformation) {
          for(i = 0;i < ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.count; i++){
            if (ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]->rat_Type
                == NR_RAT_Type_nr) {
              if (UE->UE_Capability_nr) {
                ASN_STRUCT_FREE(asn_DEF_NR_UE_NR_Capability, UE->UE_Capability_nr);
                UE->UE_Capability_nr = 0;
              }

              dec_rval = uper_decode(NULL,
                                     &asn_DEF_NR_UE_NR_Capability,
                                     (void **)&UE->UE_Capability_nr,
                                     ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]
                                         ->ue_CapabilityRAT_Container.buf,
                                     ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]
                                         ->ue_CapabilityRAT_Container.size,
                                     0,
                                     0);
              if(LOG_DEBUGFLAG(DEBUG_ASN1)){
                xer_fprint(stdout, &asn_DEF_NR_UE_NR_Capability, UE->UE_Capability_nr);
              }

              if((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)){
                LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Failed to decode nr UE capabilities (%zu bytes)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), dec_rval.consumed);
                ASN_STRUCT_FREE(asn_DEF_NR_UE_NR_Capability, UE->UE_Capability_nr);
                UE->UE_Capability_nr = 0;
              }

              UE->UE_Capability_size = ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]
                                           ->ue_CapabilityRAT_Container.size;
              if(eutra_index != -1){
                LOG_E(NR_RRC,"fatal: more than 1 eutra capability\n");
                exit(1);
              }
              eutra_index = i;
            }

            if (ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]->rat_Type
                == NR_RAT_Type_eutra_nr) {
              if (UE->UE_Capability_MRDC) {
                ASN_STRUCT_FREE(asn_DEF_NR_UE_MRDC_Capability, UE->UE_Capability_MRDC);
                UE->UE_Capability_MRDC = 0;
              }
              dec_rval = uper_decode(NULL,
                                     &asn_DEF_NR_UE_MRDC_Capability,
                                     (void **)&UE->UE_Capability_MRDC,
                                     ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]
                                         ->ue_CapabilityRAT_Container.buf,
                                     ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]
                                         ->ue_CapabilityRAT_Container.size,
                                     0,
                                     0);

              if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
                xer_fprint(stdout, &asn_DEF_NR_UE_MRDC_Capability, UE->UE_Capability_MRDC);
              }

              if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
                LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_FMT " Failed to decode nr UE capabilities (%zu bytes)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), dec_rval.consumed);
                ASN_STRUCT_FREE(asn_DEF_NR_UE_MRDC_Capability, UE->UE_Capability_MRDC);
                UE->UE_Capability_MRDC = 0;
              }
              UE->UE_MRDC_Capability_size =
                  ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]
                      ->ue_CapabilityRAT_Container.size;
            }

            if (ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList->list.array[i]->rat_Type
                == NR_RAT_Type_eutra) {
              //TODO
            }
          }

          if(eutra_index == -1)
            break;
        }
        if (get_softmodem_params()->sa) {
          rrc_gNB_send_NGAP_UE_CAPABILITIES_IND(ctxt_pP, ue_context_p, ul_dcch_msg);
        }

        if (!NODE_IS_CU(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
          if (UE->established_pdu_sessions_flag == 1) {
            rrc_gNB_generate_dedicatedRRCReconfiguration(ctxt_pP, ue_context_p, NULL);
          } else {
            rrc_gNB_generate_defaultRRCReconfiguration(ctxt_pP, ue_context_p);
          }
        } else {
          /*Generate a UE context setup request message towards the DU to provide the UE
           *capability info and get the updates on master cell group config from the DU*/
          MessageDef *message_p;
          message_p = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_UE_CONTEXT_SETUP_REQ);
          f1ap_ue_context_setup_t *req = &F1AP_UE_CONTEXT_SETUP_REQ(message_p);
          // UE_IDs will be extracted from F1AP layer
          req->gNB_CU_ue_id = 0;
          req->gNB_DU_ue_id = 0;
          req->rnti = UE->rnti;
          req->mcc = RC.nrrrc[ctxt_pP->module_id]->configuration.mcc[0];
          req->mnc = RC.nrrrc[ctxt_pP->module_id]->configuration.mnc[0];
          req->mnc_digit_length = RC.nrrrc[ctxt_pP->module_id]->configuration.mnc_digit_length[0];
          req->nr_cellid = RC.nrrrc[ctxt_pP->module_id]->nr_cellid;

          if (UE->established_pdu_sessions_flag == 1) {
            /*Instruction towards the DU for SRB2 configuration*/
            req->srbs_to_be_setup = malloc(1 * sizeof(f1ap_srb_to_be_setup_t));
            req->srbs_to_be_setup_length = 1;
            f1ap_srb_to_be_setup_t *SRBs = req->srbs_to_be_setup;
            SRBs[0].srb_id = 2;
            SRBs[0].lcid = 2;

            /*Instruction towards the DU for DRB configuration and tunnel creation*/
            req->drbs_to_be_setup = malloc(1 * sizeof(f1ap_drb_to_be_setup_t));
            req->drbs_to_be_setup_length = 1;
            f1ap_drb_to_be_setup_t *DRBs = req->drbs_to_be_setup;
            LOG_I(RRC, "Length of DRB list:%d \n", req->drbs_to_be_setup_length);
            DRBs[0].drb_id = 1;
            DRBs[0].rlc_mode = RLC_MODE_AM;
            DRBs[0].up_ul_tnl[0].tl_address = inet_addr(RC.nrrrc[ctxt_pP->module_id]->eth_params_s.my_addr);
            DRBs[0].up_ul_tnl[0].port = RC.nrrrc[ctxt_pP->module_id]->eth_params_s.my_portd;
            DRBs[0].up_ul_tnl_length = 1;
            DRBs[0].up_dl_tnl[0].tl_address = inet_addr(RC.nrrrc[ctxt_pP->module_id]->eth_params_s.remote_addr);
            DRBs[0].up_dl_tnl[0].port = RC.nrrrc[ctxt_pP->module_id]->eth_params_s.remote_portd;
            DRBs[0].up_dl_tnl_length = 1;
          }
          if (ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.present == NR_UECapabilityInformation__criticalExtensions_PR_ueCapabilityInformation) {
            struct NR_UE_CapabilityRAT_ContainerList *ue_CapabilityRAT_ContainerList =
                ul_dcch_msg->message.choice.c1->choice.ueCapabilityInformation->criticalExtensions.choice.ueCapabilityInformation->ue_CapabilityRAT_ContainerList;
            if (ue_CapabilityRAT_ContainerList != NULL) {
              LOG_I(NR_RRC, "ue_CapabilityRAT_ContainerList is present \n");
              req->cu_to_du_rrc_information = calloc(1, sizeof(cu_to_du_rrc_information_t));
              req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList = calloc(1, 4096);
              asn_enc_rval_t enc_rval =
                  uper_encode_to_buffer(&asn_DEF_NR_UE_CapabilityRAT_ContainerList, NULL, ue_CapabilityRAT_ContainerList, req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList, 4096);
              AssertFatal(enc_rval.encoded > 0, "ASN1 ue_CapabilityRAT_ContainerList encoding failed (%s, %jd)!\n", enc_rval.failed_type->name, enc_rval.encoded);
              req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList_length = (enc_rval.encoded + 7) >> 3;
            } else {
              LOG_I(NR_RRC, "ue_CapabilityRAT_ContainerList is not present \n");
            }
          }
          itti_send_msg_to_task(TASK_CU_F1, ctxt_pP->module_id, message_p);
        }

        break;

      case NR_UL_DCCH_MessageType__c1_PR_rrcReestablishmentComplete:
        LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)Rx_sdu, sdu_sizeP, "[MSG] NR_RRC Connection Reestablishment Complete\n");
        LOG_I(NR_RRC,
              PROTOCOL_RRC_CTXT_UE_FMT
              " RLC RB %02d --- RLC_DATA_IND %d bytes "
              "(rrcConnectionReestablishmentComplete) ---> RRC_gNB\n",
              PROTOCOL_RRC_CTXT_UE_ARGS(ctxt_pP),
              DCCH,
              sdu_sizeP);
        {
          rnti_t reestablish_rnti = 0;

          // select C-RNTI from map
          for (i = 0; i < MAX_MOBILES_PER_ENB; i++) {
            if (reestablish_rnti_map[i][0] == ctxt_pP->rntiMaybeUEid) {
              reestablish_rnti = reestablish_rnti_map[i][1];
              ue_context_p = rrc_gNB_get_ue_context(RC.nrrrc[ctxt_pP->module_id], reestablish_rnti);
              // clear currentC-RNTI from map
              reestablish_rnti_map[i][0] = 0;
              reestablish_rnti_map[i][1] = 0;
              LOG_D(NR_RRC, "reestablish_rnti_map[%d] [0] %x, [1] %x\n", i, reestablish_rnti_map[i][0], reestablish_rnti_map[i][1]);
              break;
            }
          }

          if (!ue_context_p) {
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " NR_RRCConnectionReestablishmentComplete without UE context, falt\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP));
            break;
          }

#if(0)
          /* TODO : It may be needed if gNB goes into full stack working. */
          // clear
          int UE_id = find_nr_UE_id(ctxt_pP->module_id, ctxt_pP->rntiMaybeUEid);

          if (UE_id == -1) {
            LOG_E(NR_RRC, PROTOCOL_RRC_CTXT_UE_FMT " NR_RRCConnectionReestablishmentComplete without UE_id(MAC) rnti %lx, fault\n", PROTOCOL_RRC_CTXT_UE_ARGS(ctxt_pP), ctxt_pP->rntiMaybeUEid);
            break;
          }

          RC.nrmac[ctxt_pP->module_id]->UE_info.UE_sched_ctrl[UE_id].ue_reestablishment_reject_timer = 0;
#endif
          UE->reestablishment_xid = -1;

          if (ul_dcch_msg->message.choice.c1->choice.rrcReestablishmentComplete->criticalExtensions.present == NR_RRCReestablishmentComplete__criticalExtensions_PR_rrcReestablishmentComplete) {
            rrc_gNB_process_RRCConnectionReestablishmentComplete(ctxt_pP, reestablish_rnti, ue_context_p, ul_dcch_msg->message.choice.c1->choice.rrcReestablishmentComplete->rrc_TransactionIdentifier);
          }

          // UE->ue_release_timer = 0;
          UE->ue_reestablishment_timer = 1;
          // remove UE after 100 frames after LTE_RRCConnectionReestablishmentRelease is triggered
          UE->ue_reestablishment_timer_thres = 1000;
        }
        break;
      default:
        break;
    }
    }
    return 0;
}

void rrc_gNB_process_f1_setup_req(f1ap_setup_req_t *f1_setup_req)
{
  LOG_I(NR_RRC, "Received F1 Setup Request from gNB_DU %llu (%s)\n", (unsigned long long int)f1_setup_req->gNB_DU_id, f1_setup_req->gNB_DU_name);
  int cu_cell_ind = 0;
  MessageDef *msg_p = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_SETUP_RESP);
  F1AP_SETUP_RESP(msg_p).num_cells_to_activate = 0;
  MessageDef *msg_p2 = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_GNB_CU_CONFIGURATION_UPDATE);

  for (int i = 0; i < f1_setup_req->num_cells_available; i++) {
    for (int j = 0; j < RC.nb_nr_inst; j++) {
      gNB_RRC_INST *rrc = RC.nrrrc[j];

      if (rrc->configuration.mcc[0] == f1_setup_req->cell[i].mcc && rrc->configuration.mnc[0] == f1_setup_req->cell[i].mnc && rrc->nr_cellid == f1_setup_req->cell[i].nr_cellid) {
        // fixme: multi instance is not consistent here
        F1AP_SETUP_RESP(msg_p).gNB_CU_name = rrc->node_name;
        // check that CU rrc instance corresponds to mcc/mnc/cgi (normally cgi should be enough, but just in case)
        rrc->carrier.MIB = malloc(f1_setup_req->mib_length[i]);
        rrc->carrier.sizeof_MIB = f1_setup_req->mib_length[i];
        LOG_W(NR_RRC, "instance %d mib length %d\n", i, f1_setup_req->mib_length[i]);
        LOG_W(NR_RRC, "instance %d sib1 length %d\n", i, f1_setup_req->sib1_length[i]);
        memcpy((void *)rrc->carrier.MIB, f1_setup_req->mib[i], f1_setup_req->mib_length[i]);
        asn_dec_rval_t dec_rval = uper_decode_complete(NULL, &asn_DEF_NR_BCCH_BCH_Message, (void **)&rrc->carrier.mib_DU, f1_setup_req->mib[i], f1_setup_req->mib_length[i]);
        AssertFatal(dec_rval.code == RC_OK, "[gNB_CU %" PRIu8 "] Failed to decode NR_BCCH_BCH_MESSAGE (%zu bits)\n", j, dec_rval.consumed);
        NR_BCCH_BCH_Message_t *mib = &rrc->carrier.mib;
        NR_BCCH_BCH_Message_t *mib_DU = rrc->carrier.mib_DU;
        mib->message.present = NR_BCCH_BCH_MessageType_PR_mib;
        mib->message.choice.mib = CALLOC(1, sizeof(struct NR_MIB));
        memset(mib->message.choice.mib, 0, sizeof(struct NR_MIB));
        memcpy(mib->message.choice.mib, mib_DU->message.choice.mib, sizeof(struct NR_MIB));

        dec_rval = uper_decode_complete(NULL,
                                        &asn_DEF_NR_SIB1, //&asn_DEF_NR_BCCH_DL_SCH_Message,
                                        (void **)&rrc->carrier.siblock1_DU,
                                        f1_setup_req->sib1[i],
                                        f1_setup_req->sib1_length[i]);
        AssertFatal(dec_rval.code == RC_OK, "[gNB_DU %" PRIu8 "] Failed to decode NR_BCCH_DLSCH_MESSAGE (%zu bits)\n", j, dec_rval.consumed);

        // Parse message and extract SystemInformationBlockType1 field
        rrc->carrier.sib1 = rrc->carrier.siblock1_DU;
        if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
          LOG_I(NR_RRC, "Printing received SIB1 container inside F1 setup request message:\n");
          xer_fprint(stdout, &asn_DEF_NR_SIB1, (void *)rrc->carrier.sib1);
        }

        rrc->carrier.physCellId = f1_setup_req->cell[i].nr_pci;

        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).gNB_CU_name = rrc->node_name;
        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].mcc = rrc->configuration.mcc[0];
        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].mnc = rrc->configuration.mnc[0];
        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].mnc_digit_length = rrc->configuration.mnc_digit_length[0];
        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].nr_cellid = rrc->nr_cellid;
        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].nrpci = f1_setup_req->cell[i].nr_pci;
        int num_SI = 0;

        if (rrc->carrier.SIB23) {
          F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].SI_container[2] = rrc->carrier.SIB23;
          F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].SI_container_length[2] = rrc->carrier.sizeof_SIB23;
          num_SI++;
        }

        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).cells_to_activate[cu_cell_ind].num_SI = num_SI;
        cu_cell_ind++;
        F1AP_GNB_CU_CONFIGURATION_UPDATE(msg_p2).num_cells_to_activate = cu_cell_ind;
        // send
        break;
      } else { // setup_req mcc/mnc match rrc internal list element
        LOG_W(NR_RRC,
              "[Inst %d] No matching MCC/MNC: rrc->mcc/f1_setup_req->mcc %d/%d rrc->mnc/f1_setup_req->mnc %d/%d rrc->nr_cellid/f1_setup_req->nr_cellid %ld/%ld \n",
              j,
              rrc->configuration.mcc[0],
              f1_setup_req->cell[i].mcc,
              rrc->configuration.mnc[0],
              f1_setup_req->cell[i].mnc,
              rrc->nr_cellid,
              f1_setup_req->cell[i].nr_cellid);
      }
    } // for (int j=0;j<RC.nb_inst;j++)

    if (cu_cell_ind == 0) {
      AssertFatal(1 == 0, "No cell found\n");
    } else {
      // send ITTI message to F1AP-CU task
      itti_send_msg_to_task(TASK_CU_F1, 0, msg_p);

      itti_send_msg_to_task(TASK_CU_F1, 0, msg_p2);
    }

    // handle other failure cases
  } // for (int i=0;i<f1_setup_req->num_cells_available;i++)
}

void rrc_gNB_process_initial_ul_rrc_message(const f1ap_initial_ul_rrc_message_t *ul_rrc)
{
  // first get RRC instance (note, no the ITTI instance)
  module_id_t i = 0;
  for (i = 0; i < RC.nb_nr_inst; i++) {
    gNB_RRC_INST *rrc = RC.nrrrc[i];
    if (rrc->nr_cellid == ul_rrc->nr_cellid)
      break;
  }
  // AssertFatal(i != RC.nb_nr_inst, "Cell_id not found\n");
  //  TODO REMOVE_DU_RRC in monolithic mode, the MAC does not have the
  //  nr_cellid. Thus, the above check would fail. For the time being, just put
  //  a warning, as we handle one DU only anyway
  if (i == RC.nb_nr_inst) {
    i = 0;
    LOG_W(RRC, "initial UL RRC message nr_cellid %ld does not match RRC's %ld\n", ul_rrc->nr_cellid, RC.nrrrc[0]->nr_cellid);
  }
  protocol_ctxt_t ctxt = {0};
  PROTOCOL_CTXT_SET_BY_INSTANCE(&ctxt, i, GNB_FLAG_YES, ul_rrc->crnti, 0, 0);

  nr_rrc_gNB_decode_ccch(&ctxt, ul_rrc->rrc_container, ul_rrc->rrc_container_length, ul_rrc->du2cu_rrc_container, ul_rrc->du2cu_rrc_container_length);

  if (ul_rrc->rrc_container)
    free(ul_rrc->rrc_container);
  if (ul_rrc->du2cu_rrc_container)
    free(ul_rrc->du2cu_rrc_container);
}

void rrc_gNB_process_release_request(const module_id_t gnb_mod_idP, x2ap_ENDC_sgnb_release_request_t *m)
{
  gNB_RRC_INST *rrc = RC.nrrrc[gnb_mod_idP];
  rrc_remove_nsa_user(rrc, m->rnti);
}

void rrc_gNB_process_dc_overall_timeout(const module_id_t gnb_mod_idP, x2ap_ENDC_dc_overall_timeout_t *m)
{
  gNB_RRC_INST *rrc = RC.nrrrc[gnb_mod_idP];
  rrc_remove_nsa_user(rrc, m->rnti);
}

static int rrc_process_DU_DL(MessageDef *msg_p, instance_t instance)
{
  NRDuDlReq_t *req = &NRDuDlReq(msg_p);
  protocol_ctxt_t ctxt = {.rntiMaybeUEid = req->rnti, .module_id = instance, .instance = instance, .enb_flag = 1, .eNB_index = instance};
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt.module_id];
  struct rrc_gNB_ue_context_s *ue_context_p = rrc_gNB_get_ue_context(rrc, ctxt.rntiMaybeUEid);
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;

  if (req->srb_id == 0) {
    AssertFatal(0 == 1, "should pass through dl_rrc_message()\n");
  } else if (req->srb_id == 1) {
    NR_DL_DCCH_Message_t *dl_dcch_msg = NULL;
    asn_dec_rval_t dec_rval;
    dec_rval = uper_decode(NULL,
                           &asn_DEF_NR_DL_DCCH_Message,
                           (void **)&dl_dcch_msg,
                           &req->buf->data[2], // buf[0] includes the pdcp header
                           req->buf->size - 6,
                           0,
                           0);

    if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0))
      LOG_E(F1AP, " Failed to decode DL-DCCH (%zu bytes)\n", dec_rval.consumed);
    else
      LOG_D(F1AP, "Received message: present %d and c1 present %d\n", dl_dcch_msg->message.present, dl_dcch_msg->message.choice.c1->present);

    if (dl_dcch_msg->message.present == NR_DL_DCCH_MessageType_PR_c1) {
      switch (dl_dcch_msg->message.choice.c1->present) {
        case NR_DL_DCCH_MessageType__c1_PR_NOTHING:
          LOG_I(F1AP, "Received PR_NOTHING on DL-DCCH-Message\n");
          return 0;

        case NR_DL_DCCH_MessageType__c1_PR_rrcReconfiguration:
          // handle RRCReconfiguration
          LOG_I(F1AP, "Logical Channel DL-DCCH (SRB1), Received RRCReconfiguration RNTI %x\n", req->rnti);
          NR_RRCReconfiguration_t *rrcReconfiguration = dl_dcch_msg->message.choice.c1->choice.rrcReconfiguration;

          if (rrcReconfiguration->criticalExtensions.present == NR_RRCReconfiguration__criticalExtensions_PR_rrcReconfiguration) {
            NR_RRCReconfiguration_IEs_t *rrcReconfiguration_ies = rrcReconfiguration->criticalExtensions.choice.rrcReconfiguration;

            if (rrcReconfiguration_ies->measConfig != NULL) {
              LOG_I(F1AP, "Measurement Configuration is present\n");
            }

            if (rrcReconfiguration_ies->radioBearerConfig) {
              LOG_I(F1AP, "Radio Resource Configuration is present\n");
              long drb_id;
              int i;
              NR_DRB_ToAddModList_t *DRB_configList = rrcReconfiguration_ies->radioBearerConfig->drb_ToAddModList;
              NR_SRB_ToAddModList_t *SRB_configList = rrcReconfiguration_ies->radioBearerConfig->srb_ToAddModList;

              // NR_DRB_ToReleaseList_t *DRB_ReleaseList = rrcReconfiguration_ies->radioBearerConfig->drb_ToReleaseList;

              // rrc_rlc_config_asn1_req

              if (SRB_configList != NULL) {
                for (i = 0; (i < SRB_configList->list.count) && (i < 3); i++) {
                  long tmp = SRB_configList->list.array[i]->srb_Identity;
                  if (tmp < 1 || tmp >= MAX_SRBs)
                    LOG_E(NR_RRC, "[gNB %d] Frame      %d CC %d : invalid SRB identity %ld\n", ctxt.module_id, ctxt.frame, UE->primaryCC_id, tmp);
                  else {
                    UE->Srb[tmp].Active = 1;
                    UE->Srb[tmp].Srb_info.Srb_id = tmp;
                  }
                }
              }

              if (DRB_configList != NULL) {
                for (i = 0; i < DRB_configList->list.count; i++) { // num max DRB (11-3-8)
                  if (DRB_configList->list.array[i]) {
                    drb_id = (int)DRB_configList->list.array[i]->drb_Identity;
                    LOG_I(F1AP,
                          "[DU %d] Logical Channel UL-DCCH, Received RRCConnectionReconfiguration for UE rnti %lx, reconfiguring DRB %d\n",
                          ctxt.module_id,
                          ctxt.rntiMaybeUEid,
                          (int)DRB_configList->list.array[i]->drb_Identity);

                  } else { // remove LCHAN from MAC/PHY
                    AssertFatal(1 == 0, "Can't handle this yet in DU\n");
                  }
                }
              }
            }
          }

          break;

        case NR_DL_DCCH_MessageType__c1_PR_rrcResume:
          LOG_I(F1AP, "Received rrcResume\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_rrcRelease:
          LOG_I(F1AP, "Received rrcRelease\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_rrcReestablishment:
          LOG_I(F1AP, "Received rrcReestablishment\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_securityModeCommand:
          LOG_I(F1AP, "Received securityModeCommand\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_dlInformationTransfer:
          LOG_I(F1AP, "Received dlInformationTransfer\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_ueCapabilityEnquiry:
          LOG_I(F1AP, "Received ueCapabilityEnquiry\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_counterCheck:
          LOG_I(F1AP, "Received counterCheck\n");
          break;

        case NR_DL_DCCH_MessageType__c1_PR_mobilityFromNRCommand:
        case NR_DL_DCCH_MessageType__c1_PR_dlDedicatedMessageSegment_r16:
        case NR_DL_DCCH_MessageType__c1_PR_ueInformationRequest_r16:
        case NR_DL_DCCH_MessageType__c1_PR_dlInformationTransferMRDC_r16:
        case NR_DL_DCCH_MessageType__c1_PR_loggedMeasurementConfiguration_r16:
        case NR_DL_DCCH_MessageType__c1_PR_spare3:
        case NR_DL_DCCH_MessageType__c1_PR_spare2:
        case NR_DL_DCCH_MessageType__c1_PR_spare1:
          break;
      }
    }
  } else if (req->srb_id == 2) {
    // TODO
    // abort();
  }

  LOG_I(F1AP, "Received DL RRC Transfer on srb_id %ld\n", req->srb_id);
  //   rlc_op_status_t    rlc_status;

  // LOG_I(F1AP, "PRRCContainer size %lu:", ie->value.choice.RRCContainer.size);
  // for (int i = 0; i < ie->value.choice.RRCContainer.size; i++)
  //   printf("%02x ", ie->value.choice.RRCContainer.buf[i]);

  // printf (", PDCP PDU size %d:", rrc_dl_sdu_len);
  // for (int i=0;i<rrc_dl_sdu_len;i++) printf("%2x ",pdcp_pdu_p->data[i]);
  // printf("\n");

  du_rlc_data_req(&ctxt, 1, 0, req->srb_id, 1, 0, req->buf->size, req->buf);
  //   rlc_status = rlc_data_req(&ctxt
  //                             , 1
  //                             , MBMS_FLAG_NO
  //                             , srb_id
  //                             , 0
  //                             , 0
  //                             , rrc_dl_sdu_len
  //                             , pdcp_pdu_p
  //                             ,NULL
  //                             ,NULL
  //                             );
  //   switch (rlc_status) {
  //     case RLC_OP_STATUS_OK:
  //       //LOG_I(F1AP, "Data sending request over RLC succeeded!\n");
  //       ret=true;
  //       break;
  //     case RLC_OP_STATUS_BAD_PARAMETER:
  //       LOG_W(F1AP, "Data sending request over RLC failed with 'Bad Parameter' reason!\n");
  //       ret= false;
  //       break;
  //     case RLC_OP_STATUS_INTERNAL_ERROR:
  //       LOG_W(F1AP, "Data sending request over RLC failed with 'Internal Error' reason!\n");
  //       ret= false;
  //       break;
  //     case RLC_OP_STATUS_OUT_OF_RESSOURCES:
  //       LOG_W(F1AP, "Data sending request over RLC failed with 'Out of Resources' reason!\n");
  //       ret= false;
  //       break;
  //     default:
  //       LOG_W(F1AP, "RLC returned an unknown status code after PDCP placed the order to send some data (Status Code:%d)\n", rlc_status);
  //       ret= false;
  //       break;
  //   } // switch case
  //   return ret;
  return 0;
}

static void rrc_DU_process_ue_context_setup_request(MessageDef *msg_p, instance_t instance)
{
  f1ap_ue_context_setup_t *req = &F1AP_UE_CONTEXT_SETUP_REQ(msg_p);
  protocol_ctxt_t ctxt = {.rntiMaybeUEid = req->rnti, .module_id = instance, .instance = instance, .enb_flag = 1, .eNB_index = instance};
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt.module_id];
  gNB_MAC_INST *mac = RC.nrmac[ctxt.module_id];
  struct rrc_gNB_ue_context_s *ue_context_p = rrc_gNB_get_ue_context(rrc, ctxt.rntiMaybeUEid);
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;
  MessageDef *message_p;
  message_p = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_UE_CONTEXT_SETUP_RESP);
  f1ap_ue_context_setup_t *resp = &F1AP_UE_CONTEXT_SETUP_RESP(message_p);
  uint32_t incoming_teid = 0;

  if (req->cu_to_du_rrc_information != NULL) {
    if (req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList != NULL) {
      LOG_I(NR_RRC, "Length of ue_CapabilityRAT_ContainerList is: %d \n", (int)req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList_length);
      struct NR_UE_CapabilityRAT_ContainerList *ue_CapabilityRAT_ContainerList = NULL;
      asn_dec_rval_t dec_rval = uper_decode_complete(NULL,
                                                     &asn_DEF_NR_UE_CapabilityRAT_ContainerList,
                                                     (void **)&ue_CapabilityRAT_ContainerList,
                                                     (uint8_t *)req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList,
                                                     (int)req->cu_to_du_rrc_information->uE_CapabilityRAT_ContainerList_length);

      if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
        AssertFatal(1 == 0, "UE Capability RAT ContainerList decode error\n");
        // free the memory
        SEQUENCE_free(&asn_DEF_NR_UE_CapabilityRAT_ContainerList, ue_CapabilityRAT_ContainerList, 1);
        return;
      }
      // To fill ue_context.UE_Capability_MRDC, ue_context.UE_Capability_nr ...
      int NR_index = -1;
      for (int i = 0; i < ue_CapabilityRAT_ContainerList->list.count; i++) {
        if (ue_CapabilityRAT_ContainerList->list.array[i]->rat_Type == NR_RAT_Type_nr) {
          LOG_I(NR_RRC, "DU received NR_RAT_Type_nr UE capabilities Info through the UE Context Setup Request from the CU \n");
          if (UE->UE_Capability_nr) {
            ASN_STRUCT_FREE(asn_DEF_NR_UE_NR_Capability, UE->UE_Capability_nr);
            UE->UE_Capability_nr = 0;
          }

          dec_rval = uper_decode(NULL,
                                 &asn_DEF_NR_UE_NR_Capability,
                                 (void **)&UE->UE_Capability_nr,
                                 ue_CapabilityRAT_ContainerList->list.array[i]->ue_CapabilityRAT_Container.buf,
                                 ue_CapabilityRAT_ContainerList->list.array[i]->ue_CapabilityRAT_Container.size,
                                 0,
                                 0);
          if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
            xer_fprint(stdout, &asn_DEF_NR_UE_NR_Capability, UE->UE_Capability_nr);
          }

          if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Failed to decode nr UE capabilities (%zu bytes)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(&ctxt), dec_rval.consumed);
            ASN_STRUCT_FREE(asn_DEF_NR_UE_NR_Capability, UE->UE_Capability_nr);
            UE->UE_Capability_nr = 0;
          }

          UE->UE_Capability_size = ue_CapabilityRAT_ContainerList->list.array[i]->ue_CapabilityRAT_Container.size;
          if (NR_index != -1) {
            LOG_E(NR_RRC, "fatal: more than 1 eutra capability\n");
            exit(1);
          }
          NR_index = i;
        }

        if (ue_CapabilityRAT_ContainerList->list.array[i]->rat_Type == NR_RAT_Type_eutra_nr) {
          LOG_I(NR_RRC, "DU received NR_RAT_Type_eutra_nr UE capabilities Info through the UE Context Setup Request from the CU \n");
          if (UE->UE_Capability_MRDC) {
            ASN_STRUCT_FREE(asn_DEF_NR_UE_MRDC_Capability, UE->UE_Capability_MRDC);
            UE->UE_Capability_MRDC = 0;
          }
          dec_rval = uper_decode(NULL,
                                 &asn_DEF_NR_UE_MRDC_Capability,
                                 (void **)&UE->UE_Capability_MRDC,
                                 ue_CapabilityRAT_ContainerList->list.array[i]->ue_CapabilityRAT_Container.buf,
                                 ue_CapabilityRAT_ContainerList->list.array[i]->ue_CapabilityRAT_Container.size,
                                 0,
                                 0);
          if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
            xer_fprint(stdout, &asn_DEF_NR_UE_MRDC_Capability, UE->UE_Capability_MRDC);
          }

          if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
            LOG_E(NR_RRC, PROTOCOL_NR_RRC_CTXT_FMT " Failed to decode nr UE capabilities (%zu bytes)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(&ctxt), dec_rval.consumed);
            ASN_STRUCT_FREE(asn_DEF_NR_UE_MRDC_Capability, UE->UE_Capability_MRDC);
            UE->UE_Capability_MRDC = 0;
          }
          UE->UE_MRDC_Capability_size = ue_CapabilityRAT_ContainerList->list.array[i]->ue_CapabilityRAT_Container.size;
        }

        if (ue_CapabilityRAT_ContainerList->list.array[i]->rat_Type == NR_RAT_Type_eutra) {
          // TODO
        }
      }
    }
  }

  /* Configure SRB2 */
  NR_SRB_ToAddMod_t *SRB2_config = NULL;
  NR_SRB_ToAddModList_t SRB_configList = {0};
  uint8_t SRBs_before_new_addition = 0;

  if (req->srbs_to_be_setup_length > 0)
    for (int i = 0; i < req->srbs_to_be_setup_length; i++) {
      long tmp = req->srbs_to_be_setup[i].srb_id;
      if (tmp < 1 || tmp >= MAX_SRBs)
        LOG_E(NR_RRC, "[gNB %d] Frame      %d CC %d : invalid SRB identity %ld\n", ctxt.module_id, ctxt.frame, UE->primaryCC_id, tmp);
      else {
        UE->Srb[tmp].Active = 1;
        UE->Srb[tmp].Srb_info.Srb_id = tmp;
      }
    }
  fill_SRB_configList(ue_context_p, &SRB_configList);

  /* Configure DRB */
  NR_DRB_ToAddMod_t *DRB_config = NULL;
  NR_DRB_ToAddModList_t DRB_configList = {0};
  // DRBFIXME: inconsistent with following lines
  fill_DRB_configList(&ctxt, ue_context_p, &DRB_configList, setE1);
  uint8_t drb_id_to_setup_start = 0;
  uint8_t nb_drb_to_setup = 0;
  long drb_priority[NGAP_MAX_DRBS_PER_UE];
  nb_drb_to_setup = req->drbs_to_be_setup_length;
  for (int i = 0; i < nb_drb_to_setup; i++) {
    DRB_config = CALLOC(1, sizeof(*DRB_config));
    DRB_config->drb_Identity = req->drbs_to_be_setup[i].drb_id;
    if (drb_id_to_setup_start == 0)
      drb_id_to_setup_start = DRB_config->drb_Identity;
    asn1cSeqAdd(&DRB_configList.list, DRB_config);
    f1ap_drb_to_be_setup_t drb_p = req->drbs_to_be_setup[i];
    transport_layer_addr_t addr;
    memcpy(addr.buffer, &drb_p.up_ul_tnl[0].tl_address, sizeof(drb_p.up_ul_tnl[0].tl_address));
    addr.length = sizeof(drb_p.up_ul_tnl[0].tl_address) * 8;
    extern instance_t DUuniqInstance;
    incoming_teid = newGtpuCreateTunnel(DUuniqInstance,
                                        req->rnti,
                                        drb_p.drb_id,
                                        drb_p.drb_id,
                                        drb_p.up_ul_tnl[0].teid,
                                        -1, // no qfi
                                        addr,
                                        drb_p.up_ul_tnl[0].port,
                                        DURecvCb,
                                        NULL);
    /* TODO: hardcoded to 13 for the time being, to be changed? */
    drb_priority[DRB_config->drb_Identity - 1] = 13;
  }

  NR_CellGroupConfig_t *cellGroupConfig = calloc(1, sizeof(NR_CellGroupConfig_t));
  if (req->srbs_to_be_setup_length > 0 || req->drbs_to_be_setup_length > 0)
    // FIXME: fill_mastercellGroupConfig() won't fill the right priorities or
    // bearer IDs for the DRBs
    fill_mastercellGroupConfig(cellGroupConfig, UE->masterCellGroup, rrc->um_on_default_drb, SRB2_config ? 1 : 0, drb_id_to_setup_start, nb_drb_to_setup, drb_priority);

  apply_macrlc_config(rrc, ue_context_p, &ctxt);

  if (req->rrc_container_length > 0) {
    mem_block_t *pdcp_pdu_p = get_free_mem_block(req->rrc_container_length, __func__);
    memcpy(&pdcp_pdu_p->data[0], req->rrc_container, req->rrc_container_length);
    du_rlc_data_req(&ctxt, 1, 0x00, 1, 1, 0, req->rrc_container_length, pdcp_pdu_p);
    LOG_I(F1AP, "Printing RRC Container of UE context setup request: \n");
    for (int j = 0; j < req->rrc_container_length; j++) {
      printf("%02x ", pdcp_pdu_p->data[j]);
    }
    printf("\n");
  }

  /* Fill the UE context setup response ITTI message to send to F1AP */
  resp->gNB_CU_ue_id = req->gNB_CU_ue_id;
  resp->rnti = ctxt.rntiMaybeUEid;
  if (DRB_configList.list.count > 0) {
    resp->drbs_to_be_setup = calloc(1, DRB_configList.list.count * sizeof(f1ap_drb_to_be_setup_t));
    resp->drbs_to_be_setup_length = DRB_configList.list.count;
    for (int i = 0; i < DRB_configList.list.count; i++) {
      resp->drbs_to_be_setup[i].drb_id = DRB_configList.list.array[i]->drb_Identity;
      resp->drbs_to_be_setup[i].rlc_mode = RLC_MODE_AM;
      resp->drbs_to_be_setup[i].up_dl_tnl[0].teid = incoming_teid;
      resp->drbs_to_be_setup[i].up_dl_tnl[0].tl_address = inet_addr(mac->eth_params_n.my_addr);
      resp->drbs_to_be_setup[i].up_dl_tnl_length = 1;
    }
  } else {
    LOG_W(NR_RRC, "No DRB added upon reception of F1 UE context setup request with a DRB to setup list\n");
  }
  if (SRB_configList.list.count > 0 && SRBs_before_new_addition < SRB_configList.list.count) {
    resp->srbs_to_be_setup = calloc(1, req->srbs_to_be_setup_length * sizeof(f1ap_srb_to_be_setup_t));
    resp->srbs_to_be_setup_length = req->srbs_to_be_setup_length;
    for (int i = SRBs_before_new_addition; i < SRB_configList.list.count; i++) {
      resp->srbs_to_be_setup[i - SRBs_before_new_addition].srb_id = SRB_configList.list.array[i]->srb_Identity;
    }
  } else {
    LOG_W(NR_RRC, "No SRB added upon reception of F1 UE Context setup request at the DU\n");
  }
  /* fixme:
   * Here we should be encoding the updates on cellgroupconfig based on the content of UE capabilities
   */
  resp->du_to_cu_rrc_information = calloc(1, sizeof(du_to_cu_rrc_information_t));
  resp->du_to_cu_rrc_information->cellGroupConfig = calloc(1, 1024);
  asn_enc_rval_t enc_rval = uper_encode_to_buffer(&asn_DEF_NR_CellGroupConfig,
                                                  NULL,
                                                  UE->masterCellGroup, //(void *)cellGroupConfig,
                                                  resp->du_to_cu_rrc_information->cellGroupConfig,
                                                  1024);
  if (enc_rval.encoded == -1) {
    LOG_E(F1AP, "Could not encode ue_context.masterCellGroup, failed element %s\n", enc_rval.failed_type->name);
    exit(-1);
  }
  resp->du_to_cu_rrc_information->cellGroupConfig_length = (enc_rval.encoded + 7) >> 3;
  free(cellGroupConfig);
  itti_send_msg_to_task(TASK_DU_F1, ctxt.module_id, message_p);
}

static void rrc_DU_process_ue_context_modification_request(MessageDef *msg_p, instance_t instance)
{
  f1ap_ue_context_setup_t *req = &F1AP_UE_CONTEXT_MODIFICATION_REQ(msg_p);
  protocol_ctxt_t ctxt = {.rntiMaybeUEid = req->rnti, .module_id = instance, .instance = instance, .enb_flag = 1, .eNB_index = instance};
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt.module_id];
  gNB_MAC_INST *mac = RC.nrmac[ctxt.module_id];
  struct rrc_gNB_ue_context_s *ue_context_p = rrc_gNB_get_ue_context(rrc, ctxt.rntiMaybeUEid);
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;
  MessageDef *message_p;
  message_p = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_UE_CONTEXT_MODIFICATION_RESP);
  f1ap_ue_context_setup_t *resp = &F1AP_UE_CONTEXT_MODIFICATION_RESP(message_p);
  uint32_t incoming_teid = 0;
  NR_CellGroupConfig_t *cellGroupConfig = NULL;

  uint8_t SRBs_before_new_addition = 0;

  if (req->srbs_to_be_setup_length > 0)
    for (int i = 0; i < req->srbs_to_be_setup_length; i++) {
      long tmp = req->srbs_to_be_setup[i].srb_id;
      if (tmp < 1 || tmp >= MAX_SRBs)
        LOG_E(NR_RRC, "[gNB %d] Frame      %d CC %d : invalid SRB identity %ld\n", ctxt.module_id, ctxt.frame, UE->primaryCC_id, tmp);
      else {
        UE->Srb[tmp].Active = 1;
        UE->Srb[tmp].Srb_info.Srb_id = tmp;
      }
    }
  NR_SRB_ToAddModList_t SRB_configList = {0};
  fill_SRB_configList(ue_context_p, &SRB_configList);

  /* Configure DRB */
  NR_DRB_ToAddMod_t *DRB_config = NULL;
  NR_DRB_ToAddModList_t DRB_configList = {0};
  fill_DRB_configList(&ctxt, ue_context_p, &DRB_configList, setE1);
  int drb_id_to_setup_start = 0;
  long drb_priority[NGAP_MAX_DRBS_PER_UE];
  if (req->drbs_to_be_setup_length > 0) {
    for (int i = 0; i < req->drbs_to_be_setup_length; i++) {
      DRB_config = CALLOC(1, sizeof(*DRB_config));
      DRB_config->drb_Identity = req->drbs_to_be_setup[i].drb_id;
      if (drb_id_to_setup_start == 0)
        drb_id_to_setup_start = DRB_config->drb_Identity;
      asn1cSeqAdd(&DRB_configList.list, DRB_config);
      f1ap_drb_to_be_setup_t drb_p = req->drbs_to_be_setup[i];
      transport_layer_addr_t addr;
      memcpy(addr.buffer, &drb_p.up_ul_tnl[0].tl_address, sizeof(drb_p.up_ul_tnl[0].tl_address));
      addr.length = sizeof(drb_p.up_ul_tnl[0].tl_address) * 8;
      extern instance_t DUuniqInstance;
      if (!drb_id_to_setup_start)
        drb_id_to_setup_start = drb_p.drb_id;
      incoming_teid = newGtpuCreateTunnel(DUuniqInstance,
                                          req->rnti,
                                          drb_p.drb_id,
                                          drb_p.drb_id,
                                          drb_p.up_ul_tnl[0].teid,
                                          -1, // no qfi
                                          addr,
                                          drb_p.up_ul_tnl[0].port,
                                          DURecvCb,
                                          NULL);
      /* TODO: hardcoded to 13 for the time being, to be changed? */
      drb_priority[DRB_config->drb_Identity - 1] = 13;
    }
  }

  if (req->srbs_to_be_setup_length > 0 || req->drbs_to_be_setup_length > 0) {
    cellGroupConfig = calloc(1, sizeof(NR_CellGroupConfig_t));
    fill_mastercellGroupConfig(cellGroupConfig, UE->masterCellGroup, rrc->um_on_default_drb, drb_id_to_setup_start < 2 ? 1 : 0, drb_id_to_setup_start, req->drbs_to_be_setup_length, drb_priority);
    apply_macrlc_config(rrc, ue_context_p, &ctxt);
  }
  if (req->ReconfigComplOutcome == RRCreconf_failure) {
    LOG_W(NR_RRC, "CU reporting RRC Reconfiguration failure \n");
  } else if (req->ReconfigComplOutcome == RRCreconf_success) {
    LOG_I(NR_RRC, "CU reporting RRC Reconfiguration success \n");
    LOG_I(NR_RRC, "Send first DDD buffer status reporting towards the CU through an ITTI message to gtp-u \n");
    uint8_t drb_id = DRB_configList.list.array[0]->drb_Identity;
    rnti_t rnti = UE->rnti;
    int rlc_tx_buffer_space = nr_rlc_get_available_tx_space(rnti, drb_id + 3);
    LOG_I(NR_RRC, "Reported in DDD drb_id:%d, rnti:%d\n", drb_id, rnti);
    MessageDef *msg = itti_alloc_new_message_sized(TASK_RRC_GNB, 0, GTPV1U_DU_BUFFER_REPORT_REQ, sizeof(gtpv1u_tunnel_data_req_t));
    gtpv1u_DU_buffer_report_req_t *req = &GTPV1U_DU_BUFFER_REPORT_REQ(msg);
    req->pdusession_id = drb_id;
    req->ue_id = rnti;
    req->buffer_availability = rlc_tx_buffer_space; // 10000000; //Hardcoding to be removed and read the actual RLC buffer availability instead
    extern instance_t DUuniqInstance;
    itti_send_msg_to_task(TASK_GTPV1_U, DUuniqInstance, msg);
  }

  /* Fill the UE context setup response ITTI message to send to F1AP */
  resp->gNB_CU_ue_id = req->gNB_CU_ue_id;
  resp->rnti = ctxt.rntiMaybeUEid;
  if (DRB_configList.list.count > 0) {
    resp->drbs_to_be_setup = calloc(1, DRB_configList.list.count * sizeof(f1ap_drb_to_be_setup_t));
    resp->drbs_to_be_setup_length = DRB_configList.list.count;
    for (int i = 0; i < DRB_configList.list.count; i++) {
      resp->drbs_to_be_setup[i].drb_id = DRB_configList.list.array[i]->drb_Identity;
      resp->drbs_to_be_setup[i].rlc_mode = RLC_MODE_AM;
      resp->drbs_to_be_setup[i].up_dl_tnl[0].teid = incoming_teid;
      resp->drbs_to_be_setup[i].up_dl_tnl[0].tl_address = inet_addr(mac->eth_params_n.my_addr);
      resp->drbs_to_be_setup[i].up_dl_tnl_length = 1;
    }
  } else {
    LOG_W(NR_RRC, "No DRB added upon reception of F1 UE context modification request with a DRB to setup list\n");
  }
  if (SRB_configList.list.count > 0 && SRBs_before_new_addition < SRB_configList.list.count) {
    resp->srbs_to_be_setup = calloc(1, req->srbs_to_be_setup_length * sizeof(f1ap_srb_to_be_setup_t));
    resp->srbs_to_be_setup_length = req->srbs_to_be_setup_length;
    for (int i = SRBs_before_new_addition; i < SRB_configList.list.count; i++) {
      resp->srbs_to_be_setup[i - SRBs_before_new_addition].srb_id = SRB_configList.list.array[i]->srb_Identity;
    }
  } else {
    LOG_W(NR_RRC, "No SRB added upon reception of F1 UE Context modification request at the DU\n");
  }

  // if(cellGroupConfig != NULL) {
  resp->du_to_cu_rrc_information = calloc(1, sizeof(du_to_cu_rrc_information_t));
  resp->du_to_cu_rrc_information->cellGroupConfig = calloc(1, 1024);
  asn_enc_rval_t enc_rval = uper_encode_to_buffer(&asn_DEF_NR_CellGroupConfig,
                                                  NULL,
                                                  UE->masterCellGroup, //(void *)cellGroupConfig,
                                                  resp->du_to_cu_rrc_information->cellGroupConfig,
                                                  1024);
  resp->du_to_cu_rrc_information->cellGroupConfig_length = (enc_rval.encoded + 7) >> 3;
  //}
  itti_send_msg_to_task(TASK_DU_F1, ctxt.module_id, message_p);
}

static void rrc_CU_process_ue_context_setup_response(MessageDef *msg_p, instance_t instance)
{
  f1ap_ue_context_setup_t *resp = &F1AP_UE_CONTEXT_SETUP_RESP(msg_p);
  protocol_ctxt_t ctxt = {.rntiMaybeUEid = resp->rnti, .module_id = instance, .instance = instance, .enb_flag = 1, .eNB_index = instance};
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt.module_id];
  struct rrc_gNB_ue_context_s *ue_context_p = rrc_gNB_get_ue_context(rrc, ctxt.rntiMaybeUEid);
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;
  NR_CellGroupConfig_t *cellGroupConfig = NULL;

  asn_dec_rval_t dec_rval = uper_decode_complete(
      NULL, &asn_DEF_NR_CellGroupConfig, (void **)&cellGroupConfig, (uint8_t *)resp->du_to_cu_rrc_information->cellGroupConfig, (int)resp->du_to_cu_rrc_information->cellGroupConfig_length);

  if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
    AssertFatal(1 == 0, "Cell group config decode error\n");
    // free the memory
    SEQUENCE_free(&asn_DEF_NR_CellGroupConfig, cellGroupConfig, 1);
    return;
  }
  // xer_fprint(stdout,&asn_DEF_NR_CellGroupConfig, cellGroupConfig);

  if (UE->masterCellGroup == NULL) {
    UE->masterCellGroup = calloc(1, sizeof(NR_CellGroupConfig_t));
  }
  if (cellGroupConfig->rlc_BearerToAddModList != NULL) {
    if (UE->masterCellGroup->rlc_BearerToAddModList != NULL) {
      int ue_ctxt_rlc_Bearers = UE->masterCellGroup->rlc_BearerToAddModList->list.count;
      for (int i = ue_ctxt_rlc_Bearers; i < ue_ctxt_rlc_Bearers + cellGroupConfig->rlc_BearerToAddModList->list.count; i++) {
        asn1cSeqAdd(&UE->masterCellGroup->rlc_BearerToAddModList->list, cellGroupConfig->rlc_BearerToAddModList->list.array[i - ue_ctxt_rlc_Bearers]);
      }
    } else {
      LOG_W(NR_RRC, "Empty rlc_BearerToAddModList at ue_context of the CU before filling the updates from UE context setup response \n");
      UE->masterCellGroup->rlc_BearerToAddModList = calloc(1, sizeof(*cellGroupConfig->rlc_BearerToAddModList));
      memcpy(UE->masterCellGroup->rlc_BearerToAddModList, cellGroupConfig->rlc_BearerToAddModList, sizeof(*cellGroupConfig->rlc_BearerToAddModList));
    }
  }
  if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
    xer_fprint(stdout, &asn_DEF_NR_CellGroupConfig, UE->masterCellGroup);
  }

  if (UE->established_pdu_sessions_flag == 1) {
    rrc_gNB_generate_dedicatedRRCReconfiguration(&ctxt, ue_context_p, cellGroupConfig);
  } else {
    rrc_gNB_generate_defaultRRCReconfiguration(&ctxt, ue_context_p);
  }

  free(cellGroupConfig->rlc_BearerToAddModList);
  free(cellGroupConfig);
}

static void rrc_CU_process_ue_context_modification_response(MessageDef *msg_p, instance_t instance)
{
  f1ap_ue_context_setup_t *resp = &F1AP_UE_CONTEXT_SETUP_RESP(msg_p);
  protocol_ctxt_t ctxt = {.rntiMaybeUEid = resp->rnti, .module_id = instance, .instance = instance, .enb_flag = 1, .eNB_index = instance};
  gNB_RRC_INST *rrc = RC.nrrrc[ctxt.module_id];
  struct rrc_gNB_ue_context_s *ue_context_p = rrc_gNB_get_ue_context(rrc, ctxt.rntiMaybeUEid);
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;

  e1ap_bearer_setup_req_t req = {0};
  req.numPDUSessionsMod = UE->nb_of_pdusessions;
  req.gNB_cu_cp_ue_id = UE->gNB_ue_ngap_id;
  req.rnti = UE->rnti;
  for (int i = 0; i < req.numPDUSessionsMod; i++) {
    req.pduSessionMod[i].numDRB2Modify = resp->drbs_to_be_setup_length;
    for (int j = 0; j < resp->drbs_to_be_setup_length; j++) {
      f1ap_drb_to_be_setup_t *drb_f1 = resp->drbs_to_be_setup + j;
      DRB_nGRAN_to_setup_t *drb_e1 = req.pduSessionMod[i].DRBnGRanModList + j;

      drb_e1->id = drb_f1->drb_id;
      drb_e1->numDlUpParam = drb_f1->up_dl_tnl_length;
      drb_e1->DlUpParamList[0].tlAddress = drb_f1->up_dl_tnl[0].tl_address;
      drb_e1->DlUpParamList[0].teId = drb_f1->up_dl_tnl[0].teid;
    }
  }

  // send the F1 response message up to update F1-U tunnel info
  rrc->cucp_cuup.bearer_context_mod(&req, instance);

  NR_CellGroupConfig_t *cellGroupConfig = NULL;

  if (resp->du_to_cu_rrc_information->cellGroupConfig != NULL) {
    asn_dec_rval_t dec_rval = uper_decode_complete(
        NULL, &asn_DEF_NR_CellGroupConfig, (void **)&cellGroupConfig, (uint8_t *)resp->du_to_cu_rrc_information->cellGroupConfig, (int)resp->du_to_cu_rrc_information->cellGroupConfig_length);

    if ((dec_rval.code != RC_OK) && (dec_rval.consumed == 0)) {
      AssertFatal(1 == 0, "Cell group config decode error\n");
      // free the memory
      SEQUENCE_free(&asn_DEF_NR_CellGroupConfig, cellGroupConfig, 1);
      return;
    }
    // xer_fprint(stdout,&asn_DEF_NR_CellGroupConfig, cellGroupConfig);

    if (UE->masterCellGroup == NULL) {
      UE->masterCellGroup = calloc(1, sizeof(NR_CellGroupConfig_t));
    }

    if (cellGroupConfig->rlc_BearerToAddModList != NULL) {
      if (UE->masterCellGroup->rlc_BearerToAddModList != NULL) {
        int ue_ctxt_rlc_Bearers = UE->masterCellGroup->rlc_BearerToAddModList->list.count;
        for (int i = ue_ctxt_rlc_Bearers; i < ue_ctxt_rlc_Bearers + cellGroupConfig->rlc_BearerToAddModList->list.count; i++) {
          asn1cSeqAdd(&UE->masterCellGroup->rlc_BearerToAddModList->list, cellGroupConfig->rlc_BearerToAddModList->list.array[i - ue_ctxt_rlc_Bearers]);
        }
      } else {
        LOG_W(NR_RRC, "Empty rlc_BearerToAddModList at ue_context of the CU before filling the updates from UE context setup response \n");
        UE->masterCellGroup->rlc_BearerToAddModList = calloc(1, sizeof(*cellGroupConfig->rlc_BearerToAddModList));
        memcpy(UE->masterCellGroup->rlc_BearerToAddModList, cellGroupConfig->rlc_BearerToAddModList, sizeof(*cellGroupConfig->rlc_BearerToAddModList));
      }
    }
    LOG_I(NR_RRC, "Updated master cell group configuration stored at the UE context of the CU:\n");
    if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
      xer_fprint(stdout, &asn_DEF_NR_CellGroupConfig, UE->masterCellGroup);
    }

    rrc_gNB_generate_dedicatedRRCReconfiguration(&ctxt, ue_context_p, cellGroupConfig);

    free(cellGroupConfig->rlc_BearerToAddModList);
    free(cellGroupConfig);
  }
}

unsigned int mask_flip(unsigned int x)
{
  return ((((x >> 8) + (x << 8)) & 0xffff) >> 6);
}

static unsigned int get_dl_bw_mask(const gNB_RRC_INST *rrc, const NR_UE_NR_Capability_t *cap)
{
  int common_band = *rrc->carrier.servingcellconfigcommon->downlinkConfigCommon->frequencyInfoDL->frequencyBandList.list.array[0];
  int common_scs = rrc->carrier.servingcellconfigcommon->downlinkConfigCommon->frequencyInfoDL->scs_SpecificCarrierList.list.array[0]->subcarrierSpacing;
  for (int i = 0; i < cap->rf_Parameters.supportedBandListNR.list.count; i++) {
    NR_BandNR_t *bandNRinfo = cap->rf_Parameters.supportedBandListNR.list.array[i];
    if (bandNRinfo->bandNR == common_band) {
      if (common_band < 257) { // FR1
        switch (common_scs) {
          case NR_SubcarrierSpacing_kHz15:
            if (bandNRinfo->channelBWs_DL && bandNRinfo->channelBWs_DL->choice.fr1 && bandNRinfo->channelBWs_DL->choice.fr1->scs_15kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_DL->choice.fr1->scs_15kHz->buf));
            break;
          case NR_SubcarrierSpacing_kHz30:
            if (bandNRinfo->channelBWs_DL && bandNRinfo->channelBWs_DL->choice.fr1 && bandNRinfo->channelBWs_DL->choice.fr1->scs_30kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_DL->choice.fr1->scs_30kHz->buf));
            break;
          case NR_SubcarrierSpacing_kHz60:
            if (bandNRinfo->channelBWs_DL && bandNRinfo->channelBWs_DL->choice.fr1 && bandNRinfo->channelBWs_DL->choice.fr1->scs_60kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_DL->choice.fr1->scs_60kHz->buf));
            break;
        }
      } else {
        switch (common_scs) {
          case NR_SubcarrierSpacing_kHz60:
            if (bandNRinfo->channelBWs_DL && bandNRinfo->channelBWs_DL->choice.fr2 && bandNRinfo->channelBWs_DL->choice.fr2->scs_60kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_DL->choice.fr2->scs_60kHz->buf));
            break;
          case NR_SubcarrierSpacing_kHz120:
            if (bandNRinfo->channelBWs_DL && bandNRinfo->channelBWs_DL->choice.fr2 && bandNRinfo->channelBWs_DL->choice.fr2->scs_120kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_DL->choice.fr2->scs_120kHz->buf));
            break;
        }
      }
    }
  }
  return (0);
}

static unsigned int get_ul_bw_mask(const gNB_RRC_INST *rrc, const NR_UE_NR_Capability_t *cap)
{
  int common_band = *rrc->carrier.servingcellconfigcommon->uplinkConfigCommon->frequencyInfoUL->frequencyBandList->list.array[0];
  int common_scs = rrc->carrier.servingcellconfigcommon->uplinkConfigCommon->frequencyInfoUL->scs_SpecificCarrierList.list.array[0]->subcarrierSpacing;
  for (int i = 0; i < cap->rf_Parameters.supportedBandListNR.list.count; i++) {
    NR_BandNR_t *bandNRinfo = cap->rf_Parameters.supportedBandListNR.list.array[i];
    if (bandNRinfo->bandNR == common_band) {
      if (common_band < 257) { // FR1
        switch (common_scs) {
          case NR_SubcarrierSpacing_kHz15:
            if (bandNRinfo->channelBWs_UL && bandNRinfo->channelBWs_UL->choice.fr1 && bandNRinfo->channelBWs_UL->choice.fr1->scs_15kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_UL->choice.fr1->scs_15kHz->buf));
            break;
          case NR_SubcarrierSpacing_kHz30:
            if (bandNRinfo->channelBWs_UL && bandNRinfo->channelBWs_UL->choice.fr1 && bandNRinfo->channelBWs_UL->choice.fr1->scs_30kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_UL->choice.fr1->scs_30kHz->buf));
            break;
          case NR_SubcarrierSpacing_kHz60:
            if (bandNRinfo->channelBWs_UL && bandNRinfo->channelBWs_UL->choice.fr1 && bandNRinfo->channelBWs_UL->choice.fr1->scs_60kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_UL->choice.fr1->scs_60kHz->buf));
            break;
        }
      } else {
        switch (common_scs) {
          case NR_SubcarrierSpacing_kHz60:
            if (bandNRinfo->channelBWs_UL && bandNRinfo->channelBWs_UL->choice.fr2 && bandNRinfo->channelBWs_UL->choice.fr2->scs_60kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_UL->choice.fr2->scs_60kHz->buf));
            break;
          case NR_SubcarrierSpacing_kHz120:
            if (bandNRinfo->channelBWs_UL && bandNRinfo->channelBWs_UL->choice.fr2 && bandNRinfo->channelBWs_UL->choice.fr2->scs_120kHz)
              return (mask_flip((unsigned int)*(uint16_t *)bandNRinfo->channelBWs_UL->choice.fr2->scs_120kHz->buf));
            break;
        }
      }
    }
  }
  return (0);
}

static int get_ul_mimo_layersCB(const gNB_RRC_INST *rrc, const NR_UE_NR_Capability_t *cap)
{
  int common_scs = rrc->carrier.servingcellconfigcommon->uplinkConfigCommon->frequencyInfoUL->scs_SpecificCarrierList.list.array[0]->subcarrierSpacing;

  // check featureSet
  NR_FeatureSets_t *fs = cap->featureSets;
  if (fs) {
    // go through UL feature sets and look for one with current SCS
    for (int i = 0; i < fs->featureSetsUplinkPerCC->list.count; i++) {
      if (fs->featureSetsUplinkPerCC->list.array[i]->supportedSubcarrierSpacingUL == common_scs && fs->featureSetsUplinkPerCC->list.array[i]->mimo_CB_PUSCH
          && fs->featureSetsUplinkPerCC->list.array[i]->mimo_CB_PUSCH->maxNumberMIMO_LayersCB_PUSCH)
        return (1 << *fs->featureSetsUplinkPerCC->list.array[i]->mimo_CB_PUSCH->maxNumberMIMO_LayersCB_PUSCH);
    }
  }
  return (1);
}

static int get_ul_mimo_layers(const gNB_RRC_INST *rrc, const NR_UE_NR_Capability_t *cap)
{
  int common_scs = rrc->carrier.servingcellconfigcommon->uplinkConfigCommon->frequencyInfoUL->scs_SpecificCarrierList.list.array[0]->subcarrierSpacing;

  // check featureSet
  NR_FeatureSets_t *fs = cap->featureSets;
  if (fs) {
    // go through UL feature sets and look for one with current SCS
    for (int i = 0; i < fs->featureSetsUplinkPerCC->list.count; i++) {
      if (fs->featureSetsUplinkPerCC->list.array[i]->supportedSubcarrierSpacingUL == common_scs && fs->featureSetsUplinkPerCC->list.array[i]->maxNumberMIMO_LayersNonCB_PUSCH)
        return (1 << *fs->featureSetsUplinkPerCC->list.array[i]->maxNumberMIMO_LayersNonCB_PUSCH);
    }
  }
  return (1);
}

static int get_dl_mimo_layers(const gNB_RRC_INST *rrc, const NR_UE_NR_Capability_t *cap)
{
  int common_scs = rrc->carrier.servingcellconfigcommon->downlinkConfigCommon->frequencyInfoDL->scs_SpecificCarrierList.list.array[0]->subcarrierSpacing;

  // check featureSet
  NR_FeatureSets_t *fs = cap->featureSets;
  if (fs) {
    // go through UL feature sets and look for one with current SCS
    for (int i = 0; i < fs->featureSetsDownlinkPerCC->list.count; i++) {
      if (fs->featureSetsUplinkPerCC->list.array[i]->supportedSubcarrierSpacingUL == common_scs && fs->featureSetsDownlinkPerCC->list.array[i]->maxNumberMIMO_LayersPDSCH)
        return (2 << *fs->featureSetsDownlinkPerCC->list.array[i]->maxNumberMIMO_LayersPDSCH);
    }
  }
  return (1);
}

void nr_rrc_subframe_process(protocol_ctxt_t *const ctxt_pP, const int CC_id)
{
  MessageDef *msg;
  rrc_gNB_ue_context_t *ue_context_p = rrc_gNB_ue_context_iterator_init();

  while (ue_context_p) {
    gNB_RRC_UE_t *UE = &ue_context_p->ue_context;
    ctxt_pP->rntiMaybeUEid = ue_context_p->ue_id_rnti;
    gNB_MAC_INST *nrmac = RC.nrmac[ctxt_pP->module_id]; // WHAT A BEAUTIFULL RACE CONDITION !!!

    if (UE->ul_failure_timer > 0) {
      UE->ul_failure_timer++;

      if (UE->ul_failure_timer >= 20000) {
        // remove UE after 20 seconds after MAC (or else) has indicated UL failure
        LOG_I(RRC, "Removing UE %x instance, because of uplink failure timer timeout\n", UE->rnti);
        if (UE->StatusRrc >= NR_RRC_CONNECTED) {
          rrc_gNB_send_NGAP_UE_CONTEXT_RELEASE_REQ(ctxt_pP->module_id, ue_context_p, NGAP_CAUSE_RADIO_NETWORK, NGAP_CAUSE_RADIO_NETWORK_RADIO_CONNECTION_WITH_UE_LOST);
        }

        // Remove here the MAC and RRC context when RRC is not connected or gNB is not connected to CN5G
        if (UE->StatusRrc < NR_RRC_CONNECTED || UE->gNB_ue_ngap_id == 0) {
          if (!NODE_IS_CU(RC.nrrrc[ctxt_pP->instance]->node_type)) {
            mac_remove_nr_ue(nrmac, ctxt_pP->rntiMaybeUEid);
            rrc_rlc_remove_ue(ctxt_pP);
            pdcp_remove_UE(ctxt_pP);

            /* remove RRC UE Context */
            ue_context_p = rrc_gNB_get_ue_context(RC.nrrrc[ctxt_pP->module_id], ctxt_pP->rntiMaybeUEid);
            if (ue_context_p) {
              rrc_gNB_remove_ue_context(RC.nrrrc[ctxt_pP->module_id], ue_context_p);
              rrc_gNB_free_mem_UE_context(ue_context_p);
              LOG_I(NR_RRC, "remove UE %lx \n", ctxt_pP->rntiMaybeUEid);
            }
          }
          // In case of CU trigger UE context release command towards the DU
          else {
            MessageDef *message_p;
            message_p = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_UE_CONTEXT_RELEASE_CMD);
            f1ap_ue_context_release_cmd_t *rel_cmd = &F1AP_UE_CONTEXT_RELEASE_CMD(message_p);
            rel_cmd->rnti = ctxt_pP->rntiMaybeUEid;
            rel_cmd->cause = F1AP_CAUSE_RADIO_NETWORK;
            rel_cmd->cause_value = 10; // 10 = F1AP_CauseRadioNetwork_normal_release
            itti_send_msg_to_task(TASK_CU_F1, ctxt_pP->module_id, message_p);
          }
        }

        break; // break RB_FOREACH
      }
    }

    if (UE->ue_release_timer_rrc > 0) {
      UE->ue_release_timer_rrc++;

      if (UE->ue_release_timer_rrc >= UE->ue_release_timer_thres_rrc) {
        LOG_I(NR_RRC, "Removing UE %x instance after UE_CONTEXT_RELEASE_Complete (ue_release_timer_rrc timeout)\n", UE->rnti);
        UE->ue_release_timer_rrc = 0;
        mac_remove_nr_ue(nrmac, ctxt_pP->rntiMaybeUEid);
        rrc_rlc_remove_ue(ctxt_pP);
        pdcp_remove_UE(ctxt_pP);
        newGtpuDeleteAllTunnels(ctxt_pP->instance, ctxt_pP->rntiMaybeUEid);

        /* remove RRC UE Context */
        ue_context_p = rrc_gNB_get_ue_context(RC.nrrrc[ctxt_pP->module_id], ctxt_pP->rntiMaybeUEid);
        if (ue_context_p) {
          rrc_gNB_remove_ue_context(RC.nrrrc[ctxt_pP->module_id], ue_context_p);
          rrc_gNB_free_mem_UE_context(ue_context_p);
          LOG_I(NR_RRC, "remove UE %lx \n", ctxt_pP->rntiMaybeUEid);
        }

        break; // break RB_FOREACH
      }
    }
    ue_context_p = rrc_gNB_ue_context_iterator_next(ue_context_p);
  }

  /* send a tick to x2ap */
  if (is_x2ap_enabled()) {
    msg = itti_alloc_new_message(TASK_RRC_ENB, 0, X2AP_SUBFRAME_PROCESS);
    itti_send_msg_to_task(TASK_X2AP, ctxt_pP->module_id, msg);
  }
}

int rrc_gNB_process_e1_setup_req(e1ap_setup_req_t *req, instance_t instance)
{
  AssertFatal(req->supported_plmns <= PLMN_LIST_MAX_SIZE, "Supported PLMNs is more than PLMN_LIST_MAX_SIZE\n");
  gNB_RRC_INST *rrc = RC.nrrrc[0]; // TODO: remove hardcoding of RC index here
  MessageDef *msg_p = itti_alloc_new_message(TASK_RRC_GNB, instance, E1AP_SETUP_RESP);

  e1ap_setup_resp_t *resp = &E1AP_SETUP_RESP(msg_p);
  resp->transac_id = req->transac_id;

  for (int i = 0; i < req->supported_plmns; i++) {
    if (rrc->configuration.mcc[i] == req->plmns[i].mcc && rrc->configuration.mnc[i] == req->plmns[i].mnc) {
      LOG_E(NR_RRC,
            "PLMNs received from CUUP (mcc:%d, mnc:%d) did not match with PLMNs in RRC (mcc:%d, mnc:%d)\n",
            req->plmns[i].mcc,
            req->plmns[i].mnc,
            rrc->configuration.mcc[i],
            rrc->configuration.mnc[i]);
      return -1;
    }
  }

  itti_send_msg_to_task(TASK_CUCP_E1, instance, msg_p);

  return 0;
}

void prepare_and_send_ue_context_modification_f1(rrc_gNB_ue_context_t *ue_context_p, e1ap_bearer_setup_resp_t *e1ap_resp)
{
  /*Generate a UE context modification request message towards the DU to instruct the DU
   *for SRB2 and DRB configuration and get the updates on master cell group config from the DU*/

  protocol_ctxt_t ctxt = {0};
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;
  PROTOCOL_CTXT_SET_BY_MODULE_ID(&ctxt, 0, GNB_FLAG_YES, UE->rnti, 0, 0, 0);

  // TODO: So many hard codings
  MessageDef *message_p;
  message_p = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_UE_CONTEXT_MODIFICATION_REQ);
  f1ap_ue_context_setup_t *req = &F1AP_UE_CONTEXT_MODIFICATION_REQ(message_p);
  req->rnti = UE->rnti;
  req->mcc = RC.nrrrc[ctxt.module_id]->configuration.mcc[0];
  req->mnc = RC.nrrrc[ctxt.module_id]->configuration.mnc[0];
  req->mnc_digit_length = RC.nrrrc[ctxt.module_id]->configuration.mnc_digit_length[0];
  req->nr_cellid = RC.nrrrc[ctxt.module_id]->nr_cellid;

  /*Instruction towards the DU for SRB2 configuration*/
  req->srbs_to_be_setup = malloc(1 * sizeof(f1ap_srb_to_be_setup_t));
  req->srbs_to_be_setup_length = 1;
  f1ap_srb_to_be_setup_t *SRBs = req->srbs_to_be_setup;
  SRBs[0].srb_id = 2;
  SRBs[0].lcid = 2;

  /*Instruction towards the DU for DRB configuration and tunnel creation*/
  req->drbs_to_be_setup_length = e1ap_resp->pduSession[0].numDRBSetup;
  req->drbs_to_be_setup = malloc(1 * sizeof(f1ap_drb_to_be_setup_t) * req->drbs_to_be_setup_length);
  for (int i = 0; i < e1ap_resp->pduSession[0].numDRBSetup; i++) {
    f1ap_drb_to_be_setup_t *DRBs = req->drbs_to_be_setup + i;
    DRBs[i].drb_id = e1ap_resp->pduSession[0].DRBnGRanList[i].id;
    DRBs[i].rlc_mode = RLC_MODE_AM;
    DRBs[i].up_ul_tnl[0].tl_address = e1ap_resp->pduSession[0].DRBnGRanList[i].UpParamList[0].tlAddress;
    DRBs[i].up_ul_tnl[0].port = RC.nrrrc[ctxt.module_id]->eth_params_s.my_portd;
    DRBs[i].up_ul_tnl[0].teid = e1ap_resp->pduSession[0].DRBnGRanList[i].UpParamList[0].teId;
    DRBs[i].up_ul_tnl_length = 1;
  }

  itti_send_msg_to_task(TASK_CU_F1, ctxt.module_id, message_p);
}

void rrc_gNB_process_e1_bearer_context_setup_resp(e1ap_bearer_setup_resp_t *resp, instance_t instance)
{
  // Find the UE context from UE ID and send ITTI message to F1AP to send UE context modification message to DU

  rrc_gNB_ue_context_t *ue_context_p = rrc_gNB_get_ue_context(RC.nrrrc[instance], resp->gNB_cu_cp_ue_id);
  protocol_ctxt_t ctxt = {0};
  gNB_RRC_UE_t *UE = &ue_context_p->ue_context;
  PROTOCOL_CTXT_SET_BY_MODULE_ID(&ctxt, 0, GNB_FLAG_YES, UE->rnti, 0, 0, 0);

  gtpv1u_gnb_create_tunnel_resp_t create_tunnel_resp = {0};
  create_tunnel_resp.num_tunnels = resp->numPDUSessions;
  for (int i = 0; i < resp->numPDUSessions; i++) {
    create_tunnel_resp.pdusession_id[i] = resp->pduSession[i].id;
    create_tunnel_resp.gnb_NGu_teid[i] = resp->pduSession[i].teId;
    memcpy(create_tunnel_resp.gnb_addr.buffer, &resp->pduSession[i].tlAddress, sizeof(in_addr_t));
    create_tunnel_resp.gnb_addr.length = sizeof(in_addr_t); // IPv4 byte length
  }

  nr_rrc_gNB_process_GTPV1U_CREATE_TUNNEL_RESP(&ctxt, &create_tunnel_resp);

  UE->setup_pdu_sessions += resp->numPDUSessions;

  // TODO: SV: combine e1ap_bearer_setup_req_t and e1ap_bearer_setup_resp_t and minimize assignments
  prepare_and_send_ue_context_modification_f1(ue_context_p, resp);
}

static void print_rrc_meas(FILE *f, const NR_MeasResults_t *measresults)
{
  DevAssert(measresults->measResultServingMOList.list.count >= 1);
  if (measresults->measResultServingMOList.list.count > 1)
    LOG_W(RRC, "Received %d MeasResultServMO, but handling only 1!\n", measresults->measResultServingMOList.list.count);

  NR_MeasResultServMO_t *measresultservmo = measresults->measResultServingMOList.list.array[0];
  NR_MeasResultNR_t *measresultnr = &measresultservmo->measResultServingCell;
  NR_MeasQuantityResults_t *mqr = measresultnr->measResult.cellResults.resultsSSB_Cell;

  fprintf(f, "    servingCellId %ld MeasResultNR for phyCellId %ld:\n      resultSSB:", measresultservmo->servCellId, *measresultnr->physCellId);
  if (mqr != NULL) {
    const long rrsrp = *mqr->rsrp - 156;
    const float rrsrq = (float)(*mqr->rsrq - 87) / 2.0f;
    const float rsinr = (float)(*mqr->sinr - 46) / 2.0f;
    fprintf(f, "RSRP %ld dBm RSRQ %.1f dB SINR %.1f dB\n", rrsrp, rrsrq, rsinr);
  } else {
    fprintf(f, "NOT PROVIDED\n");
  }
}

static void write_rrc_stats(const gNB_RRC_INST *rrc)
{
  const char *filename = "nrRRC_stats.log";
  FILE *f = fopen(filename, "w");
  if (f == NULL) {
    LOG_E(NR_RRC, "cannot open %s for writing\n", filename);
    return;
  }

  rrc_gNB_ue_context_t *ue_context_p = rrc_gNB_ue_context_iterator_init();
  /* cast is necessary to eliminate warning "discards ‘const’ qualifier" */
  while (ue_context_p) {
    const rnti_t rnti = ue_context_p->ue_id_rnti;
    const gNB_RRC_UE_t *ue_ctxt = &ue_context_p->ue_context;

    fprintf(f, "NR RRC UE rnti %04x:", rnti);

    if (ue_ctxt->Initialue_identity_5g_s_TMSI.presence)
      fprintf(f, " S-TMSI %x\n", ue_ctxt->Initialue_identity_5g_s_TMSI.fiveg_tmsi);

    fprintf(f, " failure timer %d/8\n", ue_ctxt->ul_failure_timer);

    if (ue_ctxt->UE_Capability_nr) {
      fprintf(f,
              "    UE cap: BW DL %x. BW UL %x, DL MIMO Layers %d UL MIMO Layers (CB) %d UL MIMO Layers (nonCB) %d\n",
              get_dl_bw_mask(rrc, ue_ctxt->UE_Capability_nr),
              get_ul_bw_mask(rrc, ue_ctxt->UE_Capability_nr),
              get_dl_mimo_layers(rrc, ue_ctxt->UE_Capability_nr),
              get_ul_mimo_layersCB(rrc, ue_ctxt->UE_Capability_nr),
              get_ul_mimo_layers(rrc, ue_ctxt->UE_Capability_nr));
    }

    if (ue_ctxt->measResults)
      print_rrc_meas(f, ue_ctxt->measResults);
    ue_context_p = rrc_gNB_ue_context_iterator_next(ue_context_p);
  }

  fclose(f);
}

///---------------------------------------------------------------------------------------------------------------///
///---------------------------------------------------------------------------------------------------------------///
void *rrc_gnb_task(void *args_p)
{
  MessageDef *msg_p;
  const char *msg_name_p;
  instance_t instance;
  int result;
  // SRB_INFO                           *srb_info_p;
  // int                                CC_id;
  protocol_ctxt_t ctxt = {.module_id = 0, .enb_flag = 1, .instance = 0, .rntiMaybeUEid = 0, .frame = -1, .subframe = -1, .eNB_index = 0, .brOption = false};

  /* timer to write stats to file */
  long stats_timer_id = 1;
  timer_setup(1, 0, TASK_RRC_GNB, 0, TIMER_PERIODIC, NULL, &stats_timer_id);

  itti_mark_task_ready(TASK_RRC_GNB);
  LOG_I(NR_RRC, "Entering main loop of NR_RRC message task\n");

  while (1) {
    // Wait for a message
    itti_receive_msg(TASK_RRC_GNB, &msg_p);
    msg_name_p = ITTI_MSG_NAME(msg_p);
    instance = ITTI_MSG_DESTINATION_INSTANCE(msg_p);

    switch (ITTI_MSG_ID(msg_p)) {
      case TERMINATE_MESSAGE:
        LOG_W(NR_RRC, " *** Exiting NR_RRC thread\n");
        itti_exit_task();
        break;

      case MESSAGE_TEST:
        LOG_I(NR_RRC, "[gNB %ld] Received %s\n", instance, msg_name_p);
        break;

      case TIMER_HAS_EXPIRED:
        /* only this one handled for now */
        DevAssert(TIMER_HAS_EXPIRED(msg_p).timer_id == stats_timer_id);
        write_rrc_stats(RC.nrrrc[0]);
        break;

      case RRC_SUBFRAME_PROCESS:
        nr_rrc_subframe_process(&RRC_SUBFRAME_PROCESS(msg_p).ctxt, RRC_SUBFRAME_PROCESS(msg_p).CC_id);
        break;

      case F1AP_INITIAL_UL_RRC_MESSAGE:
        AssertFatal(NODE_IS_CU(RC.nrrrc[instance]->node_type) || NODE_IS_MONOLITHIC(RC.nrrrc[instance]->node_type),
                    "should not receive F1AP_INITIAL_UL_RRC_MESSAGE, need call by CU!\n");
        rrc_gNB_process_initial_ul_rrc_message(&F1AP_INITIAL_UL_RRC_MESSAGE(msg_p));
        break;

        /* Messages from PDCP */
      case F1AP_UL_RRC_MESSAGE:
        PROTOCOL_CTXT_SET_BY_INSTANCE(&ctxt,
                                      instance,
                                      GNB_FLAG_YES,
                                      F1AP_UL_RRC_MESSAGE(msg_p).rnti,
                                      0,
                                      0);
        LOG_D(NR_RRC,
              "Decoding DCCH %d: ue %04lx, inst %ld, ctxt %p, size %d\n",
              F1AP_UL_RRC_MESSAGE(msg_p).srb_id,
              ctxt.rntiMaybeUEid,
              instance,
              &ctxt,
              F1AP_UL_RRC_MESSAGE(msg_p).rrc_container_length);
        rrc_gNB_decode_dcch(&ctxt,
                            F1AP_UL_RRC_MESSAGE(msg_p).srb_id,
                            F1AP_UL_RRC_MESSAGE(msg_p).rrc_container,
                            F1AP_UL_RRC_MESSAGE(msg_p).rrc_container_length);
        free(F1AP_UL_RRC_MESSAGE(msg_p).rrc_container);
        break;

      case NGAP_DOWNLINK_NAS:
        rrc_gNB_process_NGAP_DOWNLINK_NAS(msg_p, instance, &rrc_gNB_mui);
        break;

      case NGAP_PDUSESSION_SETUP_REQ:
        rrc_gNB_process_NGAP_PDUSESSION_SETUP_REQ(msg_p, instance);
        break;

      case NGAP_PDUSESSION_MODIFY_REQ:
        rrc_gNB_process_NGAP_PDUSESSION_MODIFY_REQ(msg_p, instance);
        break;

      case NGAP_PDUSESSION_RELEASE_COMMAND:
        rrc_gNB_process_NGAP_PDUSESSION_RELEASE_COMMAND(msg_p, instance);
        break;

        /* Messages from gNB app */
      case NRRRC_CONFIGURATION_REQ:
        LOG_I(NR_RRC, "[gNB %ld] Received %s : %p\n", instance, msg_name_p,&NRRRC_CONFIGURATION_REQ(msg_p));
        openair_rrc_gNB_configuration(GNB_INSTANCE_TO_MODULE_ID(instance), &NRRRC_CONFIGURATION_REQ(msg_p));
        break;

        /* Messages from F1AP task */
      case F1AP_SETUP_REQ:
        AssertFatal(NODE_IS_CU(RC.nrrrc[instance]->node_type),
                    "should not receive F1AP_SETUP_REQUEST, need call by CU!\n");
        LOG_I(NR_RRC,"[gNB %ld] Received %s : %p\n", instance, msg_name_p, &F1AP_SETUP_REQ(msg_p));
        rrc_gNB_process_f1_setup_req(&F1AP_SETUP_REQ(msg_p));
        break;
	
      case NR_DU_RRC_DL_INDICATION:
        rrc_process_DU_DL(msg_p, instance);
        break;
      
      case F1AP_UE_CONTEXT_SETUP_REQ:
        rrc_DU_process_ue_context_setup_request(msg_p, instance);
        break;

      case F1AP_UE_CONTEXT_SETUP_RESP:
        rrc_CU_process_ue_context_setup_response(msg_p, instance);
        break;

      case F1AP_UE_CONTEXT_MODIFICATION_RESP:
        rrc_CU_process_ue_context_modification_response(msg_p, instance);
        break;

      case F1AP_UE_CONTEXT_MODIFICATION_REQ:
        rrc_DU_process_ue_context_modification_request(msg_p, instance);
        break;

      case F1AP_UE_CONTEXT_RELEASE_CMD:
        LOG_W(NR_RRC,
              "Received F1AP_UE_CONTEXT_RELEASE_CMD for processing at the RRC layer of the DU. Processing function "
              "implementation is pending\n");
        break;

        /* Messages from X2AP */
      case X2AP_ENDC_SGNB_ADDITION_REQ:
        LOG_I(NR_RRC, "Received ENDC sgNB addition request from X2AP \n");
        rrc_gNB_process_AdditionRequestInformation(GNB_INSTANCE_TO_MODULE_ID(instance), &X2AP_ENDC_SGNB_ADDITION_REQ(msg_p));
        break;

      case X2AP_ENDC_SGNB_RECONF_COMPLETE:
        LOG_A(NR_RRC, "Handling of reconfiguration complete message at RRC gNB is pending \n");
        break;

      case NGAP_INITIAL_CONTEXT_SETUP_REQ:
        rrc_gNB_process_NGAP_INITIAL_CONTEXT_SETUP_REQ(msg_p, instance);
        break;

      case X2AP_ENDC_SGNB_RELEASE_REQUEST:
        LOG_I(NR_RRC, "Received ENDC sgNB release request from X2AP \n");
        rrc_gNB_process_release_request(GNB_INSTANCE_TO_MODULE_ID(instance), &X2AP_ENDC_SGNB_RELEASE_REQUEST(msg_p));
        break;

      case X2AP_ENDC_DC_OVERALL_TIMEOUT:
        rrc_gNB_process_dc_overall_timeout(GNB_INSTANCE_TO_MODULE_ID(instance), &X2AP_ENDC_DC_OVERALL_TIMEOUT(msg_p));
        break;

      case NGAP_UE_CONTEXT_RELEASE_REQ:
        rrc_gNB_process_NGAP_UE_CONTEXT_RELEASE_REQ(msg_p, instance);
        break;

      case NGAP_UE_CONTEXT_RELEASE_COMMAND:
        rrc_gNB_process_NGAP_UE_CONTEXT_RELEASE_COMMAND(msg_p, instance);
        break;

      case E1AP_SETUP_REQ:
        LOG_I(NR_RRC, "Received E1AP_SETUP_REQ for instance %d\n", (int)instance);
        rrc_gNB_process_e1_setup_req(&E1AP_SETUP_REQ(msg_p), instance);
        break;

      case E1AP_BEARER_CONTEXT_SETUP_RESP:
        LOG_I(NR_RRC, "Received E1AP_BEARER_CONTEXT_SETUP_RESP for instance %d\n", (int)instance);
        rrc_gNB_process_e1_bearer_context_setup_resp(&E1AP_BEARER_CONTEXT_SETUP_RESP(msg_p), instance);

      case NGAP_PAGING_IND:
        rrc_gNB_process_PAGING_IND(msg_p, instance);
        break;

      default:
        LOG_E(NR_RRC, "[gNB %ld] Received unexpected message %s\n", instance, msg_name_p);
        break;
    }

    result = itti_free(ITTI_MSG_ORIGIN_ID(msg_p), msg_p);
    AssertFatal(result == EXIT_SUCCESS, "Failed to free memory (%d)!\n", result);
    msg_p = NULL;
  }
}

//-----------------------------------------------------------------------------
void rrc_gNB_generate_SecurityModeCommand(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *const ue_context_pP)
//-----------------------------------------------------------------------------
{
  uint8_t buffer[100];
  uint8_t size;
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;

  T(T_ENB_RRC_SECURITY_MODE_COMMAND, T_INT(ctxt_pP->module_id), T_INT(ctxt_pP->frame), T_INT(ctxt_pP->subframe), T_INT(ctxt_pP->rntiMaybeUEid));
  NR_IntegrityProtAlgorithm_t integrity_algorithm = (NR_IntegrityProtAlgorithm_t)UE->integrity_algorithm;
  size = do_NR_SecurityModeCommand(ctxt_pP, buffer, rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id), UE->ciphering_algorithm, &integrity_algorithm);
  LOG_DUMPMSG(NR_RRC, DEBUG_RRC, (char *)buffer, size, "[MSG] RRC Security Mode Command\n");
  LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Logical Channel DL-DCCH, Generate SecurityModeCommand (bytes %d)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size);

  switch (RC.nrrrc[ctxt_pP->module_id]->node_type) {
    case ngran_gNB_CU:
    case ngran_gNB_CUCP:
      // create an ITTI message
      memcpy(UE->Srb[1].Srb_info.Tx_buffer.Payload, buffer, size);
      UE->Srb[1].Srb_info.Tx_buffer.payload_size = size;

      LOG_I(NR_RRC,"calling rrc_data_req :securityModeCommand\n");
      nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);
      break;

    case ngran_gNB_DU:
      // nothing to do for DU
      AssertFatal(1==0,"nothing to do for DU\n");
      break;

    case ngran_gNB:
      LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " --- PDCP_DATA_REQ/%d Bytes (securityModeCommand to UE MUI %d) --->[PDCP][RB %02d]\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size, rrc_gNB_mui, DCCH);
      LOG_D(NR_RRC, "calling rrc_data_req :securityModeCommand\n");
      nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);
      break;

    default :
      LOG_W(NR_RRC, "Unknown node type %d\n", RC.nrrrc[ctxt_pP->module_id]->node_type);
  }
}

void rrc_gNB_generate_UECapabilityEnquiry(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *const ue_context_pP)
//-----------------------------------------------------------------------------
{
  uint8_t buffer[100];
  uint8_t size;

  T(T_ENB_RRC_UE_CAPABILITY_ENQUIRY, T_INT(ctxt_pP->module_id), T_INT(ctxt_pP->frame), T_INT(ctxt_pP->subframe), T_INT(ctxt_pP->rntiMaybeUEid));
  size = do_NR_SA_UECapabilityEnquiry(ctxt_pP, buffer, rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id));
  LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Logical Channel DL-DCCH, Generate NR UECapabilityEnquiry (bytes %d)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size);
  switch (RC.nrrrc[ctxt_pP->module_id]->node_type) {
    case ngran_gNB_CU:
    case ngran_gNB_CUCP:
      nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);
      break;

    case ngran_gNB_DU:
      // nothing to do for DU
      AssertFatal(1==0,"nothing to do for DU\n");
      break;

    case ngran_gNB:
      // rrc_mac_config_req_gNB
      LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " --- PDCP_DATA_REQ/%d Bytes (NR UECapabilityEnquiry MUI %d) --->[PDCP][RB %02d]\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size, rrc_gNB_mui, DCCH);
      nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);
      break;

    default :
      LOG_W(NR_RRC, "Unknown node type %d\n", RC.nrrrc[ctxt_pP->module_id]->node_type);
  }
}

//-----------------------------------------------------------------------------
/*
 * Generate the RRC Connection Release to UE.
 * If received, UE should switch to RRC_IDLE mode.
 */
void rrc_gNB_generate_RRCRelease(const protocol_ctxt_t *const ctxt_pP, rrc_gNB_ue_context_t *const ue_context_pP)
//-----------------------------------------------------------------------------
{
  uint8_t buffer[RRC_BUF_SIZE];
  uint16_t size = 0;
  gNB_RRC_UE_t *UE = &ue_context_pP->ue_context;
  memset(buffer, 0, sizeof(buffer));

  size = do_NR_RRCRelease(buffer, sizeof(buffer), rrc_gNB_get_next_transaction_identifier(ctxt_pP->module_id));
  UE->ue_reestablishment_timer = 0;
  UE->ue_release_timer = 0;
  UE->ul_failure_timer = 0;
  UE->ue_release_timer_rrc = 0;
  LOG_I(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " Logical Channel DL-DCCH, Generate RRCRelease (bytes %d)\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size);
  LOG_D(NR_RRC, PROTOCOL_NR_RRC_CTXT_UE_FMT " --- PDCP_DATA_REQ/%d Bytes (rrcRelease MUI %d) --->[PDCP][RB %u]\n", PROTOCOL_NR_RRC_CTXT_UE_ARGS(ctxt_pP), size, rrc_gNB_mui, DCCH);

  if (NODE_IS_CU(RC.nrrrc[ctxt_pP->module_id]->node_type)) {
    uint8_t *message_buffer = itti_malloc(TASK_RRC_GNB, TASK_CU_F1, size);
    memcpy(message_buffer, buffer, size);
    MessageDef *m = itti_alloc_new_message(TASK_RRC_GNB, 0, F1AP_UE_CONTEXT_RELEASE_CMD);
    F1AP_UE_CONTEXT_RELEASE_CMD(m).rnti = ctxt_pP->rntiMaybeUEid;
    F1AP_UE_CONTEXT_RELEASE_CMD(m).cause = F1AP_CAUSE_RADIO_NETWORK;
    F1AP_UE_CONTEXT_RELEASE_CMD(m).cause_value = 10; // 10 = F1AP_CauseRadioNetwork_normal_release
    F1AP_UE_CONTEXT_RELEASE_CMD(m).rrc_container = message_buffer;
    F1AP_UE_CONTEXT_RELEASE_CMD(m).rrc_container_length = size;
    itti_send_msg_to_task(TASK_CU_F1, ctxt_pP->module_id, m);
  } else {
    nr_rrc_data_req(ctxt_pP, DCCH, rrc_gNB_mui++, SDU_CONFIRM_NO, size, buffer, PDCP_TRANSMISSION_MODE_CONTROL);

    rrc_gNB_send_NGAP_UE_CONTEXT_RELEASE_COMPLETE(ctxt_pP->instance, UE->gNB_ue_ngap_id);
    UE->ue_release_timer_rrc = 1;
  }
}

int rrc_gNB_generate_pcch_msg(uint32_t tmsi, uint8_t paging_drx, instance_t instance, uint8_t CC_id)
{
  const unsigned int Ttab[4] = {32, 64, 128, 256};
  uint8_t Tc;
  uint8_t Tue;
  uint32_t pfoffset;
  uint32_t N; /* N: min(T,nB). total count of PF in one DRX cycle */
  uint32_t Ns = 0; /* Ns: max(1,nB/T) */
  uint8_t i_s; /* i_s = floor(UE_ID/N) mod Ns */
  uint32_t T; /* DRX cycle */
  uint32_t length;
  uint8_t buffer[RRC_BUF_SIZE];
  struct NR_SIB1 *sib1 = RC.nrrrc[instance]->carrier.siblock1->message.choice.c1->choice.systemInformationBlockType1;

  /* get default DRX cycle from configuration */
  Tc = sib1->servingCellConfigCommon->downlinkConfigCommon.pcch_Config.defaultPagingCycle;

  Tue = paging_drx;
  /* set T = min(Tc,Tue) */
  T = Tc < Tue ? Ttab[Tc] : Ttab[Tue];
  /* set N = PCCH-Config->nAndPagingFrameOffset */
  switch (sib1->servingCellConfigCommon->downlinkConfigCommon.pcch_Config.nAndPagingFrameOffset.present) {
    case NR_PCCH_Config__nAndPagingFrameOffset_PR_oneT:
      N = T;
      pfoffset = 0;
      break;
    case NR_PCCH_Config__nAndPagingFrameOffset_PR_halfT:
      N = T/2;
      pfoffset = 1;
      break;
    case NR_PCCH_Config__nAndPagingFrameOffset_PR_quarterT:
      N = T/4;
      pfoffset = 3;
      break;
    case NR_PCCH_Config__nAndPagingFrameOffset_PR_oneEighthT:
      N = T/8;
      pfoffset = 7;
      break;
    case NR_PCCH_Config__nAndPagingFrameOffset_PR_oneSixteenthT:
      N = T/16;
      pfoffset = 15;
      break;
    default:
      LOG_E(RRC, "[gNB %ld] In rrc_gNB_generate_pcch_msg:  pfoffset error (pfoffset %d)\n",
            instance, sib1->servingCellConfigCommon->downlinkConfigCommon.pcch_Config.nAndPagingFrameOffset.present);
      return (-1);
  }

  switch (sib1->servingCellConfigCommon->downlinkConfigCommon.pcch_Config.ns) {
    case NR_PCCH_Config__ns_four:
      if(*sib1->servingCellConfigCommon->downlinkConfigCommon.initialDownlinkBWP.pdcch_ConfigCommon->choice.setup->pagingSearchSpace == 0){
        LOG_E(RRC, "[gNB %ld] In rrc_gNB_generate_pcch_msg:  ns error only 1 or 2 is allowed when pagingSearchSpace is 0\n",
              instance);
        return (-1);
      } else {
        Ns = 4;
      }
      break;
    case NR_PCCH_Config__ns_two:
      Ns = 2;
      break;
    case NR_PCCH_Config__ns_one:
      Ns = 1;
      break;
    default:
      LOG_E(RRC, "[gNB %ld] In rrc_gNB_generate_pcch_msg: ns error (ns %ld)\n",
            instance, sib1->servingCellConfigCommon->downlinkConfigCommon.pcch_Config.ns);
      return (-1);
  }

  /* insert data to UE_PF_PO or update data in UE_PF_PO */
  pthread_mutex_lock(&ue_pf_po_mutex);
  uint8_t i = 0;

  for (i = 0; i < MAX_MOBILES_PER_ENB; i++) {
    if ((UE_PF_PO[CC_id][i].enable_flag == true && UE_PF_PO[CC_id][i].ue_index_value == (uint16_t)(tmsi % 1024)) || (UE_PF_PO[CC_id][i].enable_flag != true)) {
      /* set T = min(Tc,Tue) */
      UE_PF_PO[CC_id][i].T = T;
      /* set UE_ID */
      UE_PF_PO[CC_id][i].ue_index_value = (uint16_t)(tmsi % 1024);
      /* calculate PF and PO */
      /* set PF_min and PF_offset: (SFN + PF_offset) mod T = (T div N)*(UE_ID mod N) */
      UE_PF_PO[CC_id][i].PF_min = (T / N) * (UE_PF_PO[CC_id][i].ue_index_value % N);
      UE_PF_PO[CC_id][i].PF_offset = pfoffset;
      /* set i_s */
      /* i_s = floor(UE_ID/N) mod Ns */
      i_s = (uint8_t)((UE_PF_PO[CC_id][i].ue_index_value / N) % Ns);
      UE_PF_PO[CC_id][i].i_s = i_s;

      // TODO,set PO

      if (UE_PF_PO[CC_id][i].enable_flag == true) {
        // paging exist UE log
        LOG_D(NR_RRC,
              "[gNB %ld] CC_id %d In rrc_gNB_generate_pcch_msg: Update exist UE %d, T %d, N %d, PF %d, i_s %d, PF_offset %d\n",
              instance,
              CC_id,
              UE_PF_PO[CC_id][i].ue_index_value,
              T,
              N,
              UE_PF_PO[CC_id][i].PF_min,
              UE_PF_PO[CC_id][i].i_s,
              UE_PF_PO[CC_id][i].PF_offset);
      } else {
        /* set enable_flag */
        UE_PF_PO[CC_id][i].enable_flag = true;
        // paging new UE log
        LOG_D(NR_RRC,
              "[gNB %ld] CC_id %d In rrc_gNB_generate_pcch_msg: Insert a new UE %d, T %d, N %d, PF %d, i_s %d, PF_offset %d\n",
              instance,
              CC_id,
              UE_PF_PO[CC_id][i].ue_index_value,
              T,
              N,
              UE_PF_PO[CC_id][i].PF_min,
              UE_PF_PO[CC_id][i].i_s,
              UE_PF_PO[CC_id][i].PF_offset);
      }
      break;
    }
  }

  pthread_mutex_unlock(&ue_pf_po_mutex);

  /* Create message for PDCP (DLInformationTransfer_t) */
  length = do_NR_Paging(instance, buffer, tmsi);

  if (length == -1) {
    LOG_I(NR_RRC, "do_Paging error\n");
    return -1;
  }
  // TODO, send message to pdcp

  return 0;
}

void nr_rrc_trigger(protocol_ctxt_t *ctxt, int CC_id, int frame, int subframe)
{
  MessageDef *message_p;
  message_p = itti_alloc_new_message(TASK_RRC_GNB, 0, RRC_SUBFRAME_PROCESS);
  RRC_SUBFRAME_PROCESS(message_p).ctxt = *ctxt;
  RRC_SUBFRAME_PROCESS(message_p).CC_id = CC_id;
  LOG_D(NR_RRC, "Time in RRC: %u/ %u \n", frame, subframe);
  itti_send_msg_to_task(TASK_RRC_GNB, ctxt->module_id, message_p);
}
