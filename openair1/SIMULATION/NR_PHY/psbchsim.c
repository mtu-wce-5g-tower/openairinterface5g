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

#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "common/config/config_userapi.h"
#include "common/utils/LOG/log.h"
#include "common/utils/load_module_shlib.h"
#include "common/ran_context.h"
#include "common/utils/nr/nr_common.h"
#include "PHY/types.h"
#include "PHY/defs_nr_common.h"
#include "PHY/defs_nr_UE.h"
#include "PHY/NR_REFSIG/refsig_defs_ue.h"
#include "PHY/MODULATION/modulation_eNB.h"
#include "PHY/MODULATION/modulation_UE.h"
#include "PHY/MODULATION/nr_modulation.h"
#include "PHY/INIT/phy_init.h"
#include "PHY/NR_TRANSPORT/nr_transport_proto.h"
#include "PHY/NR_UE_TRANSPORT/nr_transport_proto_ue.h"
#include "PHY/NR_UE_ESTIMATION/nr_estimation.h"
#include "PHY/phy_vars.h"
#include "SCHED_NR/sched_nr.h"
#include "openair1/SIMULATION/TOOLS/sim.h"
#include "openair1/SIMULATION/RF/rf.h"
#include "openair1/SIMULATION/NR_PHY/nr_unitary_defs.h"
#include "openair1/SIMULATION/NR_PHY/nr_dummy_functions.c"
#include "openair1/PHY/MODULATION/nr_modulation.h"
#include <executables/softmodem-common.h>
#include <executables/nr-uesoftmodem.h>
//#define DEBUG_NR_PSBCHSIM
RAN_CONTEXT_t RC;
double cpuf;
uint16_t NB_UE_INST = 1;
openair0_config_t openair0_cfg[MAX_CARDS];
uint8_t const nr_rv_round_map[4] = {0, 2, 3, 1};

uint64_t get_softmodem_optmask(void) {return 0;}
static softmodem_params_t softmodem_params;
softmodem_params_t *get_softmodem_params(void) {
  return &softmodem_params;
}

nrUE_params_t nrUE_params={0};
nrUE_params_t *get_nrUE_params(void) {
  return &nrUE_params;
}

void init_downlink_harq_status(NR_DL_UE_HARQ_t *dl_harq) {}

int nr_ue_pdcch_procedures(uint8_t gNB_id,
			   PHY_VARS_NR_UE *ue,
			   UE_nr_rxtx_proc_t *proc,
         int32_t pdcch_est_size,
         int32_t pdcch_dl_ch_estimates[][pdcch_est_size],
         NR_UE_PDCCH_CONFIG *phy_pdcch_config,
         int n_ss) {
  return 0;
}

int nr_ue_pdsch_procedures(PHY_VARS_NR_UE *ue,
                           UE_nr_rxtx_proc_t *proc,
                           int eNB_id, PDSCH_t pdsch,
                           NR_UE_DLSCH_t *dlsch0, NR_UE_DLSCH_t *dlsch1) {
  return 0;
}

bool nr_ue_dlsch_procedures(PHY_VARS_NR_UE *ue,
                            UE_nr_rxtx_proc_t *proc,
                            int gNB_id,
                            PDSCH_t pdsch,
                            NR_UE_DLSCH_t *dlsch0,
                            NR_UE_DLSCH_t *dlsch1,
                            int *dlsch_errors) {
  return false;
}

double cfo = 0;
double snr0 =- 2.0;
double snr1 = 2.0;
uint8_t snr1set = 0;
int n_trials = 1;
uint8_t n_tx = 1;
uint8_t n_rx = 1;
uint16_t Nid_cell = 0;
uint64_t SSB_positions = 0x01;
int ssb_subcarrier_offset = 0;
FILE *input_fd = NULL;
SCM_t channel_model = AWGN;
int N_RB_DL = 273;
int mu = 1;
unsigned char psbch_phase = 0;
int run_initial_sync = 0;
int loglvl = OAILOG_WARNING;
float target_error_rate = 0.01;
int seed = 0;

void nr_phy_config_request_sim_psbchsim(PHY_VARS_NR_UE *ue,
                                        int N_RB_DL,
                                        int N_RB_UL,
                                        int mu,
                                        int Nid_SL,
                                        uint64_t position_in_burst)
{
  uint64_t rev_burst = 0;
  for (int i = 0; i < 64; i++)
    rev_burst |= (((position_in_burst >> (63-i))&0x01) << i);

  NR_DL_FRAME_PARMS *fp                                  = &ue->frame_parms;
  fapi_nr_config_request_t *nrUE_config                  = &ue->nrUE_config;
  nrUE_config->cell_config.phy_cell_id                   = Nid_SL; // TODO
  nrUE_config->ssb_config.scs_common                     = mu;
  nrUE_config->ssb_table.ssb_subcarrier_offset           = 0;
  nrUE_config->ssb_table.ssb_offset_point_a              = (N_RB_DL-20)>>1;
  nrUE_config->ssb_table.ssb_mask_list[1].ssb_mask       = (rev_burst)&(0xFFFFFFFF);
  nrUE_config->ssb_table.ssb_mask_list[0].ssb_mask       = (rev_burst>>32)&(0xFFFFFFFF);
  nrUE_config->cell_config.frame_duplex_type             = TDD;
  nrUE_config->ssb_table.ssb_period                      = 1; //10ms
  nrUE_config->carrier_config.dl_grid_size[mu]           = N_RB_DL;
  nrUE_config->carrier_config.ul_grid_size[mu]           = N_RB_UL;
  nrUE_config->carrier_config.num_tx_ant                 = fp->nb_antennas_tx;
  nrUE_config->carrier_config.num_rx_ant                 = fp->nb_antennas_rx;
  nrUE_config->tdd_table.tdd_period                      = 0;
  ue->mac_enabled                                        = 1;
  fp->dl_CarrierFreq                                     = 3600000000;
  fp->ul_CarrierFreq                                     = 3600000000;
  fp->nb_antennas_tx = n_tx;
  fp->nb_antennas_rx = n_rx;
  fp->nb_antenna_ports_gNB = n_tx;
  fp->N_RB_DL = N_RB_DL;
  fp->Nid_cell = Nid_cell;
  fp->nushift = Nid_cell % 4;
  fp->ssb_type = nr_ssb_type_C;
  fp->freq_range = mu < 2 ? nr_FR1 : nr_FR2;
  fp->nr_band = mu < 2 ? 78 : 257;
  fp->threequarter_fs = 0;
  fp->ofdm_offset_divisor = UINT_MAX;
  fp->ssb_start_subcarrier = 12 * ue->nrUE_config.ssb_table.ssb_offset_point_a + ssb_subcarrier_offset;
  nrUE_config->carrier_config.dl_bandwidth = config_bandwidth(mu, N_RB_DL, fp->nr_band);

  nr_init_frame_parms_ue(fp, nrUE_config, fp->nr_band);
  init_timeshift_rotation(fp);
  init_symbol_rotation(fp);

  ue->configured = true;
  LOG_I(NR_PHY, "nrUE configured\n");
}


static void get_sim_cl_opts(int argc, char **argv)
{
    char c;
    while ((c = getopt(argc, argv, "F:g:hIL:m:M:n:N:o:O:P:r:R:s:S:x:y:z:")) != -1) {
    switch (c) {
      case 'F':
        input_fd = fopen(optarg, "r");
        if (input_fd == NULL) {
          printf("Problem with filename %s. Exiting.\n", optarg);
          exit(-1);
        }
        break;

      case 'g':
        switch((char)*optarg) {
          case 'A':
            channel_model=SCM_A;
            break;

          case 'B':
            channel_model=SCM_B;
            break;

          case 'C':
            channel_model=SCM_C;
            break;

          case 'D':
            channel_model=SCM_D;
            break;

          case 'E':
            channel_model=EPA;
            break;

          case 'F':
            channel_model=EVA;
            break;

          case 'G':
            channel_model=ETU;
            break;

          default:
            printf("Unsupported channel model! Exiting.\n");
            exit(-1);
          }
        break;

      case 'I':
        run_initial_sync = 1;
        target_error_rate = 0.1;
        break;

      case 'L':
        loglvl = atoi(optarg);
        break;

      case 'm':
        mu = atoi(optarg);
        break;

      case 'M':
        SSB_positions = atoi(optarg);
        break;

      case 'n':
        n_trials = atoi(optarg);
        break;

      case 'N':
        Nid_cell = atoi(optarg);
        break;

      case 'O':
        ssb_subcarrier_offset = atoi(optarg);
        break;

      case 'o':
        cfo = atof(optarg);
        break;

      case 'P':
        psbch_phase = atoi(optarg);
        if (psbch_phase > 3)
          printf("Illegal PSBCH phase (0-3) got %d\n", psbch_phase);
        break;

      case 'r':
        seed = atoi(optarg);
        break;

      case 'R':
        N_RB_DL = atoi(optarg);
        break;

      case 's':
        snr0 = atof(optarg);
        break;

      case 'S':
        snr1 = atof(optarg);
        snr1set = 1;
        break;

      case 'y':
        n_tx = atoi(optarg);
        if ((n_tx == 0) || (n_tx > 2)) {
          printf("Unsupported number of TX antennas %d. Exiting.\n", n_tx);
          exit(-1);
        }
        break;

      case 'z':
        n_rx = atoi(optarg);
        if ((n_rx == 0) || (n_rx > 2)) {
          printf("Unsupported number of RX antennas %d. Exiting.\n", n_rx);
          exit(-1);
        }
        break;

      default:
      case 'h':
        printf("%s -F input_filename -g channel_mod -h(elp) -I(nitial sync) -L log_lvl -n n_frames -M SSBs -n frames -N cell_id -o FO -P phase -r seed -R RBs -s snr0 -S snr1 -y TXant -z RXant\n",
              argv[0]);
        printf("-F Input filename (.txt format) for RX conformance testing\n");
        printf("-g [A,B,C,D,E,F,G] Use 3GPP SCM (A,B,C,D) or 36-101 (E-EPA,F-EVA,G-ETU) models (ignores delay spread and Ricean factor)\n");
        printf("-h This message\n");
        printf("-I run initial sync with target error rate 0.1\n");
        printf("-L set the log level (-1 disable, 0 error, 1 warning, 2 info, 3 debug, 4 trace)\n");
        printf("-m Numerology index\n");
        printf("-M Multiple SSB positions in burst\n");
        printf("-n Number of frames to simulate\n");
        printf("-N Nid_cell\n");
        printf("-o Carrier frequency offset in Hz\n");
        printf("-O SSB subcarrier offset\n");
        printf("-P PSBCH phase, allowed values 0-3\n");
        printf("-r set the random number generator seed (default: 0 = current time)\n");
        printf("-R N_RB_DL\n");
        printf("-s Starting SNR, runs from SNR0 to SNR0 + 10 dB if not -S given. If -n 1, then just SNR is simulated\n");
        printf("-S Ending SNR, runs from SNR0 to SNR1\n");
        printf("-x Transmission mode (1,2,6 for the moment)\n");
        printf("-y Number of TX antennas used in eNB\n");
        printf("-z Number of RX antennas used in UE\n");
        exit (-1);
        break;
    }
  }
}

int main(int argc, char **argv)
{
  get_softmodem_params()->sa = 1;
  get_softmodem_params()->sl_mode = 2;
  if (load_configmodule(argc, argv, CONFIG_ENABLECMDLINEONLY) == 0) {
    exit_fun("[NR_PSBCHSIM] Error, configuration module init failed\n");
  }
  get_sim_cl_opts(argc, argv);
  randominit(seed);
  logInit();
  set_glog(loglvl);
  if (snr1set == 0)
    snr1 = snr0 + 10;

  printf("Initializing gNodeB for mu %d, N_RB_DL %d\n", mu, N_RB_DL);

  PHY_VARS_NR_UE *UE = malloc16_clear(sizeof(*UE));
  nr_phy_config_request_sim_psbchsim(UE, N_RB_DL, N_RB_DL, mu, Nid_cell, SSB_positions);
  init_nr_ue_signal(UE, 1);
#if 0
  double fs = 0;
  double scs = 30000;
  double bw = 100e6;
  switch (mu) {
    case 1:
      scs = 30000;
      frame_parms->Lmax = 8;
      if (N_RB_DL == 217) {
        fs = 122.88e6;
        bw = 80e6;
      }
      else if (N_RB_DL == 245) {
        fs = 122.88e6;
        bw = 90e6;
      }
      else if (N_RB_DL == 273) {
        fs = 122.88e6;
        bw = 100e6;
      }
      else if (N_RB_DL == 106) {
        fs = 61.44e6;
        bw = 40e6;
      }
      else AssertFatal(1==0,"Unsupported numerology for mu %d, N_RB %d\n",mu, N_RB_DL);
      break;
    case 3:
      frame_parms->Lmax = 64;
      scs = 120000;
      if (N_RB_DL == 66) {
        fs = 122.88e6;
        bw = 100e6;
      }
      else AssertFatal(1 == 0,"Unsupported numerology for mu %d, N_RB %d\n", mu, N_RB_DL);
      break;
  }

  channel_desc_t *gNB2UE = new_channel_desc_scm(n_tx, n_rx, channel_model, fs, bw, 300e-9, 0, 0, 0, 0);
  AssertFatal(gNB2UE, "Problem generating channel model. Exiting.\n");
  int frame_length_complex_samples = frame_parms->samples_per_subframe * NR_NUMBER_OF_SUBFRAMES_PER_FRAME;
  double **s_re = malloc(2 * sizeof(double*));
  double **s_im = malloc(2 * sizeof(double*));
  double **r_re = malloc(2 * sizeof(double*));
  double **r_im = malloc(2 * sizeof(double*));
  int **txdata = calloc(2, sizeof(int*));

  for (int i = 0; i < 2; i++) {
    s_re[i] = malloc16_clear(frame_length_complex_samples * sizeof(double));
    s_im[i] = malloc16_clear(frame_length_complex_samples * sizeof(double));
    r_re[i] = malloc16_clear(frame_length_complex_samples * sizeof(double));
    r_im[i] = malloc16_clear(frame_length_complex_samples * sizeof(double));
    printf("Allocating %d samples for txdata\n", frame_length_complex_samples);
    txdata[i] = malloc16_clear(frame_length_complex_samples * sizeof(int));
  }

  //configure UE
  memcpy(&UE->frame_parms, frame_parms, sizeof(UE->frame_parms));
  if (run_initial_sync == 1) {
    UE->is_synchronized = 0;
  } else {
    UE->is_synchronized = 1;
  }
  UE->UE_fo_compensation = (cfo / scs) != 0.0 ? 1 : 0; // if a frequency offset is set then perform fo estimation and compensation

  if (init_nr_ue_signal(UE, 1) != 0) {
    printf("Error at UE NR initialisation\n");
    exit(-1);
  }

  nr_gold_psbch(UE);
  processingData_L1tx_t msgDataTx;
  if (input_fd == NULL) {
    for (int i = 0; i < frame_parms->Lmax; i++) {
      if((SSB_positions >> i) & 0x01) {
        const int sc_offset = frame_parms->freq_range == nr_FR1 ? ssb_subcarrier_offset<<mu : ssb_subcarrier_offset;
        const int prb_offset = frame_parms->freq_range == nr_FR1 ? UE->nrUE_config.ssb_table.ssb_offset_point_a<<mu : UE->nrUE_config.ssb_table.ssb_offset_point_a << (mu - 2);
        msgDataTx.ssb[i].ssb_pdu.ssb_pdu_rel15.bchPayload = 0x55dd33;
        msgDataTx.ssb[i].ssb_pdu.ssb_pdu_rel15.SsbBlockIndex = i;
        msgDataTx.ssb[i].ssb_pdu.ssb_pdu_rel15.SsbSubcarrierOffset = sc_offset;
        msgDataTx.ssb[i].ssb_pdu.ssb_pdu_rel15.ssbOffsetPointA = prb_offset;
        for (int aa = 0; aa < gNB->frame_parms.nb_antennas_tx; aa++)
          memset(gNB->common_vars.txdataF[aa], 0, frame_parms->samples_per_slot_wCP * sizeof(int32_t));

        int frame = 0;
        int slot = nr_get_ssb_start_symbol(frame_parms, i) / 14;
        nr_common_signal_procedures(gNB, frame, slot, msgDataTx.ssb[i].ssb_pdu);
        for (int aa = 0; aa < gNB->frame_parms.nb_antennas_tx; aa++) {
          apply_nr_rotation(frame_parms,
                            (int16_t*)gNB->common_vars.txdataF[aa],
                            slot, 0, 14);
          PHY_ofdm_mod(gNB->common_vars.txdataF[aa],
                        (int*)&txdata[aa][frame_parms->get_samples_slot_timestamp(slot, frame_parms, 0)],
                        frame_parms->ofdm_symbol_size,
                        1, frame_parms->nb_prefix_samples0, CYCLIC_PREFIX);
          PHY_ofdm_mod(&gNB->common_vars.txdataF[aa][frame_parms->ofdm_symbol_size],
                        (int*)&txdata[aa][frame_parms->get_samples_slot_timestamp(slot,frame_parms,0)+frame_parms->nb_prefix_samples0+frame_parms->ofdm_symbol_size],
                        frame_parms->ofdm_symbol_size,
                        13, frame_parms->nb_prefix_samples, CYCLIC_PREFIX);
        }
      }
    }
    int frame_length_complex_samples_no_prefix = frame_parms->samples_per_subframe_wCP;
    LOG_M("txsigF0.m", "txsF0", gNB->common_vars.txdataF[0], frame_length_complex_samples_no_prefix, 1, 1);
    if (gNB->frame_parms.nb_antennas_tx > 1)
      LOG_M("txsigF1.m", "txsF1", gNB->common_vars.txdataF[1], frame_length_complex_samples_no_prefix, 1, 1);

  } else {
    printf("Reading %d samples from file to antenna buffer 0\n", frame_length_complex_samples);
    UE->UE_fo_compensation = 1;
    if (fread(txdata[0], sizeof(int32_t), frame_length_complex_samples, input_fd) != frame_length_complex_samples) {
      printf("error reading from file\n");
    }
  }

  LOG_M("txsig0.m","txs0", txdata[0],frame_length_complex_samples, 1, 1);
  if (gNB->frame_parms.nb_antennas_tx>1)
    LOG_M("txsig1.m","txs1", txdata[1],frame_length_complex_samples, 1, 1);

  int n_errors = 0;
  for (double SNR = snr0; SNR < snr1; SNR += 0.2) {
    n_errors = 0;
    int n_errors_payload = 0;

    for (int trial = 0; trial < n_trials; trial++) {
      for (int i = 0; i<frame_length_complex_samples; i++) {
        for (int aa = 0; aa < frame_parms->nb_antennas_tx; aa++) {
          r_re[aa][i] = ((double)(((short *)txdata[aa]))[(i<<1)]);
          r_im[aa][i] = ((double)(((short *)txdata[aa]))[(i<<1)+1]);
        }
      }

      //AWGN
      double ip = 0.0;
      if ((cfo / scs) != 0.0) {
        rf_rx(r_re,  // real part of txdata
              r_im,  // imag part of txdata
              NULL,  // interference real part
              NULL, // interference imag part
              0,  // interference power
              frame_parms->nb_antennas_rx,  // number of rx antennas
              frame_length_complex_samples,  // number of samples in frame
              1.0e9/fs,   //sampling time (ns)
              cfo,	// frequency offset in Hz
              0.0, // drift (not implemented)
              0.0, // noise figure (not implemented)
              0.0, // rx gain in dB ?
              200, // 3rd order non-linearity in dB ?
              &ip, // initial phase
              30.0e3,  // phase noise cutoff in kHz
              -500.0, // phase noise amplitude in dBc
              0.0,  // IQ imbalance (dB),
	            0.0); // IQ phase imbalance (rad)
      }

      for (int i = 0; i < frame_length_complex_samples; i++) {
        double sigma2_dB = 20 * log10((double)AMP / 4) - SNR;
        double sigma2 = pow(10, sigma2_dB / 10);
        for (int aa = 0; aa < frame_parms->nb_antennas_rx; aa++) {
          ((short*) UE->common_vars.rxdata[aa])[2*i]   = (short) ((r_re[aa][i] + sqrt(sigma2 / 2) * gaussdouble(0.0, 1.0)));
          ((short*) UE->common_vars.rxdata[aa])[2*i+1] = (short) ((r_im[aa][i] + sqrt(sigma2 / 2) * gaussdouble(0.0, 1.0)));
        }
      }

      if (n_trials == 1) {
        LOG_M("rxsig0.m","rxs0", UE->common_vars.rxdata[0],frame_parms->samples_per_frame, 1, 1);
        if (gNB->frame_parms.nb_antennas_tx > 1)
          LOG_M("rxsig1.m","rxs1", UE->common_vars.rxdata[1],frame_parms->samples_per_frame, 1, 1);
      }

      int ret;
      if (UE->is_synchronized == 0) {
        UE_nr_rxtx_proc_t proc = {0};
        ret = nr_sl_initial_sync(&proc, UE, 1);
        printf("nr_sl_initial_sync1 returns %d\n", ret);
        if (ret < 0) {
          n_errors++;
        }
      } else {
        UE_nr_rxtx_proc_t proc = {0};
        UE->rx_offset = 0;
        uint8_t ssb_index = 0;
        const int estimateSz = 7 * 2 * sizeof(int) * frame_parms->ofdm_symbol_size;
        __attribute__ ((aligned(32))) struct complex16 dl_ch_estimates[frame_parms->nb_antennas_rx][estimateSz];
        __attribute__ ((aligned(32))) struct complex16 dl_ch_estimates_time[frame_parms->nb_antennas_rx][estimateSz];
        while (!((SSB_positions >> ssb_index) & 0x01)) {
          ssb_index++;  // to select the first transmitted ssb
        }
        UE->symbol_offset = nr_get_ssb_start_symbol(frame_parms,ssb_index);
        uint8_t n_hf = 0;
        int ssb_slot = (UE->symbol_offset / 14) + (n_hf * (frame_parms->slots_per_frame >> 1));
        for (int i = UE->symbol_offset + 1; i < UE->symbol_offset + 4; i++) {
          nr_slot_fep(UE, &proc, i % frame_parms->symbols_per_slot, ssb_slot);
          nr_psbch_channel_estimation(UE,estimateSz, dl_ch_estimates, dl_ch_estimates_time, &proc,
              0, ssb_slot, i % frame_parms->symbols_per_slot, i - (UE->symbol_offset+1), ssb_index % 8, n_hf);
        }
        fapiPbch_t result;
        /* Side link rx PSBCH */
        ret = 0;
#if 0
        ret = nr_rx_psbch(UE,
                          &proc,
                          estimateSz,
                          dl_ch_estimates,
                          UE->psbch_vars[0],
                          frame_parms,
                          0,
                          ssb_index%8,
                          SISO,
                          &phy_pdcch_config,
                          &result);
#endif
        if (ret == 0) {
          int payload_ret = 0;
          uint8_t gNB_xtra_byte = 0;
          for (int i = 0; i < 8; i++)
            gNB_xtra_byte |= ((gNB->psbch.psbch_a >> (31 - i)) & 1) << (7 - i);
          payload_ret = (result.xtra_byte == gNB_xtra_byte);
          for (int i = 0; i < 3; i++)
            payload_ret += (result.decoded_output[i] == ((msgDataTx.ssb[ssb_index].ssb_pdu.ssb_pdu_rel15.bchPayload >> (8 * i)) & 0xff));
          if (payload_ret != 4)
            n_errors_payload++;
        }
        if (ret != 0) {
          n_errors++;
        }
      }
    } //noise trials
    printf("SNR %f: trials %d, n_errors_crc = %d, n_errors_payload %d\n", SNR, n_trials, n_errors, n_errors_payload);
    if (((float)n_errors / (float)n_trials <= target_error_rate) && (n_errors_payload == 0)) {
      printf("PSBCH test OK\n");
      break;
    }
  } // NSR

  free_channel_desc_scm(gNB2UE);
  phy_free_nr_gNB(gNB);
  term_nr_ue_signal(UE, 1);
  free(UE);

  for (int i = 0; i < 2; i++) {
    free(s_re[i]);
    free(s_im[i]);
    free(r_re[i]);
    free(r_im[i]);
    free(txdata[i]);
  }
  free(s_re);
  free(s_im);
  free(r_re);
  free(r_im);
  free(txdata);

  if (input_fd)
    fclose(input_fd);

  loader_reset();
  logTerm();
#endif
  return 0;
}