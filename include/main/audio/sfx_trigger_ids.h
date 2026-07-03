#ifndef MAIN_AUDIO_SFX_TRIGGER_IDS_H_
#define MAIN_AUDIO_SFX_TRIGGER_IDS_H_

/* SFX *trigger* IDs (index into audio/data/Sfx.bin), as passed to
   Sfx_PlayFromObject / Sfx_*LoopedObjectSound. Names are DERIVED from the
   MusyX sound each trigger plays (see comment); refine to gameplay-context
   names per file as desired. Values are authoritative. */

#define SFXTRIG_foot                    0x10   /* plays SFXfoot_stone_scuff, SFXfoot_wood_land, SFXfoot_wood_scuff, SFXfoot_climb_1 */
#define SFXTRIG_foot_var                0x11   /* plays SFXfoot_climb_2, SFXfoot_climb_3, SFXfoot_climb_4, SFXfoot_ladder1 */
#define SFXTRIG_pullup2                 0x12   /* plays SFXkr_pullup2, SFXkr_scream1, SFXkr_climb1, SFXkr_climb2 */
#define SFXTRIG_land                    0x13   /* plays SFXkr_land1, SFXkr_land2 */
#define SFXTRIG_attack                  0x14   /* plays SFXsc_attack01, SFXsc_attack02, SFXsc_attack03, SFXsc_attack04 */
#define SFXTRIG_death01                 0x15   /* plays SFXsc_death01, SFXsc_death02, SFXsc_gethit01 */
#define SFXTRIG_gethit02                0x16   /* plays SFXsc_gethit02, SFXsc_gethit03, SFXsc_gethit04, SFXsc_mumble01 */
#define SFXTRIG_spotfox01               0x19   /* plays SFXsc_spotfox01 */
#define SFXTRIG_sswsh                   0x1a   /* plays SFXwp_sswsh1_c, SFXwp_sswsh2_c, SFXwp_sswsh3_c */
#define SFXTRIG_fox                     0x1e   /* plays SFXfox_swimstroke322, SFXfox_swimstroke422, SFXfox_outofwater122 */
#define SFXTRIG_foxcom                  0x1f   /* plays SFXfoxcom_decoy, SFXfoxcom_find, SFXfoxcom_flame */
#define SFXTRIG_stftest                 0x22   /* plays SFXwp_stftest122, SFXwp_stftest222, SFXwp_stftest322 */
#define SFXTRIG_sabrepush163            0x24   /* plays SFXsp_sabrepush163, SFXsp_sabrepush164, SFXsp_sa_climb01 */
#define SFXTRIG_watery_bubble           0x28   /* plays SFXwatery_bubble1, SFXwatery_bubble2 */
#define SFXTRIG_sa_def01                0x29   /* plays SFXsp_sa_def01 */
#define SFXTRIG_sa_jump03               0x2a   /* plays SFXsp_sa_jump03, SFXsp_sa_off01 */
#define SFXTRIG_literun116              0x2b   /* plays SFXsp_literun116, SFXsp_literun117, SFXsp_rgarb3_c, SFXsp_rgarb4_c */
#define SFXTRIG_fox_swimstroke222       0x2f   /* plays SFXfox_swimstroke222 */
#define SFXTRIG_id_31                   0x31   /* no direct sound (looped/special) */
#define SFXTRIG_gcexp1_c                0x38   /* plays SFXwp_gcexp1_c */
#define SFXTRIG_id_47                   0x47   /* no direct sound (looped/special) */
#define SFXTRIG_crtsmsh6                0x48   /* plays SFXwp_crtsmsh6 */
#define SFXTRIG_lockoff22               0x49   /* plays SFXsc_lockoff22 */
#define SFXTRIG_dsmk2_c                 0x4a   /* plays SFXwp_dsmk2_c */
#define SFXTRIG_littletink22            0x4b   /* plays SFXen_littletink22 */
#define SFXTRIG_cam90_c                 0x58   /* plays SFXsc_cam90_c */
#define SFXTRIG_ladderslide16           0x5c   /* plays SFXmv_ladderslide16 */
#define SFXTRIG_neonbuzzlp16            0x5d   /* plays SFXen_neonbuzzlp16 */
#define SFXTRIG_id_5e                   0x5e   /* no direct sound (looped/special) */
#define SFXTRIG_birdymornin11           0x64   /* plays SFXen_birdymornin11 */
#define SFXTRIG_espar5_c                0x65   /* plays SFXwp_espar5_c */
#define SFXTRIG_treedrum16              0x66   /* plays SFXen_treedrum16 */
#define SFXTRIG_curtainopen16           0x68   /* plays SFXmv_curtainopen16 */
#define SFXTRIG_barrel_throw            0x6b   /* plays SFXbarrel_throw */
#define SFXTRIG_id_6c                   0x6c   /* no direct sound (looped/special) */
#define SFXTRIG_vineclimb116            0x6d   /* plays SFXmv_vineclimb116 */
#define SFXTRIG_mushdizzylp12           0x72   /* plays SFXmv_mushdizzylp12 */
#define SFXTRIG_id_73                   0x73   /* no direct sound (looped/special) */
#define SFXTRIG_id_74                   0x74   /* no direct sound (looped/special) */
#define SFXTRIG_id_75                   0x75   /* no direct sound (looped/special) */
#define SFXTRIG_id_76                   0x76   /* no direct sound (looped/special) */
#define SFXTRIG_id_7b                   0x7b   /* no direct sound (looped/special) */
#define SFXTRIG_id_7c                   0x7c   /* no direct sound (looped/special) */
#define SFXTRIG_mpick1_b                0x7e   /* plays SFXsc_mpick1_b */
#define SFXTRIG_en_treedrum16           0x7f   /* plays SFXen_treedrum16 */
#define SFXTRIG_cvdrip1c                0x80   /* plays SFXen_cvdrip1c */
#define SFXTRIG_crf_babyambi2           0x96   /* plays SFXcrf_babyambi2 */
#define SFXTRIG_crf_babyambi3           0x97   /* plays SFXcrf_babyambi3 */
#define SFXTRIG_wmap_swoosh             0x98   /* plays SFXwmap_swoosh */
#define SFXTRIG_wmap_greatfox_lp        0x99   /* plays SFXwmap_greatfox_lp */
#define SFXTRIG_diallp_c                0x9a   /* plays SFXen_diallp_c */
#define SFXTRIG_cagelp_c                0x9b   /* plays SFXmv_cagelp_c */
#define SFXTRIG_id_9c                   0x9c   /* no direct sound (looped/special) */
#define SFXTRIG_mv_ladderslide16        0x9d   /* plays SFXmv_ladderslide16 */
#define SFXTRIG_forcecryslp11           0x9e   /* plays SFXen_forcecryslp11 */
#define SFXTRIG_mushrele16              0xa0   /* plays SFXen_mushrele16 */
#define SFXTRIG_hitpos_6                0xaf   /* plays SFXwp_hitpos_6 */
#define SFXTRIG_npu_216                 0xb3   /* plays SFXsc_npu_216 */
#define SFXTRIG_id_b6                   0xb6   /* no direct sound (looped/special) */
#define SFXTRIG_majring2                0xb7   /* plays SFXen_majring2 */
#define SFXTRIG_foot_water_walk_1       0xba   /* plays SFXfoot_water_walk_1 */
#define SFXTRIG_wp_crtsmsh6             0xd0   /* plays SFXwp_crtsmsh6 */
#define SFXTRIG_barrel_putdown          0xd2   /* plays SFXbarrel_putdown */
#define SFXTRIG_id_ef                   0xef   /* no direct sound (looped/special) */
#define SFXTRIG_id_f0                   0xf0   /* no direct sound (looped/special) */
#define SFXTRIG_crthit6                 0xf1   /* plays SFXwp_crthit6 */
#define SFXTRIG_menu_fox_exit           0xf5   /* plays SFXmenu_fox_exit */
#define SFXTRIG_menu_fox_inventory_up   0xf7   /* plays SFXmenu_fox_inventory_up */
#define SFXTRIG_npu_116                 0xfb   /* plays SFXsc_npu_116 */
#define SFXTRIG_warningloop             0xfc   /* plays SFXar_warningloop */
#define SFXTRIG_noboost                 0xfd   /* plays SFXar_noboost */
#define SFXTRIG_wmap_name               0x100  /* plays SFXwmap_name */
#define SFXTRIG_lwfl1_c                 0x107  /* plays SFXen_lwfl1_c */
#define SFXTRIG_en_diallp_c             0x108  /* plays SFXen_diallp_c */
#define SFXTRIG_menuups16k              0x109  /* plays SFXsc_menuups16k */
#define SFXTRIG_id_10a                  0x10a  /* no direct sound (looped/special) */
#define SFXTRIG_id_10c                  0x10c  /* no direct sound (looped/special) */
#define SFXTRIG_en_cvdrip1c             0x10f  /* plays SFXen_cvdrip1c */
#define SFXTRIG_id_111                  0x111  /* no direct sound (looped/special) */
#define SFXTRIG_id_116                  0x116  /* no direct sound (looped/special) */
#define SFXTRIG_sliftloop11             0x11d  /* plays SFXmv_sliftloop11 */
#define SFXTRIG_gscsc                   0x11f  /* plays SFXdn_gscsc1_c, SFXdn_gscsc2_c */
#define SFXTRIG_earthhuff               0x121  /* plays SFXdn_earthhuff111, SFXdn_earthhuff211 */
#define SFXTRIG_swdtest222              0x129  /* plays SFXwp_swdtest222 */
#define SFXTRIG_gland2_c                0x12a  /* plays SFXen_gland2_c */
#define SFXTRIG_sdrstp_c                0x12b  /* plays SFXen_sdrstp_c */
#define SFXTRIG_en_sdrstp_c             0x12c  /* plays SFXen_sdrstp_c */
#define SFXTRIG_en_sdrstp_c_12d         0x12d  /* plays SFXen_sdrstp_c */
#define SFXTRIG_trwhin4                 0x134  /* plays SFXsk_trwhin4, SFXsk_doggydig11, SFXsk_trwhin2, SFXsk_trwhin3, SFXsp_literun112, SFXsp_literun113 */
#define SFXTRIG_literun116_var          0x13a  /* plays SFXsp_literun116, SFXsp_literun117, SFXsp_rgarb3_c, SFXsp_rgarb4_c */
#define SFXTRIG_trwhin1                 0x13d  /* plays SFXsk_trwhin1 */
#define SFXTRIG_propsp_6                0x13f  /* plays SFXmv_propsp_6 */
#define SFXTRIG_cagesqk11               0x140  /* plays SFXmv_cagesqk11 */
#define SFXTRIG_wickhit16               0x141  /* plays SFXmv_wickhit16 */
#define SFXTRIG_id_14b                  0x14b  /* no direct sound (looped/special) */
#define SFXTRIG_sa_off                  0x14c  /* plays SFXsp_sa_off02, SFXsp_sa_off03 */
#define SFXTRIG_id_14d                  0x14d  /* no direct sound (looped/special) */
#define SFXTRIG_id_14f                  0x14f  /* no direct sound (looped/special) */
#define SFXTRIG_skeep_mumb              0x150  /* plays SFXsp_skeep_mumb1, SFXsp_skeep_mumb2 */
#define SFXTRIG_bapt11_c                0x16a  /* plays SFXsk_bapt11_c */
#define SFXTRIG_baptr1_c                0x16c  /* plays SFXsk_baptr1_c */
#define SFXTRIG_wp_hitpos_6             0x16d  /* plays SFXwp_hitpos_6 */
#define SFXTRIG_iceywindlp16            0x16f  /* plays SFXwp_iceywindlp16 */
#define SFXTRIG_sc_menuups16k           0x170  /* plays SFXsc_menuups16k */
#define SFXTRIG_liftloop                0x1cb  /* plays SFXmv_liftloop */
#define SFXTRIG_wp_iceywindlp16         0x1d4  /* plays SFXwp_iceywindlp16 */
#define SFXTRIG_cnplarlp                0x1fe  /* plays SFXtr_cnplarlp */
#define SFXTRIG_gal_sailflap2           0x1ff  /* plays SFXtr_gal_sailflap2 */
#define SFXTRIG_gal_sailflap1           0x201  /* plays SFXtr_gal_sailflap1 */
#define SFXTRIG_tr_cnplarlp             0x202  /* plays SFXtr_cnplarlp */
#define SFXTRIG_sexpl2_c                0x203  /* plays SFXwp_sexpl2_c */
#define SFXTRIG_foot_crawl2             0x20d  /* plays SFXfoot_crawl2 */
#define SFXTRIG_fox_bigfallgrunt2       0x20e  /* plays SFXfox_bigfallgrunt2 */
#define SFXTRIG_foot_ladder2            0x20f  /* plays SFXfoot_ladder2 */
#define SFXTRIG_staff_boulder_drops     0x21b  /* plays SFXstaff_boulder_drops */
#define SFXTRIG_en_diallp_c_223         0x223  /* plays SFXen_diallp_c */
#define SFXTRIG_swd                     0x239  /* plays SFXwp_swdout1, SFXwp_swdstone16, SFXwp_swdtest122 */
#define SFXTRIG_id_23b                  0x23b  /* no direct sound (looped/special) */
#define SFXTRIG_robolaser16             0x23c  /* plays SFXwp_robolaser16 */
#define SFXTRIG_fball2_c                0x23d  /* plays SFXwp_fball2_c */
#define SFXTRIG_swd_var                 0x23e  /* plays SFXwp_swdout1, SFXwp_swdstone16, SFXwp_swdtest122 */
#define SFXTRIG_stftest_var             0x23f  /* plays SFXwp_stftest122, SFXwp_stftest222, SFXwp_stftest322 */
#define SFXTRIG_id_249                  0x249  /* no direct sound (looped/special) */
#define SFXTRIG_id_24a                  0x24a  /* no direct sound (looped/special) */
#define SFXTRIG_baddie_kooshy_hit       0x24b  /* plays SFXbaddie_kooshy_hit */
#define SFXTRIG_baddie_kooshy_death     0x24c  /* plays SFXbaddie_kooshy_death */
#define SFXTRIG_swdout1                 0x255  /* plays SFXwp_swdout1 */
#define SFXTRIG_scream1                 0x257  /* plays SFXkr_scream1 */
#define SFXTRIG_whiz3_c                 0x278  /* plays SFXwp_whiz3_c */
#define SFXTRIG_lummy311                0x279  /* plays SFXmn_lummy311 */
#define SFXTRIG_id_281                  0x281  /* no direct sound (looped/special) */
#define SFXTRIG_id_282                  0x282  /* no direct sound (looped/special) */
#define SFXTRIG_blkscrp6                0x285  /* plays SFXen_blkscrp6, SFXen_cavedirt22 */
#define SFXTRIG_shop_priceup            0x28b  /* plays SFXsc_shop_priceup */
#define SFXTRIG_barrelgrabber_suck      0x2c9  /* plays SFXtr_barrelgrabber_suck */
#define SFXTRIG_foxcom_heel             0x2cb  /* plays SFXfoxcom_heel */
#define SFXTRIG_impact3                 0x2d3  /* plays SFXkr_impact3 */
#define SFXTRIG_id_2df                  0x2df  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e2                  0x2e2  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e3                  0x2e3  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e5                  0x2e5  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e6                  0x2e6  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e7                  0x2e7  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e8                  0x2e8  /* no direct sound (looped/special) */
#define SFXTRIG_id_2e9                  0x2e9  /* no direct sound (looped/special) */
#define SFXTRIG_swapstone_move_long     0x2f1  /* plays SFXswapstone_move_long */
#define SFXTRIG_swapstone_move_short    0x2f4  /* plays SFXswapstone_move_short */
#define SFXTRIG_awghitobj16             0x2f9  /* plays SFXar_awghitobj16 */
#define SFXTRIG_fox_var                 0x318  /* plays SFXfox_quakecry1, SFXfox_watergasp1, SFXfox_climbgrunt1, SFXfox_climbgrunt2 */
#define SFXTRIG_foxcom_decoy            0x327  /* plays SFXfoxcom_decoy */
#define SFXTRIG_foot_33a                0x33a  /* plays SFXfoot_ice_run_2, SFXfoot_ice_run_3, SFXfoot_ice_run_4, SFXfoot_metal_walk_1 */
#define SFXTRIG_spirit_voice            0x343  /* plays SFXspirit_voice1, SFXspirit_voice2, SFXspirit_voice3, SFXspirit_voice4 */
#define SFXTRIG_spirit_basketspin       0x344  /* plays SFXspirit_basketspin */
#define SFXTRIG_spirit_voice_var        0x345  /* plays SFXspirit_voice1, SFXspirit_voice2, SFXspirit_voice3, SFXspirit_voice4 */
#define SFXTRIG_newtricky_01j           0x357  /* plays SFXnewtricky_01j */
#define SFXTRIG_en_littletink22         0x366  /* plays SFXen_littletink22 */
#define SFXTRIG_watery_bubble3          0x367  /* plays SFXwatery_bubble3, SFXfox_bigfallgrunt1, SFXfox_climbgrunt3, SFXfox_climbgrunt4 */
#define SFXTRIG_fend_fox_keytap         0x368  /* plays SFXfend_fox_keytap1, SFXfend_fox_keytap2, SFXfend_fox_keytap3 */
#define SFXTRIG_fend_rob_servo1         0x369  /* plays SFXfend_rob_servo1 */
#define SFXTRIG_fend_rob_servo2         0x36a  /* plays SFXfend_rob_servo2 */
#define SFXTRIG_fend_slip_kickbox       0x36b  /* plays SFXfend_slip_kickbox */
#define SFXTRIG_fend_pep_snorein        0x36c  /* plays SFXfend_pep_snorein */
#define SFXTRIG_fend_pep_wakeup         0x36d  /* plays SFXfend_pep_wakeup */
#define SFXTRIG_snort                   0x36e  /* plays SFXsc_snort03, SFXsc_snort04 */
#define SFXTRIG_baddie_mika_death       0x36f  /* plays SFXbaddie_mika_death */
#define SFXTRIG_fend_pep_snoreout       0x370  /* plays SFXfend_pep_snoreout */
#define SFXTRIG_mammoth_grunt           0x374  /* plays SFXmammoth_grunt2, SFXmammoth_grunt3 */
#define SFXTRIG_thorntail_chew1         0x375  /* plays SFXthorntail_chew1, SFXttail_queen_breathout */
#define SFXTRIG_recrate_hit             0x376  /* plays SFXrecrate_hit */
#define SFXTRIG_staff_rapidfire         0x377  /* plays SFXstaff_rapidfire */
#define SFXTRIG_foot_ladder3            0x378  /* plays SFXfoot_ladder3, SFXfoot_ladder4, SFXfox_standsup, SFXfoot_crawl1 */
#define SFXTRIG_sa_jump02               0x379  /* plays SFXsp_sa_jump02 */
#define SFXTRIG_menu_fox_select         0x37b  /* plays SFXmenu_fox_select */
#define SFXTRIG_laser_pickup            0x37c  /* plays SFXar_laser_pickup */
#define SFXTRIG_staff_rocket_powerup    0x37e  /* plays SFXstaff_rocket_powerup */
#define SFXTRIG_bomb_pickup             0x37f  /* plays SFXar_bomb_pickup */
#define SFXTRIG_barrelblow11            0x380  /* plays SFXen_barrelblow11 */
#define SFXTRIG_generic_pickup          0x381  /* plays SFXar_generic_pickup */
#define SFXTRIG_whit3_c                 0x382  /* plays SFXwp_whit3_c */
#define SFXTRIG_sml_trex_snap3          0x383  /* plays SFXmn_sml_trex_snap3 */
#define SFXTRIG_mammoth_snowstep        0x38a  /* plays SFXmammoth_snowstep */
#define SFXTRIG_mammoth_annoyed         0x38b  /* plays SFXmammoth_annoyed */
#define SFXTRIG_scabshort32             0x38d  /* plays SFXsc_scabshort32 */
#define SFXTRIG_en_cvdrip1c_393         0x393  /* plays SFXen_cvdrip1c */
#define SFXTRIG_foot_metal_scuff        0x394  /* plays SFXfoot_metal_scuff */
#define SFXTRIG_foot_metal_land         0x395  /* plays SFXfoot_metal_land */
#define SFXTRIG_clock_loop              0x397  /* plays SFXsc_clock_loop */
#define SFXTRIG_jump3                   0x398  /* plays SFXkr_jump3, SFXkr_panting1 */
#define SFXTRIG_weetinkoneshot          0x39b  /* plays SFXen_weetinkoneshot */
#define SFXTRIG_commsbleep              0x3a8  /* plays SFXsc_commsbleep */
#define SFXTRIG_baddie_rach_call3       0x3ac  /* plays SFXbaddie_rach_call3 */
#define SFXTRIG_cflap2_c                0x3ad  /* plays SFXmv_cflap2_c */
#define SFXTRIG_blockscrape_lp          0x3af  /* plays SFXmv_blockscrape_lp */
#define SFXTRIG_thorntail_chew2         0x3b3  /* plays SFXthorntail_chew2 */
#define SFXTRIG_pda_compassbeep         0x3b9  /* plays SFXpda_compassbeep */
#define SFXTRIG_jbike_bombbeep          0x3bb  /* plays SFXtr_jbike_bombbeep */
#define SFXTRIG_tr_jbike_bombbeep       0x3bc  /* plays SFXtr_jbike_bombbeep */
#define SFXTRIG_bcrek1_c                0x3be  /* plays SFXtr_bcrek1_c */
#define SFXTRIG_jbike_snowspray         0x3bf  /* plays SFXtr_jbike_snowspray */
#define SFXTRIG_jbike_boost             0x3c0  /* plays SFXtr_jbike_boost */
#define SFXTRIG_foot_ice_scuff          0x3c2  /* plays SFXfoot_ice_scuff, SFXchar_on_firelp, SFXchar_puts_out_fire, SFXfoot_run_jingle1 */
#define SFXTRIG_staff_lever             0x3c3  /* plays SFXstaff_lever */
#define SFXTRIG_en_littletink22_3c4     0x3c4  /* plays SFXen_littletink22 */
#define SFXTRIG_cahit2_c                0x3c8  /* plays SFXwp_cahit2_c */
#define SFXTRIG_ar_awghitobj16          0x3cc  /* plays SFXar_awghitobj16 */
#define SFXTRIG_rserv1_c                0x3cd  /* plays SFXwp_rserv1_c */
#define SFXTRIG_and_swipe1              0x3d8  /* plays SFXand_swipe1 */
#define SFXTRIG_barrel_timerbeep        0x3da  /* plays SFXbarrel_timerbeep */
#define SFXTRIG_en_cvdrip1c_3db         0x3db  /* plays SFXen_cvdrip1c */
#define SFXTRIG_trpopn_c                0x3dc  /* plays SFXen_trpopn_c */
#define SFXTRIG_en_cvdrip1c_3dd         0x3dd  /* plays SFXen_cvdrip1c */
#define SFXTRIG_wp_dsmk2_c              0x3e1  /* plays SFXwp_dsmk2_c */
#define SFXTRIG_headcam_in              0x3e4  /* plays SFXsc_headcam_in */
#define SFXTRIG_menu_fox_sidekick_up    0x3e5  /* plays SFXmenu_fox_sidekick_up */
#define SFXTRIG_mammoth                 0x3e6  /* plays SFXmammoth_slurp, SFXmammoth_woodstep */
#define SFXTRIG_baddie_rach_death       0x3e8  /* plays SFXbaddie_rach_death */
#define SFXTRIG_baddie_eba              0x3e9  /* plays SFXbaddie_eba_death, SFXbaddie_eba_hit, SFXbaddie_eba_leavesclose */
#define SFXTRIG_baddie_eba_leavesopen   0x3ea  /* plays SFXbaddie_eba_leavesopen */
#define SFXTRIG_pda_compassbeep_3f0     0x3f0  /* plays SFXpda_compassbeep */
#define SFXTRIG_and_suck_lp             0x3f1  /* plays SFXand_suck_lp */
#define SFXTRIG_menu_fox_weapons_up     0x3f2  /* plays SFXmenu_fox_weapons_up */
#define SFXTRIG_shop_pricedown          0x3f3  /* plays SFXsc_shop_pricedown */
#define SFXTRIG_and_swipe2              0x3f4  /* plays SFXand_swipe2 */
#define SFXTRIG_and_missilelaunch       0x3f5  /* plays SFXand_missilelaunch */
#define SFXTRIG_baddie_eggsnatch_sniff2 0x3fd  /* plays SFXbaddie_eggsnatch_sniff2 */
#define SFXTRIG_pk_staff_fizz           0x3fe  /* plays SFXpk_staff_fizz */
#define SFXTRIG_headcam_out             0x3ff  /* plays SFXsc_headcam_out */
#define SFXTRIG_strafe_active           0x400  /* plays SFXsc_strafe_active */
#define SFXTRIG_lockon2_off             0x401  /* plays SFXsc_lockon2_off */
#define SFXTRIG_lockon2_on              0x402  /* plays SFXsc_lockon2_on */
#define SFXTRIG_pk_fuelcell_fizz        0x403  /* plays SFXpk_fuelcell_fizz */
#define SFXTRIG_foot_run_jingle4        0x404  /* plays SFXfoot_run_jingle4 */
#define SFXTRIG_pda_fper_move           0x405  /* plays SFXpda_fper_move */
#define SFXTRIG_scarab_runloop          0x406  /* plays SFXscarab_runloop */
#define SFXTRIG_pk_fruit_lands          0x407  /* plays SFXpk_fruit_lands */
#define SFXTRIG_menu_spin               0x408  /* plays SFXmenu_spin */
#define SFXTRIG_sc_menuups16k_409       0x409  /* plays SFXsc_menuups16k */
#define SFXTRIG_staff_swipes_short      0x40b  /* plays SFXstaff_swipes_short */
#define SFXTRIG_staff_swipes_long       0x40c  /* plays SFXstaff_swipes_long */
#define SFXTRIG_thorntail               0x410  /* plays SFXthorntail_footstep, SFXthorntail_injured1 */
#define SFXTRIG_fend_rob_armout         0x412  /* plays SFXfend_rob_armout */
#define SFXTRIG_fend_rob_armin          0x413  /* plays SFXfend_rob_armin */
#define SFXTRIG_fend_rob_wave           0x414  /* plays SFXfend_rob_wave */
#define SFXTRIG_swapstone_mumble        0x416  /* plays SFXswapstone_mumble */
#define SFXTRIG_swapstone_yawn          0x417  /* plays SFXswapstone_yawn */
#define SFXTRIG_menu_pause_up           0x418  /* plays SFXmenu_pause_up */
#define SFXTRIG_menu_pause_down         0x419  /* plays SFXmenu_pause_down */
#define SFXTRIG_menu_fend_forward       0x41b  /* plays SFXmenu_fend_forward */
#define SFXTRIG_menu_fend_back          0x41c  /* plays SFXmenu_fend_back */
#define SFXTRIG_fened_pep_yawn          0x41d  /* plays SFXfened_pep_yawn */
#define SFXTRIG_mfin2_c                 0x41e  /* plays SFXwp_mfin2_c, SFXwp_roboalarm, SFXwp_fox_kick1 */
#define SFXTRIG_id_420                  0x420  /* no direct sound (looped/special) */
#define SFXTRIG_fend_slip_fingersnap    0x421  /* plays SFXfend_slip_fingersnap */
#define SFXTRIG_fend_rob_beep           0x426  /* plays SFXfend_rob_beep1, SFXfend_rob_beep2, SFXfend_rob_beep3 */
#define SFXTRIG_foot_run_jingle3        0x428  /* plays SFXfoot_run_jingle3 */
#define SFXTRIG_foot_run_jingle3_429    0x429  /* plays SFXfoot_run_jingle3 */
#define SFXTRIG_foot_run_jingle3_42a    0x42a  /* plays SFXfoot_run_jingle3 */
#define SFXTRIG_foot_run_jingle3_42b    0x42b  /* plays SFXfoot_run_jingle3 */
#define SFXTRIG_lrope_powerup           0x42c  /* plays SFXen_lrope_powerup */
#define SFXTRIG_lockon3_on              0x42d  /* plays SFXsc_lockon3_on */
#define SFXTRIG_gal_prophitbird         0x42e  /* plays SFXtr_gal_prophitbird */
#define SFXTRIG_pk_moonseed_rattle      0x438  /* plays SFXpk_moonseed_rattle */
#define SFXTRIG_hightop_call1           0x43a  /* plays SFXhightop_call1, SFXhightop_call2, SFXmammoth_annoyed2, SFXmammoth_breath1 */
#define SFXTRIG_pk_lightcritter_lp      0x43b  /* plays SFXpk_lightcritter_lp */
#define SFXTRIG_skeep_mumb4             0x43c  /* plays SFXsp_skeep_mumb4, SFXsp_mam_getmeout, SFXsp_guardian_call1, SFXsp_guardian_call2, SFXsp_lfoot_treasure, SFXsp_lfoot_taunt2 */
#define SFXTRIG_baddie_weev             0x43f  /* plays SFXbaddie_weev_attack, SFXbaddie_weev_death, SFXbaddie_weev_hit, SFXbaddie_weev_move */
#define SFXTRIG_baddie                  0x440  /* plays SFXbaddie_hits_fox, SFXbaddie_gets_hit, SFXbaddie_invin_hit, SFXbaddie_eba_bigswipe */
#define SFXTRIG_baddie_vambat_death     0x441  /* plays SFXbaddie_vambat_death */
#define SFXTRIG_baddie_eba_smallswipe1  0x442  /* plays SFXbaddie_eba_smallswipe1 */
#define SFXTRIG_statue_waterfall        0x446  /* plays SFXen_statue_waterfall */
#define SFXTRIG_statue_wave             0x447  /* plays SFXen_statue_wave */
#define SFXTRIG_holorays16              0x44b  /* plays SFXms_holorays16 */
#define SFXTRIG_lockon3_off             0x44c  /* plays SFXsc_lockon3_off */
#define SFXTRIG_ar_bomb_pickup          0x44e  /* plays SFXar_bomb_pickup */
#define SFXTRIG_en_diallp_c_450         0x450  /* plays SFXen_diallp_c */
#define SFXTRIG_fox_452                 0x452  /* plays SFXfox_cough1, SFXfox_cough2, SFXfox_bigfallrecover1, SFXfox_fightbreath1 */
#define SFXTRIG_rexelctro11             0x454  /* plays SFXdn_rexelctro11 */
#define SFXTRIG_foot_metal_scuff_455    0x455  /* plays SFXfoot_metal_scuff */
#define SFXTRIG_treadlpc                0x458  /* plays SFXen_treadlpc */
#define SFXTRIG_bblast16                0x45f  /* plays SFXar_bblast16 */
#define SFXTRIG_sc_commsbleep           0x460  /* plays SFXsc_commsbleep */
#define SFXTRIG_lfoot_taunt             0x464  /* plays SFXsp_lfoot_taunt3, SFXsp_lfoot_taunt4 */
#define SFXTRIG_and_missileloop         0x466  /* plays SFXand_missileloop */
#define SFXTRIG_and_roar1               0x467  /* plays SFXand_roar1 */
#define SFXTRIG_and_falcoflyby          0x468  /* plays SFXand_falcoflyby */
#define SFXTRIG_and_spitout             0x469  /* plays SFXand_spitout */
#define SFXTRIG_and_laugh               0x46d  /* plays SFXand_laugh */
#define SFXTRIG_drak_pain1              0x46f  /* plays SFXdrak_pain1 */
#define SFXTRIG_drak_roar1              0x470  /* plays SFXdrak_roar1 */
#define SFXTRIG_and_ring_lp             0x471  /* plays SFXand_ring_lp */
#define SFXTRIG_and_chompf              0x472  /* plays SFXand_chompf */
#define SFXTRIG_rockshat16              0x473  /* plays SFXen_rockshat16 */
#define SFXTRIG_tile_buzzlp             0x475  /* plays SFXen_tile_buzzlp */
#define SFXTRIG_ocean_beamlp            0x476  /* plays SFXen_ocean_beamlp */
#define SFXTRIG__UNK                    0x477  /* plays SFX_UNK_830, SFX_UNK_831 */
#define SFXTRIG__UNK_var                0x478  /* plays SFX_UNK_828, SFX_UNK_829 */
#define SFXTRIG_drak_pain2              0x479  /* plays SFXdrak_pain2 */
#define SFXTRIG_fox_kick2               0x47a  /* plays SFXwp_fox_kick2 */
#define SFXTRIG_barrel_bounce1          0x47b  /* plays SFXwp_barrel_bounce1 */
#define SFXTRIG_hightop_fstep           0x47f  /* plays SFXdn_hightop_fstep */
#define SFXTRIG_waterblock_wave         0x480  /* plays SFXen_waterblock_wave */
#define SFXTRIG_mv_sliftloop11          0x481  /* plays SFXmv_sliftloop11 */
#define SFXTRIG_wmap_nameoff            0x484  /* plays SFXwmap_nameoff */
#define SFXTRIG_en_barrelblow11         0x485  /* plays SFXen_barrelblow11 */
#define SFXTRIG_wp_fball2_c             0x486  /* plays SFXwp_fball2_c */
#define SFXTRIG_lowoxy_beep             0x487  /* plays SFXsc_lowoxy_beep */
#define SFXTRIG_baddie_haga_talk3       0x48e  /* plays SFXbaddie_haga_talk3 */
#define SFXTRIG_firlp6                  0x493  /* plays SFXen_firlp6 */
#define SFXTRIG_gate_stops              0x494  /* plays SFXen_gate_stops */
#define SFXTRIG_wmap_nameoff_496        0x496  /* plays SFXwmap_nameoff */
#define SFXTRIG_wp_sexpl2_c             0x497  /* plays SFXwp_sexpl2_c */
#define SFXTRIG_baddie_haga_death       0x498  /* plays SFXbaddie_haga_death */
#define SFXTRIG_baddie_blooplaugh1      0x499  /* plays SFXbaddie_blooplaugh1 */
#define SFXTRIG_baddie_blooplaugh2      0x49a  /* plays SFXbaddie_blooplaugh2 */
#define SFXTRIG_baddie_blooplaugh3      0x49b  /* plays SFXbaddie_blooplaugh3 */
#define SFXTRIG_baddie_eggsnatch_movelp 0x49c  /* plays SFXbaddie_eggsnatch_movelp */
#define SFXTRIG_baddie_eggsnatch        0x49d  /* plays SFXbaddie_eggsnatch_sniff3, SFXbaddie_eggsnatch_sniff4, SFXbaddie_eggsnatch_carry1 */
#define SFXTRIG_baddie_eggsnatch_carry2 0x49e  /* plays SFXbaddie_eggsnatch_carry2 */
#define SFXTRIG_pda                     0x4a0  /* plays SFXpda_turnon, SFXpda_turnoff, SFXpda_scroll */
#define SFXTRIG_door_creak              0x4a2  /* plays SFXdoor_creak */
#define SFXTRIG_spotfox03               0x4a3  /* plays SFXsc_spotfox03, SFXsc_spotfox04, SFXsc_clubhit01, SFXsc_clubhit02 */
#define SFXTRIG__UNK_832                0x4a6  /* plays SFX_UNK_832 */
#define SFXTRIG_baddie_eggsnatch_carry3 0x4a8  /* plays SFXbaddie_eggsnatch_carry3 */
#define SFXTRIG_baddie_eggsnatch_var    0x4a9  /* plays SFXbaddie_eggsnatch_carry4, SFXbaddie_eggsnatch_eggslide */
#define SFXTRIG_baddie_var              0x4aa  /* plays SFXbaddie_crater_call, SFXbaddie_eggsnatch_start1 */
#define SFXTRIG_en_cvdrip1c_4ae         0x4ae  /* plays SFXen_cvdrip1c */
#define SFXTRIG_mpwru1                  0x4af  /* plays SFXwp_mpwru1 */
#define SFXTRIG_sc_npu_216              0x4b0  /* plays SFXsc_npu_216 */
#define SFXTRIG_wp_mpwru1               0x4b1  /* plays SFXwp_mpwru1 */
#define SFXTRIG_sc_npu_216_4b2          0x4b2  /* plays SFXsc_npu_216 */
#define SFXTRIG_en_barrelblow11_4b6     0x4b6  /* plays SFXen_barrelblow11 */
#define SFXTRIG_wp_sexpl2_c_4b8         0x4b8  /* plays SFXwp_sexpl2_c */
#define SFXTRIG_totem_slide             0x4bc  /* plays SFXmv_totem_slide */
#define SFXTRIG_sc_menuups16k_4bd       0x4bd  /* plays SFXsc_menuups16k */
#define SFXTRIG_htop_hurry1             0x4be  /* plays SFXsp_htop_hurry1, SFXsp_htop_hurry2, SFXtr_cnpltht1, SFXtr_cnshot6, SFXtr_cnflyby6, SFXtr_cndrht11 */
#define SFXTRIG_wp_sexpl2_c_4bf         0x4bf  /* plays SFXwp_sexpl2_c */
#define SFXTRIG_windlift_loop           0x4c0  /* plays SFXms_windlift_loop, SFXmn_cling02 */
#define SFXTRIG_wp_sexpl2_c_4c2         0x4c2  /* plays SFXwp_sexpl2_c */
#define SFXTRIG_id_fff                  0xfff  /* no direct sound (looped/special) */
#define SFXTRIG_id_ffff                 0xffff /* no direct sound (looped/special) */


/* stragglers recovered via full call-site parse */
#define SFXTRIG_rfall5_c                0x56   /* plays SFXen_rfall5_c */
#define SFXTRIG_wp_fball2_c_1c9         0x1c9  /* plays SFXwp_fball2_c */
#define SFXTRIG_swtst1_c                0x2c6  /* plays SFXwp_swtst1_c */


/* ternary-branch triggers */
#define SFXTRIG_sa_climb02              0x26   /* plays SFXsp_sa_climb02 */
#define SFXTRIG_jump2                   0x2d0  /* plays SFXkr_jump2 */

#define SFXTRIG_sabrepush               0x1d   /* plays SFXsp_sabrepush161, SFXsp_sabrepush162 */
#define SFXTRIG_sa_jump03_var           0x27   /* plays SFXsp_sa_jump03, SFXsp_sa_off01 */
#define SFXTRIG_pole1_c                 0x2ce  /* plays SFXwp_pole1_c */
#define SFXTRIG_sa_def                  0x2d4  /* plays SFXsp_sa_def01, SFXsp_sa_def02, SFXsp_sa_def03 */
#define SFXTRIG_foxcom_var              0x2d5  /* plays SFXfoxcom_gogetit, SFXfoxcom_heel, SFXfoxcom_stay */
#define SFXTRIG_panting2                0x399  /* plays SFXkr_panting2, SFXkr_pullup1 */
#define SFXTRIG_wp_pole1_c              0x48c  /* plays SFXwp_pole1_c */

#endif /* MAIN_AUDIO_SFX_TRIGGER_IDS_H_ */
