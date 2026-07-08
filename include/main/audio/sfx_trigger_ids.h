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


/* batch-import correction: sound-effect triggers resolved through Sfx.bin
   (engine looks up by the record's id field; see audio.c Sfx_FindTrigger). */
#define SFXTRIG_sc_mumble02             0x17   /* plays SFXsc_mumble02, SFXsc_mumble03, SFXsc_snort01, SFXsc_snort02 */
#define SFXTRIG_sc_snort03              0x18   /* plays SFXsc_snort03, SFXsc_snort04 */
#define SFXTRIG_sp_sa_def01             0x1b   /* plays SFXsp_sa_def01, SFXsp_sa_def02, SFXsp_sa_def03 */
#define SFXTRIG_wp_pole1_c_23           0x23   /* plays SFXwp_pole1_c */
#define SFXTRIG_wp_swddirt16            0x2c   /* plays SFXwp_swddirt16 */
#define SFXTRIG_fox_fightbreath2        0x2e   /* plays SFXfox_fightbreath2, SFXfox_fightbreath3, SFXfox_fightbreath4, SFXfox_roll1 */
#define SFXTRIG_en_trpopn_c             0x34   /* plays SFXen_trpopn_c */
#define SFXTRIG_en_trpopn_c_35          0x35   /* plays SFXen_trpopn_c */
#define SFXTRIG_wp_gcfir1_c             0x36   /* plays SFXwp_gcfir1_c */
#define SFXTRIG_wp_gcfir1_c_37          0x37   /* plays SFXwp_gcfir1_c */
#define SFXTRIG_sc_npu_216_3f           0x3f   /* plays SFXsc_npu_216 */
#define SFXTRIG_dn_boar1_c              0x40   /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_45           0x45   /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_46           0x46   /* plays SFXdn_boar1_c */
#define SFXTRIG_en_lflsh3_c             0x4c   /* plays SFXen_lflsh3_c */
#define SFXTRIG_dn_boar1_c_4d           0x4d   /* plays SFXdn_boar1_c */
#define SFXTRIG_sc_cam90_c              0x4e   /* plays SFXsc_cam90_c */
#define SFXTRIG_en_tranch_6             0x52   /* plays SFXen_tranch_6 */
#define SFXTRIG_mv_bodyf4_c             0x54   /* plays SFXmv_bodyf4_c */
#define SFXTRIG_en_liftstpc             0x57   /* plays SFXen_liftstpc */
#define SFXTRIG_sc_eatthefood16         0x59   /* plays SFXsc_eatthefood16 */
#define SFXTRIG_en_firlp6               0x61   /* plays SFXen_firlp6 */
#define SFXTRIG_wp_mpwru1_62            0x62   /* plays SFXwp_mpwru1 */
#define SFXTRIG_dn_boar1_c_63           0x63   /* plays SFXdn_boar1_c */
#define SFXTRIG_en_lrope_powerup        0x69   /* plays SFXen_lrope_powerup */
#define SFXTRIG_dn_boar1_c_6a           0x6a   /* plays SFXdn_boar1_c */
#define SFXTRIG_mammoth_grunt1          0x6e   /* plays SFXmammoth_grunt1 */
#define SFXTRIG_dn_boar1_c_70           0x70   /* plays SFXdn_boar1_c */
#define SFXTRIG_wp_crthit6              0x71   /* plays SFXwp_crthit6 */
#define SFXTRIG_dn_boar1_c_77           0x77   /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_78           0x78   /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_79           0x79   /* plays SFXdn_boar1_c */
#define SFXTRIG_wp_espk2_c              0x7a   /* plays SFXwp_espk2_c */
#define SFXTRIG_en_treedrum16_7d        0x7d   /* plays SFXen_treedrum16 */
#define SFXTRIG_en_icecrk16             0x81   /* plays SFXen_icecrk16 */
#define SFXTRIG_wp_beamhit16            0x82   /* plays SFXwp_beamhit16 */
#define SFXTRIG_wp_blaserflyby16        0x83   /* plays SFXwp_blaserflyby16 */
#define SFXTRIG_wp_beamgenlp16          0x84   /* plays SFXwp_beamgenlp16 */
#define SFXTRIG_en_birdymornin11        0x85   /* plays SFXen_birdymornin11 */
#define SFXTRIG_dn_rexroarsht11         0x86   /* plays SFXdn_rexroarsht11 */
#define SFXTRIG_dn_rexroarmed11         0x87   /* plays SFXdn_rexroarmed11 */
#define SFXTRIG_dn_rexroarlng11         0x88   /* plays SFXdn_rexroarlng11 */
#define SFXTRIG_dn_rexexhale16          0x89   /* plays SFXdn_rexexhale16 */
#define SFXTRIG_en_fireup_c             0x8a   /* plays SFXen_fireup_c */
#define SFXTRIG_dn_rexthrash11          0x8b   /* plays SFXdn_rexthrash11, SFXdn_rexthrash12 */
#define SFXTRIG_dn_rexhurt12            0x8c   /* plays SFXdn_rexhurt12, SFXdn_rexhurt13 */
#define SFXTRIG_dn_rexbreathin11        0x8e   /* plays SFXdn_rexbreathin11 */
#define SFXTRIG_dn_rexbreathout11       0x8f   /* plays SFXdn_rexbreathout11 */
#define SFXTRIG_dn_rexfoot11            0x90   /* plays SFXdn_rexfoot11 */
#define SFXTRIG_dn_rexfoot11_91         0x91   /* plays SFXdn_rexfoot11 */
#define SFXTRIG_dn_rexfoot11_92         0x92   /* plays SFXdn_rexfoot11 */
#define SFXTRIG_wp_stftest122           0x94   /* plays SFXwp_stftest122, SFXwp_stftest222, SFXwp_stftest322 */
#define SFXTRIG_dn_boar1_c_95           0x95   /* plays SFXdn_boar1_c */
#define SFXTRIG_en_trpopn_c_9f          0x9f   /* plays SFXen_trpopn_c */
#define SFXTRIG_bombplant_grows         0xa1   /* plays SFXbombplant_grows */
#define SFXTRIG_en_majring2             0xa2   /* plays SFXen_majring2 */
#define SFXTRIG_bombplant_woompf        0xa3   /* plays SFXbombplant_woompf */
#define SFXTRIG_en_sbalhis6             0xa4   /* plays SFXen_sbalhis6 */
#define SFXTRIG_wp_swdwood16            0xa5   /* plays SFXwp_swdwood16 */
#define SFXTRIG_mv_curtainopen16        0xa6   /* plays SFXmv_curtainopen16 */
#define SFXTRIG_sc_gemrun0122           0xa7   /* plays SFXsc_gemrun0122 */
#define SFXTRIG_wp_stpos4_b             0xc0   /* plays SFXwp_stpos4_b */
#define SFXTRIG_wp_stapo1_b             0xc1   /* plays SFXwp_stapo1_b */
#define SFXTRIG_dn_boar1_c_c6           0xc6   /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_c7           0xc7   /* plays SFXdn_boar1_c */
#define SFXTRIG_en_treedrum16_c8        0xc8   /* plays SFXen_treedrum16 */
#define SFXTRIG_mv_bflconc1             0xc9   /* plays SFXmv_bflconc1 */
#define SFXTRIG_sc_menuups16k_ca        0xca   /* plays SFXsc_menuups16k */
#define SFXTRIG_wp_iceywindlp16_cb      0xcb   /* plays SFXwp_iceywindlp16 */
#define SFXTRIG_en_cvdrip1c_cc          0xcc   /* plays SFXen_cvdrip1c */
#define SFXTRIG_wp_dsmk2_c_cf           0xcf   /* plays SFXwp_dsmk2_c */
#define SFXTRIG_en_barrelblow11_d1      0xd1   /* plays SFXen_barrelblow11 */
#define SFXTRIG_barrel_throw_d3         0xd3   /* plays SFXbarrel_throw */
#define SFXTRIG_wp_ice_freeze           0xd4   /* plays SFXwp_ice_freeze, SFXwp_ice_smash, SFXcrf_babyreply */
#define SFXTRIG_dn_boar1_c_d5           0xd5   /* plays SFXdn_boar1_c */
#define SFXTRIG_en_icecrk16_d6          0xd6   /* plays SFXen_icecrk16 */
#define SFXTRIG_en_lflsh1_c             0xd7   /* plays SFXen_lflsh1_c */
#define SFXTRIG_foot_water_roll         0xe3   /* plays SFXfoot_water_roll, SFXthorntail_annoyed1 */
#define SFXTRIG_sp_literun114           0xe7   /* plays SFXsp_literun114, SFXsp_literun115 */
#define SFXTRIG_tr_bcrek1_c             0xe8   /* plays SFXtr_bcrek1_c */
#define SFXTRIG_wp_rolovr_6             0xe9   /* plays SFXwp_rolovr_6 */
#define SFXTRIG_ar_barrel16             0xee   /* plays SFXar_barrel16 */
#define SFXTRIG_en_sbalhis6_f2          0xf2   /* plays SFXen_sbalhis6 */
#define SFXTRIG_sc_lockedon22           0xf3   /* plays SFXsc_lockedon22 */
#define SFXTRIG_sc_lockedon22_f4        0xf4   /* plays SFXsc_lockedon22 */
#define SFXTRIG_crf_babyflute           0xff   /* plays SFXcrf_babyflute */
#define SFXTRIG_dn_boar1_c_103          0x103  /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_104          0x104  /* plays SFXdn_boar1_c */
#define SFXTRIG_wp_dsmk2_c_106          0x106  /* plays SFXwp_dsmk2_c */
#define SFXTRIG_dn_boar1_c_10d          0x10d  /* plays SFXdn_boar1_c */
#define SFXTRIG_mv_mushdizzylp12        0x110  /* plays SFXmv_mushdizzylp12 */
#define SFXTRIG_mv_wickpickup16         0x113  /* plays SFXmv_wickpickup16 */
#define SFXTRIG_en_ripefruit11          0x115  /* plays SFXen_ripefruit11 */
#define SFXTRIG_dn_boar1_c_117          0x117  /* plays SFXdn_boar1_c */
#define SFXTRIG_tr_gal_rumblelp11       0x11b  /* plays SFXtr_gal_rumblelp11 */
#define SFXTRIG_dn_boar1_c_11e          0x11e  /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_gscsc1_c             0x125  /* plays SFXdn_gscsc1_c, SFXdn_gscsc2_c */
#define SFXTRIG_sc_spotfox02            0x12e  /* plays SFXsc_spotfox02 */
#define SFXTRIG_wp_swdtest322           0x130  /* plays SFXwp_swdtest322 */
#define SFXTRIG_sk_trwhin3              0x133  /* plays SFXsk_trwhin3, SFXsk_trwhin4, SFXsp_literun112, SFXsp_literun113, SFXsk_trwhin2, SFXsk_doggydig11 */
#define SFXTRIG_wp_swdtest322_135       0x135  /* plays SFXwp_swdtest322 */
#define SFXTRIG_wp_simp1_c              0x136  /* plays SFXwp_simp1_c */
#define SFXTRIG_mv_cagerat01            0x137  /* plays SFXmv_cagerat01 */
#define SFXTRIG_wp_swdtest222           0x138  /* plays SFXwp_swdtest222 */
#define SFXTRIG_tr_gal_lightning        0x143  /* plays SFXtr_gal_lightning */
#define SFXTRIG_tr_gal_crateslide       0x144  /* plays SFXtr_gal_crateslide */
#define SFXTRIG_tr_gal_sailflap3        0x145  /* plays SFXtr_gal_sailflap3 */
#define SFXTRIG_mv_curtainloop16        0x146  /* plays SFXmv_curtainloop16 */
#define SFXTRIG_dn_boar1_c_155          0x155  /* plays SFXdn_boar1_c */
#define SFXTRIG_mv_dinostomp1           0x156  /* plays SFXmv_dinostomp1 */
#define SFXTRIG_wp_hitpos_6_167         0x167  /* plays SFXwp_hitpos_6 */
#define SFXTRIG_dn_boar1_c_169          0x169  /* plays SFXdn_boar1_c */
#define SFXTRIG_en_lflsh3_c_16b         0x16b  /* plays SFXen_lflsh3_c */
#define SFXTRIG_wp_blaserrecoil16       0x172  /* plays SFXwp_blaserrecoil16 */
#define SFXTRIG_dn_boar1_c_173          0x173  /* plays SFXdn_boar1_c */
#define SFXTRIG_mn_dimbos46             0x17d  /* plays SFXmn_dimbos46 */
#define SFXTRIG_wp_gcexp1_c             0x17e  /* plays SFXwp_gcexp1_c */
#define SFXTRIG_mn_lummy311             0x186  /* plays SFXmn_lummy311 */
#define SFXTRIG_en_cvdrip1c_188         0x188  /* plays SFXen_cvdrip1c */
#define SFXTRIG_dn_boar1_c_18d          0x18d  /* plays SFXdn_boar1_c */
#define SFXTRIG_mv_blkhit_c             0x192  /* plays SFXmv_blkhit_c */
#define SFXTRIG_mv_persquk2             0x193  /* plays SFXmv_persquk2 */
#define SFXTRIG_mv_wickpickup16_194     0x194  /* plays SFXmv_wickpickup16 */
#define SFXTRIG_wp_cahit2_c             0x1ab  /* plays SFXwp_cahit2_c */
#define SFXTRIG_wp_blasershot11         0x1ac  /* plays SFXwp_blasershot11 */
#define SFXTRIG_id_1ad                  0x1ad  /* no direct sound (looped/special) */
#define SFXTRIG_dn_boar1_c_1b3          0x1b3  /* plays SFXdn_boar1_c, SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_1c4          0x1c4  /* plays SFXdn_boar1_c */
#define SFXTRIG_en_treedrum16_1c8       0x1c8  /* plays SFXen_treedrum16 */
#define SFXTRIG_mv_bflconc1_1d0         0x1d0  /* plays SFXmv_bflconc1 */
#define SFXTRIG_mn_eggylaugh116         0x1ea  /* plays SFXmn_eggylaugh116 */
#define SFXTRIG_mn_dimspit6             0x1eb  /* plays SFXmn_dimspit6 */
#define SFXTRIG_baddie_zyck_lash        0x1ec  /* plays SFXbaddie_zyck_lash, SFXbaddie_kooshy_call, SFXsc_walkstep */
#define SFXTRIG_wp_stftest122_1f2       0x1f2  /* plays SFXwp_stftest122, SFXwp_stftest222, SFXwp_stftest322 */
#define SFXTRIG_mv_liftloop             0x1f5  /* plays SFXmv_liftloop */
#define SFXTRIG_dn_boar1_c_1f6          0x1f6  /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_1f7          0x1f7  /* plays SFXdn_boar1_c */
#define SFXTRIG_en_lflsh2_b             0x1f8  /* plays SFXen_lflsh2_b */
#define SFXTRIG_en_birdymornin11_1f9    0x1f9  /* plays SFXen_birdymornin11 */
#define SFXTRIG_en_nlite1_c             0x1fa  /* plays SFXen_nlite1_c */
#define SFXTRIG_en_fireup_c_1fb         0x1fb  /* plays SFXen_fireup_c */
#define SFXTRIG_tr_jrumbalp             0x1fd  /* plays SFXtr_jrumbalp */
#define SFXTRIG_wp_dsmk2_c_206          0x206  /* plays SFXwp_dsmk2_c */
#define SFXTRIG_wp_dsmk2_c_207          0x207  /* plays SFXwp_dsmk2_c */
#define SFXTRIG_dn_boar1_c_208          0x208  /* plays SFXdn_boar1_c, SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_209          0x209  /* plays SFXdn_boar1_c */
#define SFXTRIG_wp_hitpos_6_20a         0x20a  /* plays SFXwp_hitpos_6 */
#define SFXTRIG_staff_rocket_hitdirt    0x20b  /* plays SFXstaff_rocket_hitdirt */
#define SFXTRIG_mv_dive4_c              0x210  /* plays SFXmv_dive4_c */
#define SFXTRIG_mv_ropecreak22          0x211  /* plays SFXmv_ropecreak22 */
#define SFXTRIG_mv_curtainopen16_212    0x212  /* plays SFXmv_curtainopen16 */
#define SFXTRIG_staff_quake_powerup     0x215  /* plays SFXstaff_quake_powerup */
#define SFXTRIG_staff_quake_strike      0x216  /* plays SFXstaff_quake_strike */
#define SFXTRIG_staff_boulder_move2     0x217  /* plays SFXstaff_boulder_move2 */
#define SFXTRIG_staff_rocket_boost      0x218  /* plays SFXstaff_rocket_boost */
#define SFXTRIG_fox_roll2               0x219  /* plays SFXfox_roll2 */
#define SFXTRIG_staff_boulder_move1     0x21a  /* plays SFXstaff_boulder_move1 */
#define SFXTRIG_id_21c                  0x21c  /* no direct sound (looped/special) */
#define SFXTRIG_en_rfall5_c             0x232  /* plays SFXen_rfall5_c */
#define SFXTRIG_wp_iceywindlp16_233     0x233  /* plays SFXwp_iceywindlp16 */
#define SFXTRIG_en_twiggysnap11         0x236  /* plays SFXen_twiggysnap11 */
#define SFXTRIG_dn_seal4_c              0x237  /* plays SFXdn_seal4_c */
#define SFXTRIG_dn_boar1_c_238          0x238  /* plays SFXdn_boar1_c */
#define SFXTRIG_en_grumb4_c             0x23a  /* plays SFXen_grumb4_c */
#define SFXTRIG_dn_boar1_c_244          0x244  /* plays SFXdn_boar1_c */
#define SFXTRIG_sc_clubswipe            0x245  /* plays SFXsc_clubswipe */
#define SFXTRIG_sc_walkstep             0x246  /* plays SFXsc_walkstep */
#define SFXTRIG_sc_runstep              0x247  /* plays SFXsc_runstep */
#define SFXTRIG_dn_boar1_c_248          0x248  /* plays SFXdn_boar1_c */
#define SFXTRIG_baddie_rach_bite        0x24d  /* plays SFXbaddie_rach_bite */
#define SFXTRIG_baddie_rach_call1       0x24e  /* plays SFXbaddie_rach_call1, SFXbaddie_rach_call2 */
#define SFXTRIG_baddie_kooshy_call      0x24f  /* plays SFXbaddie_kooshy_call */
#define SFXTRIG_mv_ladderslide16_250    0x250  /* plays SFXmv_ladderslide16 */
#define SFXTRIG_dn_boar1_c_251          0x251  /* plays SFXdn_boar1_c */
#define SFXTRIG_id_252                  0x252  /* no direct sound (looped/special) */
#define SFXTRIG_id_253                  0x253  /* no direct sound (looped/special) */
#define SFXTRIG_baddie_zyck_lash_254    0x254  /* plays SFXbaddie_zyck_lash */
#define SFXTRIG_baddie_zyck_strike      0x258  /* plays SFXbaddie_zyck_strike */
#define SFXTRIG_baddie_mika_cackle      0x259  /* plays SFXbaddie_mika_cackle */
#define SFXTRIG_baddie_mika_bombwhistle 0x25a  /* plays SFXbaddie_mika_bombwhistle, SFXbaddie_eggsnatch_start3, SFXbaddie_eggsnatch_start4, SFXbaddie_mush_windup */
#define SFXTRIG_baddie_mika_wingflap    0x25b  /* plays SFXbaddie_mika_wingflap */
#define SFXTRIG_mn_heart1_c             0x25c  /* plays SFXmn_heart1_c */
#define SFXTRIG_dn_boar1_c_25d          0x25d  /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_25e          0x25e  /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_25f          0x25f  /* plays SFXdn_boar1_c */
#define SFXTRIG_baddie_mika_wingflap_260 0x260  /* plays SFXbaddie_mika_wingflap */
#define SFXTRIG_mn_heart1_c_261         0x261  /* plays SFXmn_heart1_c */
#define SFXTRIG_baddie_eba_pollenspin   0x262  /* plays SFXbaddie_eba_pollenspin, SFXbaddie_eba_pollenspit, SFXbaddie_vambat_attack */
#define SFXTRIG_dn_seal4_c_263          0x263  /* plays SFXdn_seal4_c */
#define SFXTRIG_dn_boar1_c_264          0x264  /* plays SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_265          0x265  /* plays SFXdn_boar1_c */
#define SFXTRIG_baddie_rach_bite_266    0x266  /* plays SFXbaddie_rach_bite */
#define SFXTRIG_dn_boar1_c_267          0x267  /* plays SFXdn_boar1_c */
#define SFXTRIG_baddie_zyck_lash_268    0x268  /* plays SFXbaddie_zyck_lash */
#define SFXTRIG_baddie_zyck_call02      0x269  /* plays SFXbaddie_zyck_call02, SFXbaddie_zyck_call03, SFXbaddie_zyck_death */
#define SFXTRIG_mn_lummy311_26a         0x26a  /* plays SFXmn_lummy311 */
#define SFXTRIG_baddie_rach_bite_26b    0x26b  /* plays SFXbaddie_rach_bite */
#define SFXTRIG_dn_boar1_c_26c          0x26c  /* plays SFXdn_boar1_c, SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_26e          0x26e  /* plays SFXdn_boar1_c, SFXdn_boar1_c */
#define SFXTRIG_dn_boar1_c_26f          0x26f  /* plays SFXdn_boar1_c */
#define SFXTRIG_mn_lummy211             0x270  /* plays SFXmn_lummy211 */
#define SFXTRIG_mn_lummy111             0x271  /* plays SFXmn_lummy111, SFXmn_lummy211, SFXmn_impyflap16 */
#define SFXTRIG_mn_lummy211_273         0x273  /* plays SFXmn_lummy211 */
#define SFXTRIG_mn_impyflap16           0x274  /* plays SFXmn_impyflap16, SFXmn_lummy111, SFXmn_lummy211 */
#define SFXTRIG_mn_cling03              0x275  /* plays SFXmn_cling03 */
#define SFXTRIG_wp_beamgenlp16_276      0x276  /* plays SFXwp_beamgenlp16 */
#define SFXTRIG_dn_boar1_c_277          0x277  /* plays SFXdn_boar1_c */
#define SFXTRIG_ms_windlift_loop        0x27a  /* plays SFXms_windlift_loop */
#define SFXTRIG_mv_persquk1             0x27b  /* plays SFXmv_persquk1 */
#define SFXTRIG_dn_seal4_c_27c          0x27c  /* plays SFXdn_seal4_c */
#define SFXTRIG_mv_roothack16           0x27e  /* plays SFXmv_roothack16 */
#define SFXTRIG_id_27f                  0x27f  /* no direct sound (looped/special) */
#define SFXTRIG_wp_swdtest222_280       0x280  /* plays SFXwp_swdtest222 */
#define SFXTRIG_mv_totem_stop           0x286  /* plays SFXmv_totem_stop */
#define SFXTRIG_sc_clock_timesup        0x287  /* plays SFXsc_clock_timesup */
#define SFXTRIG_sc_scabshortish32       0x288  /* plays SFXsc_scabshortish32 */
#define SFXTRIG_sc_gemrun1022           0x289  /* plays SFXsc_gemrun1022 */
#define SFXTRIG_sc_commsbleep_28c       0x28c  /* plays SFXsc_commsbleep */
#define SFXTRIG_sc_lockon22             0x28d  /* plays SFXsc_lockon22 */
#define SFXTRIG_wmap_nameoff_29e        0x29e  /* plays SFXwmap_nameoff */
#define SFXTRIG_ar_boost16              0x29f  /* plays SFXar_boost16 */
#define SFXTRIG_wmap_select             0x2a0  /* plays SFXwmap_select */
#define SFXTRIG_ar_brakes16             0x2a1  /* plays SFXar_brakes16 */
#define SFXTRIG_ar_englp16              0x2a2  /* plays SFXar_englp16 */
#define SFXTRIG_ar_badhit16             0x2a3  /* plays SFXar_badhit16 */
#define SFXTRIG_wmap_arwingflyby        0x2a4  /* plays SFXwmap_arwingflyby */
#define SFXTRIG_ar_awghitobj16_2a5      0x2a5  /* plays SFXar_awghitobj16 */
#define SFXTRIG_ar_ring_pickup          0x2a6  /* plays SFXar_ring_pickup */
#define SFXTRIG_ar_largeenergy_pickup   0x2a7  /* plays SFXar_largeenergy_pickup */
#define SFXTRIG_ar_smallenergy_pickup   0x2a8  /* plays SFXar_smallenergy_pickup */
#define SFXTRIG_ar_lsrhitobj16          0x2a9  /* plays SFXar_lsrhitobj16 */
#define SFXTRIG_ar_laser216             0x2ab  /* plays SFXar_laser216 */
#define SFXTRIG_wmap_select_2ac         0x2ac  /* plays SFXwmap_select */
#define SFXTRIG_ar_laser116             0x2b3  /* plays SFXar_laser116 */
#define SFXTRIG_ar_deflect16            0x2b4  /* plays SFXar_deflect16 */
#define SFXTRIG_wp_blaserhit16          0x2b5  /* plays SFXwp_blaserhit16 */
#define SFXTRIG_ar_barrel16_2b6         0x2b6  /* plays SFXar_barrel16 */
#define SFXTRIG_ar_bblast16             0x2b7  /* plays SFXar_bblast16 */
#define SFXTRIG_en_birdynight11         0x2b8  /* plays SFXen_birdynight11 */
#define SFXTRIG_mv_bflconc1_2b9         0x2b9  /* plays SFXmv_bflconc1 */
#define SFXTRIG_swapstone_move_short_2bc 0x2bc  /* plays SFXswapstone_move_short */
#define SFXTRIG_ar_blaunch16            0x2c0  /* plays SFXar_blaunch16 */
#define SFXTRIG_en_mushsporedisp22      0x2c1  /* plays SFXen_mushsporedisp22 */
#define SFXTRIG_recrate_smash           0x2c3  /* plays SFXrecrate_smash */
#define SFXTRIG_dn_boar1_c_2ca          0x2ca  /* plays SFXdn_boar1_c */
#define SFXTRIG_id_2e4                  0x2e4  /* no direct sound (looped/special) */
#define SFXTRIG_id_308                  0x308  /* no direct sound (looped/special) */
#define SFXTRIG_id_309                  0x309  /* no direct sound (looped/special) */
#define SFXTRIG_id_30a                  0x30a  /* no direct sound (looped/special) */
#define SFXTRIG_id_30b                  0x30b  /* no direct sound (looped/special) */
#define SFXTRIG_id_30c                  0x30c  /* no direct sound (looped/special) */
#define SFXTRIG_id_30f                  0x30f  /* no direct sound (looped/special) */
#define SFXTRIG_en_trpopn_c_312         0x312  /* plays SFXen_trpopn_c */
#define SFXTRIG_tr_jbike_snowhit        0x313  /* plays SFXtr_jbike_snowhit */
#define SFXTRIG_mv_gdtur2_c             0x315  /* plays SFXmv_gdtur2_c, SFXmv_icesmash16 */
#define SFXTRIG_wp_ice_freeze_316       0x316  /* plays SFXwp_ice_freeze, SFXwp_ice_smash, SFXcrf_babyreply */
#define SFXTRIG_en_lrope_powerdown      0x31b  /* plays SFXen_lrope_powerdown */
#define SFXTRIG_barrel_putdown_31f      0x31f  /* plays SFXbarrel_putdown */
#define SFXTRIG_barrelgen_slide         0x328  /* plays SFXbarrelgen_slide */
#define SFXTRIG_wp_mzap2_c              0x329  /* plays SFXwp_mzap2_c */
#define SFXTRIG_dn_boar1_c_32b          0x32b  /* plays SFXdn_boar1_c */
#define SFXTRIG_en_cvdrip1c_32c         0x32c  /* plays SFXen_cvdrip1c */
#define SFXTRIG_en_trpopn_c_32d         0x32d  /* plays SFXen_trpopn_c */
#define SFXTRIG_mn_heart1_c_334         0x334  /* plays SFXmn_heart1_c */

#endif /* MAIN_AUDIO_SFX_TRIGGER_IDS_H_ */
