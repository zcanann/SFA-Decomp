export const meta = {
  name: 'dll-cleanup-wave',
  description: 'Cleanup of loose src/main/dll/*.c: Opus clean (incl. dead-FUN_ removal) -> Sonnet review -> Opus apply-fixes',
  phases: [
    { title: 'Clean', detail: 'Opus: clean + prune unused symbols + remove dead FUN_ bodies' },
    { title: 'Review', detail: 'Sonnet read-only review of each cleaned file' },
    { title: 'Fix', detail: 'Opus: apply safe review findings' },
  ],
}

const REFERENCE = 'src/main/dll/WM/dll_020C_wmspiritplace.c'
const CONCURRENCY = 3
const CHUNK_START = 244
const CHUNK_SIZE = 20

const BATCH = [
  { name: 'animobjd2.c', baseline: '090345264b7e4a324194e00d6ecd98f0', pct: 92.974 },
  { name: 'balloonbaddie.c', baseline: '3b6ee22d2853e99dd29d3f233793f9c2', pct: 94.498 },
  { name: 'boulder.c', baseline: '0c6eb5f855c427a726acbec5f4977a3b', pct: 100.0 },
  { name: 'bwalphaanim.c', baseline: 'b5b9cbed6c2642d46b436dfccb7f9bd9', pct: 100.0 },
  { name: 'camshipbattle5c.c', baseline: '848004a9ad22f317fe57b9dcab8a5d33', pct: 96.057 },
  { name: 'cannon.c', baseline: '384c6fad0410e79584d48e048506d64f', pct: 94.033 },
  { name: 'cannonball.c', baseline: '6cb3e1a6567eafd5b391f4d71c691e7a', pct: 99.224 },
  { name: 'cf_doorlight.c', baseline: '429744e2114807bc8e7c45e0912667cd', pct: 100.0 },
  { name: 'cloudaction.c', baseline: '4640e5d52bd08ce4d09c0d34dbc1afbc', pct: 99.928 },
  { name: 'crate.c', baseline: '031fad9538948c74b5d0ac16fd1b7d7a', pct: 100.0 },
  { name: 'cutcam.c', baseline: 'df1ebfb509f7e6cc24360e8599eb0450', pct: 98.355 },
  { name: 'dbprotection.c', baseline: '4a484c846d642893a6851d942446c276', pct: 99.518 },
  { name: 'dfbarrelanim.c', baseline: '98836b259ab37723a3824440bb34a86f', pct: 94.016 },
  { name: 'dfpulley.c', baseline: '59e64a1039d73360cd2ead5034b73713', pct: 100.0 },
  { name: 'dll_0000_baby_snowworm.c', baseline: 'c2ea4450af0b2f1a4b193810f77081e6', pct: 94.176 },
  { name: 'dll_0001_camcontrol.c', baseline: '63227bb8e86a21648cd83ea20e7ca993', pct: 97.442 },
  { name: 'dll_0003_checkpoint.c', baseline: '89919726537a24f88c85670ae065a4c0', pct: 97.894 },
  { name: 'dll_0004_dummy04.c', baseline: '8ae5ed0ef4eeea83f0556fe899387553', pct: 100.0 },
  { name: 'dll_000A_expgfx.c', baseline: '74da41cdfac67c9f8d100955a80e1cc0', pct: 86.196 },
  { name: 'dll_000B_dll0b.c', baseline: '5c6d4fa5df87a85a2f25e229f5c68361', pct: 94.9 },
  { name: 'dll_000C_projgfx.c', baseline: '6dd4f995786a6d169f45a5ac5b04a14a', pct: 100.0 },
  { name: 'dll_000D_playershadow.c', baseline: '39b88d3eb2fa2b875da070caa17136fc', pct: 94.458 },
  { name: 'dll_000E_partfx.c', baseline: '689658ea582a4d1b7181a2e2e2e26217', pct: 97.82 },
  { name: 'dll_000F_unk.c', baseline: '614519ccae6c5f99bbfd71530db10cd5', pct: 98.266 },
  { name: 'dll_0010_uicontroller.c', baseline: '91252f0d720f16e5b0c2fdf6aeee5a61', pct: 100.0 },
  { name: 'dll_0011_screens.c', baseline: '6e2be209b992db968080efed1e01ea0b', pct: 99.922 },
  { name: 'dll_0012_unk.c', baseline: '15a8dba0e5e45ebaf3ea37b033081f26', pct: 100.0 },
  { name: 'dll_0013_waterfx.c', baseline: '5743c961bcc7c62dc295b2ec27115c1b', pct: 95.843 },
  { name: 'dll_0015_curves.c', baseline: '959d5a06e5e5d9cae3d3ba131c3a63e0', pct: 92.119 },
  { name: 'dll_0016_screentransition.c', baseline: 'fd27d0cd724208bfb7731f908bac90c6', pct: 95.102 },
  { name: 'dll_0018_boneparticleeffect.c', baseline: 'c68cb25808771a1544d3315d9f393995', pct: 94.249 },
  { name: 'dll_0019_dll19func0.c', baseline: '96d9d45f6a8698b4a6ef19c8a211bc36', pct: 98.237 },
  { name: 'dll_001A_effect1.c', baseline: '8c741b2970f7f7a3933c8d77130b2b32', pct: 99.991 },
  { name: 'dll_001B_effect2.c', baseline: 'da83d5342baca4889013dc46a7a1c515', pct: 100.0 },
  { name: 'dll_001C_effect3.c', baseline: 'aa9daeafe29cb7c422246ee94de10419', pct: 99.754 },
  { name: 'dll_001D_effect4.c', baseline: '8072ffb22e6f3b42fad8f08059915a07', pct: 100.0 },
  { name: 'dll_001E_effect5.c', baseline: '9190825ad1c7b3494fe1f416bcdc848f', pct: 100.0 },
  { name: 'dll_001F_effect6.c', baseline: '3561d8dfc36bbd9762418a38db773c93', pct: 100.0 },
  { name: 'dll_0020_effect7.c', baseline: '92b34d4284ae44406aacbe13379606c0', pct: 100.0 },
  { name: 'dll_0021_effect8.c', baseline: '2f0520500dec50a14ef1abeda79d6672', pct: 100.0 },
  { name: 'dll_0022_effect9.c', baseline: '0ea4009f09ea45337cca6180e2dea1d4', pct: 99.977 },
  { name: 'dll_0023_effect10.c', baseline: '978d778fc2e0270a6e4bdc3b1136e2f4', pct: 100.0 },
  { name: 'dll_0026_effect13.c', baseline: 'ecc2c81fdbcc1fa4f5bf5f170f2e1b6b', pct: 100.0 },
  { name: 'dll_0027_effect14.c', baseline: 'c9bd8957dfb07add8be567cc078c367f', pct: 100.0 },
  { name: 'dll_0028_effect15.c', baseline: 'daa38fb894d548d0eea3e5e27dcfb798', pct: 100.0 },
  { name: 'dll_0029_effect16.c', baseline: '01d3d13639a2f303fc4be2eec9788fcc', pct: 100.0 },
  { name: 'dll_002A_effect17.c', baseline: 'ce97d27dde8aad5341996fcf3ade11a9', pct: 100.0 },
  { name: 'dll_002B_effect18.c', baseline: '66ac41dab005d4b8f09aac34ae86073a', pct: 99.987 },
  { name: 'dll_002C_effect19.c', baseline: '4927ba43a7ebae89814ca216fcbc15e9', pct: 100.0 },
  { name: 'dll_002D_effect20.c', baseline: 'cf1b1593715d1054bd451623f7f386d1', pct: 99.985 },
  { name: 'dll_002E_moveLib.c', baseline: '41380530cfb166fc642bbcad5b46e620', pct: 99.202 },
  { name: 'dll_002F_carryable.c', baseline: 'ae322e4d07e61d6b269f59463bf3701b', pct: 99.101 },
  { name: 'dll_0031_minimap.c', baseline: 'd727a6fd700ff898839932633e6f6777', pct: 96.495 },
  { name: 'dll_0032_titlescreeninit.c', baseline: 'a71551cb012f3a2b81a570f733d8492e', pct: 96.71 },
  { name: 'dll_0035_saveselectscreen.c', baseline: '77571075f047cb6352cf9daa973d81ed', pct: 99.124 },
  { name: 'dll_0037_optionsscreen.c', baseline: 'fd139ef106754cc336e64bbd025a33ca', pct: 98.319 },
  { name: 'dll_0039_dummy39.c', baseline: 'c5f2719e35a629f85c046caae8b0d861', pct: 100.0 },
  { name: 'dll_003B_menu.c', baseline: '492648346514b1e4f1892ee829bf9846', pct: 100.0 },
  { name: 'dll_003C_tumbleweedbush.c', baseline: '47af4c68afe2b4b67d969942c2e17464', pct: 94.089 },
  { name: 'dll_003F_dll3f.c', baseline: '3ecb30033e306212b887855d04827799', pct: 100.0 },
  { name: 'dll_0040_credits.c', baseline: 'cf3f13141c4fddc8f9f92796c9c6b26d', pct: 95.732 },
  { name: 'dll_0041_warpstoneui.c', baseline: '6ed6f8f55247bf71254787f1fac87fd6', pct: 97.071 },
  { name: 'dll_0042_unk.c', baseline: '3ea0c72f52be5017752dbb39a3707287', pct: 97.156 },
  { name: 'dll_0043_unk.c', baseline: 'df71aa94b025d65a4e708d31b18bb8b7', pct: 98.08 },
  { name: 'dll_0044_cameramodeviewfinder.c', baseline: '17841917a9a6954d41ba941ec0b33a66', pct: 98.699 },
  { name: 'dll_004B_cameramodeclimb.c', baseline: '49c111615dc44c42148441d06fb15eb0', pct: 95.617 },
  { name: 'dll_004C_camDebug.c', baseline: '9f0b2e4f0597a9dca26faa45ffd5af21', pct: 100.0 },
  { name: 'dll_004D_cameramodenpcspeak.c', baseline: 'c5a85bf20b2e0f9eced86bba539b89f5', pct: 98.287 },
  { name: 'dll_004E_cameramodeworldmap.c', baseline: 'cde29b73a20443fd770ca25ff7205445', pct: 95.324 },
  { name: 'dll_004F_dll4f.c', baseline: 'dc1a97ad954b90f4498f5cb02d08ccb7', pct: 97.123 },
  { name: 'dll_0050_cameramodecrawl.c', baseline: '2f4a56397d4d22a986ed27d877c09240', pct: 99.169 },
  { name: 'dll_0051_cameramodecannon.c', baseline: '67408b765bd8cf0fcd5ca04921b4cf84', pct: 100.0 },
  { name: 'dll_0052_cameramodeforcebehind.c', baseline: 'e0c980b132475971ba36ff5aa2cbd135', pct: 95.448 },
  { name: 'dll_0054_dll54.c', baseline: 'a227e3f0fd012934780a6cf2e2e3e087', pct: 100.0 },
  { name: 'dll_0055_cameramodeperv.c', baseline: 'b85c72f81132bfddf920ca1295f807ba', pct: 100.0 },
  { name: 'dll_0056_cameramodearwing.c', baseline: '31a0014928ab83dff04eec0de8093afb', pct: 96.126 },
  { name: 'dll_0057_cameramodetitle.c', baseline: '5b9a052be2a2a35ca0c8178365715a54', pct: 97.511 },
  { name: 'dll_0058_dummy58.c', baseline: '95bd7653de0f26cf0b09505d46dc2eeb', pct: 100.0 },
  { name: 'dll_0059_dll59func0.c', baseline: '217dfa71522a9786c9040de8305317ca', pct: 99.693 },
  { name: 'dll_005A_staffcollisionfunc03.c', baseline: '2e99c531550e6540179c747205b4ff32', pct: 97.449 },
  { name: 'dll_005B_modgfxfunc03.c', baseline: '05ebcdc21f2c67b9925ef0b4a36e886f', pct: 99.03 },
  { name: 'dll_005C_dll5cfunc0.c', baseline: 'af55774367e20e74c913675dc5587367', pct: 100.0 },
  { name: 'dll_005D_dll5dfunc0.c', baseline: '9ffdd34d46428a832a6a67d403a9bd06', pct: 100.0 },
  { name: 'dll_005E_dll5efunc0.c', baseline: '427fecbabcdfc27a6a4cfa109342b1b2', pct: 88.322 },
  { name: 'dll_005F_dll5ffunc0.c', baseline: '1fa255ba58f7f090433925a69f569e37', pct: 98.373 },
  { name: 'dll_0060_dll60func0.c', baseline: '99fbe04ca48683a4955b8c3b809d29f0', pct: 92.355 },
  { name: 'dll_0061_dll61func0.c', baseline: 'f384f3e043bcf3390316cfb89057ccc0', pct: 99.455 },
  { name: 'dll_0062_dll62func0.c', baseline: 'a6d716746b7119a38b992c4e88eecd65', pct: 100.0 },
  { name: 'dll_0063_dll63func0.c', baseline: '8b62ce6ea86e8ebed4db012dd0cf7e7b', pct: 99.458 },
  { name: 'dll_0064_dll64func0.c', baseline: 'eb3118c8ee19cb6fce7186441b96957c', pct: 100.0 },
  { name: 'dll_0065_dll65func0.c', baseline: 'f13d439b31101c07965aeec5104059b3', pct: 98.571 },
  { name: 'dll_0066_dll66func0.c', baseline: 'b785f11d31f53afacacfd23158018564', pct: 94.977 },
  { name: 'dll_0067_dll67func0.c', baseline: '2364f23c557ed8ace51bd5efaa10e2a8', pct: 99.057 },
  { name: 'dll_0068_dll68func0.c', baseline: '5b798d526f8fc8a4de30c2a5620dfe98', pct: 98.679 },
  { name: 'dll_0069_dll69func0.c', baseline: '6d37b704f415ed737c7b9a622dcaa959', pct: 97.389 },
  { name: 'dll_006A_dll6afunc0.c', baseline: '8957ed1712cc04c0ef6becae5ec8e09e', pct: 96.088 },
  { name: 'dll_006B_dll6bfunc0.c', baseline: '8b3f8d732c4fde51f234b894dc6c7553', pct: 99.189 },
  { name: 'dll_006C_dummy6c.c', baseline: '589a6fa8cbd7d52d2487487761597313', pct: 100.0 },
  { name: 'dll_006D_dll6dfunc0.c', baseline: 'de57b33489c4e8d2db6f73c5efa14bf9', pct: 100.0 },
  { name: 'dll_006E_dll6efunc0.c', baseline: '510a5554d40be5d10504ce0f8835534c', pct: 98.547 },
  { name: 'dll_006F_dll6ffunc0.c', baseline: '51e223052b58c21fb7cf435b016a6973', pct: 95.465 },
  { name: 'dll_0070_dll70func0.c', baseline: '91e973fa1a85bdd4c9a4018e38effef2', pct: 96.466 },
  { name: 'dll_0071_dll71func0.c', baseline: '6eb49dfbeb987c35ea71d524fecedaa2', pct: 99.729 },
  { name: 'dll_0072_dll72func0.c', baseline: 'b48f525e6dbb59bce0949ee63218b66d', pct: 100.0 },
  { name: 'dll_0073_dll73func0.c', baseline: 'cc434f46300ddb1d025184095cc326ea', pct: 99.681 },
  { name: 'dll_0074_dll74func0.c', baseline: '1ec7131a668d34d1b999bcfc641532d6', pct: 98.276 },
  { name: 'dll_0075_dll75func0.c', baseline: '2ddacff3fb152c6284cdc2851ee971fa', pct: 100.0 },
  { name: 'dll_0076_dll76func0.c', baseline: '4d82e8c61cb8418b31393fdac276eb46', pct: 100.0 },
  { name: 'dll_0077_dll77func0.c', baseline: '065efe6084e2f4179bd8fcec1c958cf0', pct: 100.0 },
  { name: 'dll_0078_dll78func0.c', baseline: 'f5be1e8c24cac373dc93df2b0601fab9', pct: 100.0 },
  { name: 'dll_0079_dll79func0.c', baseline: '239d358090a1cd512fdfd0971598d3a0', pct: 98.362 },
  { name: 'dll_007A_dll7afunc0.c', baseline: '3e00001f34c8b0ec543219b524d66e96', pct: 99.882 },
  { name: 'dll_007B_dll7bfunc0.c', baseline: '814e34319c3ab20613d8ca611972ab74', pct: 98.866 },
  { name: 'dll_007C_dll7cfunc0.c', baseline: '6708447f1d252ddd8fe66c70ada8b954', pct: 100.0 },
  { name: 'dll_007D_dll7dfunc0.c', baseline: '01b61e5b896f0159c12de20aabb7f8dc', pct: 100.0 },
  { name: 'dll_007E_dll7efunc0.c', baseline: '7d15307d17870b061e9750b3406a157c', pct: 100.0 },
  { name: 'dll_007F_dll7ffunc0.c', baseline: '7fcaad41705eb3e93758808a836996f6', pct: 100.0 },
  { name: 'dll_0081_dll81func0.c', baseline: 'edc5c6ac5f5f823d131d7ac0a5ccb9a2', pct: 100.0 },
  { name: 'dll_0084_dll84func0.c', baseline: '010d02c328538f892ee48e97ea8ddd36', pct: 100.0 },
  { name: 'dll_0085_dll85func0.c', baseline: '011bfaa6d53ab826c0981091d53a5d59', pct: 100.0 },
  { name: 'dll_0086_dll86func0.c', baseline: '69232d367c53f36fecf1afaa060fed1b', pct: 100.0 },
  { name: 'dll_0087_dll87func0.c', baseline: 'cacd4fe468e9b84432f530d75cecea73', pct: 100.0 },
  { name: 'dll_0089_dll89func0.c', baseline: '5ee18066303b9ed3a9a1815103a409b0', pct: 100.0 },
  { name: 'dll_008B_dll8bfunc0.c', baseline: '2a1438d51eeede770867c4cf4acaac8a', pct: 93.645 },
  { name: 'dll_008C_dll8cfunc0.c', baseline: 'e86682c9d8c290e423b0ec97eb77e2dc', pct: 100.0 },
  { name: 'dll_008D_dll8dfunc0.c', baseline: '2346de4c7e239a94cd0abc4a366aaa82', pct: 99.543 },
  { name: 'dll_008E_dll8efunc0.c', baseline: 'f29dae7a60f6f6556a38e30531367847', pct: 99.877 },
  { name: 'dll_008F_dll8ffunc0.c', baseline: 'c245c31d49e495c54216c7432e121909', pct: 100.0 },
  { name: 'dll_0091_dll91func0.c', baseline: '7138802018ced33f4db57188e62b1b76', pct: 100.0 },
  { name: 'dll_0092_dll92func0.c', baseline: 'ab850f91e051f6eaac6a023a466ee54b', pct: 98.39 },
  { name: 'dll_0093_dll93func0.c', baseline: 'e4d828e7eabf743eaf2b7f44357c17f2', pct: 100.0 },
  { name: 'dll_0096_dll96func0.c', baseline: '059c7dddea4a07ab60a40895287d0f74', pct: 100.0 },
  { name: 'dll_0097_dll97func0.c', baseline: '70a3fcd495a45f25b33df6f569a54838', pct: 98.708 },
  { name: 'dll_0098_dll98func0.c', baseline: 'b061db9020d1115043538a87c8394471', pct: 99.847 },
  { name: 'dll_009A_dll9afunc0.c', baseline: 'b111a12e5501e191ce1426371a0efa64', pct: 99.77 },
  { name: 'dll_009B_dll9bfunc0.c', baseline: '009e8c53c23b36b31a556044345204e7', pct: 97.698 },
  { name: 'dll_009C_dll9cfunc0.c', baseline: '1d1831c5ecfa0fa75b0f9cb37005997b', pct: 95.342 },
  { name: 'dll_009D_dll9dfunc0.c', baseline: 'af10edfce65cb2c8f0e07c30c825fd32', pct: 100.0 },
  { name: 'dll_009E_dll9efunc0.c', baseline: 'c90623887558051961cbe697d7545e3c', pct: 100.0 },
  { name: 'dll_009F_dll9ffunc0.c', baseline: '70b0167682130134eb8d1096011116bd', pct: 100.0 },
  { name: 'dll_00A0_dlla0func0.c', baseline: 'd9e187dba5e18f182d99ed158e41849f', pct: 100.0 },
  { name: 'dll_00A1_dlla1func0.c', baseline: '51ec9ca56c70c6b63e48b81724ebc35c', pct: 100.0 },
  { name: 'dll_00A2_dlla2func0.c', baseline: '36e0a0348becc44699dd2ac4eaa801b0', pct: 100.0 },
  { name: 'dll_00A3_dlla3func0.c', baseline: '30b3711f12d77f850ba7bf4cfebeddaa', pct: 96.92 },
  { name: 'dll_00A4_dummya4.c', baseline: '0e00a809ca5a71a82fdbc7af507ead9a', pct: 100.0 },
  { name: 'dll_00A5_dlla5func0.c', baseline: 'c28a57fc4a0b26802fdbc051d18338f7', pct: 100.0 },
  { name: 'dll_00A6_dlla6func0.c', baseline: '0f0ad7ac3e408e2b5788eb71ddd959eb', pct: 100.0 },
  { name: 'dll_00A7_dlla7func0.c', baseline: '27b92a4ce98d08e70ab5fda63eceec45', pct: 96.118 },
  { name: 'dll_00A9_dlla9func0.c', baseline: 'e12bdf1adc4bdfa90613cf626015e47d', pct: 100.0 },
  { name: 'dll_00AA_dllaafunc0.c', baseline: '1581923b5b08372c18fcece5eae7632b', pct: 98.78 },
  { name: 'dll_00AB_projdummy.c', baseline: '49a85becc804b269af1f65ea2848d826', pct: 100.0 },
  { name: 'dll_00AC_projmagicstream.c', baseline: 'd0940b10a5ba090f96a6d9b356e9850e', pct: 100.0 },
  { name: 'dll_00AD_projmagicemmit1.c', baseline: '73a8b2cffe0f6ba6efcdc88206980197', pct: 100.0 },
  { name: 'dll_00AE_projroombeam.c', baseline: '5d6b7064574b905dd6b0c230bf6b8ffa', pct: 100.0 },
  { name: 'dll_00AF_projlightning1.c', baseline: '7a8b1dd76434099db61b1c25b9fd7291', pct: 100.0 },
  { name: 'dll_00B0_projlightning2.c', baseline: '8b56dfe3086a7b1fde1aa86203eb9ccb', pct: 100.0 },
  { name: 'dll_00B1_projlightning3.c', baseline: '00d1ed763683c007912c3cc26d2111e5', pct: 100.0 },
  { name: 'dll_00B2_projrobotfire.c', baseline: '75768b1587704e7fafa4b1c528495f43', pct: 100.0 },
  { name: 'dll_00B3_projlightning4.c', baseline: '83ac15ca7af744e887278a712f02b9d0', pct: 100.0 },
  { name: 'dll_00B4_projenergise1.c', baseline: '671a2d296f6503c02b3ca1dd892b4b16', pct: 100.0 },
  { name: 'dll_00B5_projenergise2.c', baseline: '5805091accad7936e7edef765445ebff', pct: 100.0 },
  { name: 'dll_00B6_projsquirt1.c', baseline: 'db9536c3178fcbef4fdab8630916f80b', pct: 100.0 },
  { name: 'dll_00B7_projship1.c', baseline: 'e8cec924bd1d3d93fcf0eec1473523d0', pct: 100.0 },
  { name: 'dll_00B8_projlightning5.c', baseline: '6614b0a4e1082a2d82ce2f4260537c24', pct: 100.0 },
  { name: 'dll_00B9_projlightning7.c', baseline: '045738a667d6f59cc1fa4535b2098545', pct: 100.0 },
  { name: 'dll_00BA_projlightning6.c', baseline: '2183022030a058c095dfc130be354aae', pct: 100.0 },
  { name: 'dll_00BB_projwallpower.c', baseline: '3dd86d4f2aea7e92d628343256a9d19b', pct: 100.0 },
  { name: 'dll_00BC_projquakeshock.c', baseline: 'a8633e47ebddf24f840196f22927c774', pct: 100.0 },
  { name: 'dll_00BD_projsunshock.c', baseline: '2d55b6f7295a21bebe2f5e27f518b499', pct: 100.0 },
  { name: 'dll_00BE_projtesla.c', baseline: 'ea8f9cac1a98c813f3edc19de30a5a61', pct: 100.0 },
  { name: 'dll_00BF_projcore1.c', baseline: '7282b98cc49d72a1eda1e644b2e972d1', pct: 100.0 },
  { name: 'dll_00C0_projcore2.c', baseline: 'd2b681d98cd83f72da392584e799bfdf', pct: 100.0 },
  { name: 'dll_00C1_projcore3.c', baseline: '19882016fd77f6390f7c182ac3b47dd3', pct: 100.0 },
  { name: 'dll_00C2_projdfp1r.c', baseline: '910e04dfade6d7de958b20a9552e3483', pct: 100.0 },
  { name: 'dll_00C6_animatedobj.c', baseline: 'ae665b1a6a3fd25fa43337744b3a7695', pct: 98.659 },
  { name: 'dll_00C8_depthoffieldpoint.c', baseline: 'd2a16af01530fda8ba682871e27819a7', pct: 100.0 },
  { name: 'dll_00C9_enemy.c', baseline: 'c38e6a7befb57571057d0cda8b94bb73', pct: 99.617 },
  { name: 'dll_00CB_dllcb.c', baseline: 'ca92b08b21de6345f55513cd1eb80bc3', pct: 100.0 },
  { name: 'dll_00CC_chukchuk.c', baseline: 'c898b5a5c27ccf24992e3db8c2e4879e', pct: 100.0 },
  { name: 'dll_00CD_iceball.c', baseline: 'b29ffd79c120f4354c0081f273f8c703', pct: 100.0 },
  { name: 'dll_00CE_dllce.c', baseline: '79e6a334df2c191ea01dbf79222f7818', pct: 100.0 },
  { name: 'dll_00CF_cannonclaw.c', baseline: '3dbbd775e8f2243cb8d70b6a6f0e1311', pct: 100.0 },
  { name: 'dll_00D1_tumbleweedbush.c', baseline: '499c3281cb05adcfd0b450a97c5b8eeb', pct: 99.281 },
  { name: 'dll_00D3_staffAction.c', baseline: '1c237fce27a021c02826fcff69e7c044', pct: 98.912 },
  { name: 'dll_00D5_kaldachom.c', baseline: 'e10e56d010a4b2b504ffaa9c8eeb4884', pct: 98.335 },
  { name: 'dll_00D6_kaldachomme.c', baseline: 'b192a6dd2a4fd4958b1d1a3a639e8da2', pct: 100.0 },
  { name: 'dll_00D7_kaldachompspit.c', baseline: 'f2b34f8da63f25d2382aeef233015e06', pct: 100.0 },
  { name: 'dll_00D8_pinponspike.c', baseline: '5a83048242dc4e5c8c9d975f66f57374', pct: 98.463 },
  { name: 'dll_00D9_pollen.c', baseline: '6ade300a4807554ad8189aef2d2af385', pct: 99.663 },
  { name: 'dll_00DA_pollenfragment.c', baseline: '67175aac69b7fe24b992af91e6e63c06', pct: 97.911 },
  { name: 'dll_00DB_mikabomb.c', baseline: '46ca45eeade399bb304ec24a335bf9bb', pct: 100.0 },
  { name: 'dll_00DC_mikabombshadow.c', baseline: '0da094efe1bd8d83637dd6cf88a2f152', pct: 100.0 },
  { name: 'dll_00DD_gcbaddieshield.c', baseline: 'fdfd4f36ac7e4861490cf8451cb866fb', pct: 100.0 },
  { name: 'dll_00DE_baddieinterestp.c', baseline: '0cc37c2228acd13f0fef9451a899e32d', pct: 99.491 },
  { name: 'dll_00DF_hagabon.c', baseline: '36969c2b1a9010aebd21975a51a20981', pct: 91.362 },
  { name: 'dll_00E0_swarmbaddie.c', baseline: 'bd4f8492e5b45dbb1fe74668f3dc1acb', pct: 100.0 },
  { name: 'dll_00E1_wispbaddie.c', baseline: 'f798e8111c6c42304dc083075c0375e8', pct: 97.799 },
  { name: 'dll_00E3_fireball.c', baseline: 'd80901be57f87b78412c2f0ae980da2b', pct: 98.146 },
  { name: 'dll_00E4_flamethrowerspe.c', baseline: '2b9021c2140dd0c42b0cfd74785526f8', pct: 98.222 },
  { name: 'dll_00E5_shield.c', baseline: '10e75b6959daa4c234df924cbf0c7886', pct: 96.242 },
  { name: 'dll_00E6_restartmarker.c', baseline: '372624911dd818c8469d7b32bd5b0731', pct: 100.0 },
  { name: 'dll_00E7_flammablevine.c', baseline: '59b7724ffaadcbc9151c3b6e55c7df6c', pct: 100.0 },
  { name: 'dll_00E8_checkpoint4.c', baseline: '1bfd5c5aef6707810c026bb9860c29cc', pct: 98.261 },
  { name: 'dll_00E9_setuppoint.c', baseline: '9e0565e4918eac7d8e86ea9c8c8cd4c6', pct: 100.0 },
  { name: 'dll_00EA_sideload.c', baseline: '80c2d7fae1fcc61dd54e6e4ced93ac37', pct: 100.0 },
  { name: 'dll_00EB_siderepel.c', baseline: 'dcedf3ddc3db62b7561f439ec16d65ad', pct: 100.0 },
  { name: 'dll_00EC_infopoint.c', baseline: '0b83bb7d63973c414cc236fffcd7fed8', pct: 100.0 },
  { name: 'dll_00ED_collectible.c', baseline: 'bb6f1477b06a6af0e43d9423bc79c934', pct: 100.0 },
  { name: 'dll_00EE_effectbox.c', baseline: '182fb40db5669c820a2539bc989df8d1', pct: 97.868 },
  { name: 'dll_00F0_warppoint.c', baseline: '85e81a30504a0215dd796c7ddfc477a8', pct: 100.0 },
  { name: 'dll_00F1_invhit.c', baseline: '56fc707f18d5e901e9039f41d6b22784', pct: 98.532 },
  { name: 'dll_00F2_iceblast.c', baseline: 'e50fa42b7257c664599090fc193ec35e', pct: 96.131 },
  { name: 'dll_00F4_doorf4.c', baseline: 'ed25116c5bb83ccb27299ee5736d36a4', pct: 98.52 },
  { name: 'dll_00F5_sidekickball.c', baseline: '5caf58aecc24efa4a2c201876eae7bdb', pct: 93.448 },
  { name: 'dll_00F6_area.c', baseline: 'ca6cf25be351dc45b2e01229b6a0d73f', pct: 100.0 },
  { name: 'dll_00F7_dllf7.c', baseline: '4fe3af9bfaca00b906c0938c6549bdf8', pct: 98.528 },
  { name: 'dll_00F8_levelname.c', baseline: 'aa722539345369e58347aa2d1245921c', pct: 100.0 },
  { name: 'dll_00FB_pressureswitchfb.c', baseline: '09c6dc7d9918e88fdc9e9476fc2a215d', pct: 97.504 },
  { name: 'dll_00FE_magicplant.c', baseline: 'a729acbcebe2c99eecf440250a02288d', pct: 99.954 },
  { name: 'dll_0100_trickywarp.c', baseline: '20c4000778597b61a484ec50edc117ca', pct: 100.0 },
  { name: 'dll_0101_trickyguard.c', baseline: 'f9563466052fcbd13b2581c4ef27b97e', pct: 100.0 },
  { name: 'dll_0102_staypoint.c', baseline: '4ae98194cd97d4672e5f02c7a2246fbb', pct: 100.0 },
  { name: 'dll_0103_curvefish.c', baseline: 'b645c817dfecd62dfbaf2ff498ea6f51', pct: 95.333 },
  { name: 'dll_0104_smallbasket.c', baseline: 'e43605d600fb8f434e1b1be6bf160a12', pct: 98.566 },
  { name: 'dll_0105_largecrate.c', baseline: '473e88d41d6b135dbf377dc504f7e736', pct: 99.626 },
  { name: 'dll_010A_fallladders.c', baseline: '467f79250b0ad77dff8ba95d1748e17f', pct: 100.0 },
  { name: 'dll_0111_doorlock.c', baseline: '860f367c4a6cbea0a07d7b1eb6dbee5c', pct: 100.0 },
  { name: 'dll_0112_seqobject.c', baseline: '8995adec5674d06e3cf156a75422cf8a', pct: 100.0 },
  { name: 'dll_0113_seqobj2.c', baseline: 'eff4191096e5ed54eff4a51f6adfdb67', pct: 100.0 },
  { name: 'dll_0115_dll115.c', baseline: '06815e41916bda89163f1bb5d5c59cb0', pct: 100.0 },
  { name: 'dll_0118_duster.c', baseline: '299f922b0a84a15c60684c419940206c', pct: 98.281 },
  { name: 'dll_0119_coldwatercontrol.c', baseline: '85674ca0a376c0c2d8dd674dff25f98b', pct: 100.0 },
  { name: 'dll_011A_decoration11a.c', baseline: '049df653c5507aec28c683a90528e484', pct: 100.0 },
  { name: 'dll_011B_landedarwing.c', baseline: '9fec2b44b33d3e5b915979f5fdd40539', pct: 100.0 },
  { name: 'dll_011C_staffactivated.c', baseline: '8382da9c07567e39cab4f317cfbafedf', pct: 100.0 },
  { name: 'dll_0125_curve.c', baseline: '1642d0df7268a2f0be4a6dc44badd923', pct: 100.0 },
  { name: 'dll_012B_fxemit.c', baseline: 'a331fb0e403728cd22b469cdf67be266', pct: 100.0 },
  { name: 'dll_012C_transporter.c', baseline: '0b491cbe463fc6fbc310d0179d5f784d', pct: 99.679 },
  { name: 'dll_012D_lfxemitter.c', baseline: 'c96865ca36ba856096eb6302c789219c', pct: 100.0 },
  { name: 'dll_0130_areafxemit.c', baseline: '243a75d13c928747cc3e40f69704f4af', pct: 100.0 },
  { name: 'dll_0133_sfxplayer.c', baseline: 'fe23cbc3ba1ba2ed28fa6d357705e561', pct: 99.842 },
  { name: 'dll_0135_texscroll.c', baseline: '59d287d5c2cf4edfafe0ce7784e9b049', pct: 100.0 },
  { name: 'dll_0138_groundanimator.c', baseline: '18d5a9055117f0470e3120877c5271d4', pct: 94.063 },
  { name: 'dll_013A_visanimator.c', baseline: '2e354b9717b677914071c31487882f03', pct: 100.0 },
  { name: 'dll_013C_xyzanimator.c', baseline: '497247647c787df05cc173e8dfcd2fab', pct: 98.717 },
  { name: 'dll_0140_fogcontrol.c', baseline: '95cb32668d4672718fca857b3ffc3d67', pct: 100.0 },
  { name: 'dll_0143_feseqobject.c', baseline: '0fe0b059a5b62a8a80541020c7232260', pct: 95.662 },
  { name: 'dll_0144_dll144.c', baseline: 'a812ce76b1672334f0c629811b0bffed', pct: 100.0 },
  { name: 'dll_0145_cloudprisoncontrol.c', baseline: '2ea3e1d3ee5f1aacfc4688fce7bb83fc', pct: 95.075 },
  { name: 'dll_0157_spiritdoorspirit.c', baseline: 'f0fdcdc207ddf4705134a6386c807664', pct: 100.0 },
  { name: 'dll_0158_gunpowderbarrel.c', baseline: 'c98236b21c7c18c0a9db54e56d3b3cf5', pct: 98.552 },
  { name: 'dll_015A_explodable.c', baseline: '934e8d26c4f98b5ca8c77a19f1c232f0', pct: 100.0 },
  { name: 'dll_015D_slidingdoor.c', baseline: 'c81f2c112f0ed7d624f6f425312184cd', pct: 100.0 },
  { name: 'dll_015F_attractor.c', baseline: '0fd305b2af4a6a8322fcffe7b9d9780f', pct: 100.0 },
  { name: 'dll_0166_exploded.c', baseline: 'f3e84dd0b760ea1801fffe88fe74ce9c', pct: 99.08 },
  { name: 'dll_0167_spiritdoorlock.c', baseline: '4e917340af932ebf179ad41d973fde4c', pct: 97.375 },
  { name: 'dll_016A_crrockfall.c', baseline: '6fc4b68d7789ec896738de6b6c9d04e8', pct: 96.52 },
  { name: 'dll_016C_dll16c.c', baseline: 'cce13f07477df715fd4cab8e81b67a29', pct: 100.0 },
  { name: 'dll_0172_linkblevcontrol.c', baseline: 'a287cca94f97f3ff5011197604fdc5d6', pct: 100.0 },
  { name: 'dll_017A_spiritprize.c', baseline: 'b93e1ddbc11872db6c06e3338196af42', pct: 99.044 },
  { name: 'dll_017F_moonseedbush.c', baseline: 'cfe8c02b7120c144384f310bd14ac686', pct: 100.0 },
  { name: 'dll_0184_animsharpclaw.c', baseline: '2018dd56e9765093116e22a425271f37', pct: 99.016 },
  { name: 'dll_018C_mmshshrine.c', baseline: '8bfb009fe014f629dd239052b4c6c7e8', pct: 99.599 },
  { name: 'dll_018D_mmshscales.c', baseline: 'd76f8a40ab48a49545ca8738dc4d5bc9', pct: 100.0 },
  { name: 'dll_018F_ecshshrine.c', baseline: '6e381b7df649b8bf5f3da208214bbd09', pct: 100.0 },
  { name: 'dll_0191_ecshcreator.c', baseline: '291d5f699408c4b2e28b0afe0be1bd8e', pct: 100.0 },
  { name: 'dll_0195_dbshshrine.c', baseline: '26f677ad833f4ed0fdca54f20c9b0ff5', pct: 100.0 },
  { name: 'dll_0196_dbshsymbol.c', baseline: '9d9924f624812dcb309244639f977979', pct: 97.485 },
  { name: 'dll_0197_dll197.c', baseline: 'ce66fce9c4888ece99e46a85f298568d', pct: 100.0 },
  { name: 'dll_019A_dll19a.c', baseline: 'a07768675f78e598e32c06694451cdba', pct: 100.0 },
  { name: 'dll_01A7_ediblemushroom.c', baseline: 'a0107ba01dba634db27e680b97601a0d', pct: 98.991 },
  { name: 'dll_01BD_paymentkiosk.c', baseline: '67b48fbb7b9b3d07ff0d38a0438695e0', pct: 100.0 },
  { name: 'dll_01CE_dll1ce.c', baseline: '554023ae581f9e5aca6cb25fbacd0868', pct: 99.85 },
  { name: 'dll_01D6_dll1d6.c', baseline: '495ecd95b20292e3a838db4c7b546726', pct: 98.696 },
  { name: 'dll_01DA_dll1da.c', baseline: 'a42a54974d4be50aeff8fc4c92e79373', pct: 98.72 },
  { name: 'dll_01DB_dll1db.c', baseline: '117523f40cada37df93d0d92ce224bd8', pct: 100.0 },
  { name: 'dll_01DF_dll1df.c', baseline: 'cf85072d298b8f171a3f22b89b65b000', pct: 100.0 },
  { name: 'dll_01F4_lamp.c', baseline: '25b0176442d0351aa08a7b8d45bb8d8e', pct: 100.0 },
  { name: 'dll_01F6_flag.c', baseline: 'dd4b365f4b3b3641e522000e9549052d', pct: 100.0 },
  { name: 'dll_01FC_laserbeam.c', baseline: 'f6930ca9417ec61f63922195a8eb87b6', pct: 100.0 },
  { name: 'dll_01FE_pressureswitch.c', baseline: '2a1e2e291fdd8058f292819e4a47fae2', pct: 98.537 },
  { name: 'dll_0206_lightsource.c', baseline: 'c4b6e55d2a2b6831dd43687ae32e39b5', pct: 99.613 },
  { name: 'dll_0219.c', baseline: '89e10a19eabc2f57128421017d9a5fdd', pct: 98.925 },
  { name: 'dll_021B.c', baseline: '68b2c1157756216a03af744bcb89956d', pct: 96.603 },
  { name: 'dll_022C_dll22c.c', baseline: '3805a460a4cbbe5a517cfd63b27155cf', pct: 98.851 },
  { name: 'dll_0238_linkalevco.c', baseline: 'd63b7270af7482298fa60cdb32551a81', pct: 100.0 },
  { name: 'dll_023F_dbegg.c', baseline: '990d3ee0cea1cef54b243031684af181', pct: 97.061 },
  { name: 'dll_0240_gcrobotblast.c', baseline: 'cb7762a50ca2af3cdd1189405fc2c860', pct: 100.0 },
  { name: 'dll_0241_drakorenergy.c', baseline: '6454469162789c0fff9711fb87458562', pct: 100.0 },
  { name: 'dll_0243_dbholecontrol1.c', baseline: '80a23aac3e8b127b6dde491e14ba885c', pct: 99.924 },
  { name: 'dll_024D_bossdrakor.c', baseline: '4e9d1b7eb80878b8c829390d19aba53e', pct: 97.357 },
  { name: 'dll_024E_drakordthornbush.c', baseline: 'ca7e09639cb008d92662e6ffabda9a6e', pct: 99.789 },
  { name: 'dll_025A_staticcamera.c', baseline: '1837a4fdbdbdd3c3890c2cab91a148e0', pct: 100.0 },
  { name: 'dll_025B_msplantings.c', baseline: '5357bd31656a6270588fa444d41a175e', pct: 100.0 },
  { name: 'dll_0266_kytesmum.c', baseline: '0a37c70fcfd8897ea3d15ffb5a9f6855', pct: 98.192 },
  { name: 'dll_0269_explodeplan.c', baseline: 'a2503236cf5fba4c9292bc8fbce22454', pct: 99.481 },
  { name: 'dll_0273_firepipe.c', baseline: 'd0ad1a84c7fdb86134829b0b802a75ef', pct: 100.0 },
  { name: 'dll_0284_shopitem.c', baseline: '9c6a48c9f3cd8c81ac2eb5bcda85e1b0', pct: 99.843 },
  { name: 'dll_028B.c', baseline: '30296e8378ce358de731a0f3e0da0d6e', pct: 99.095 },
  { name: 'dll_0299.c', baseline: '8ae87a840f40ede5dd834522f0f624d6', pct: 100.0 },
  { name: 'dll_029B_arwingandrossstuff.c', baseline: '80d83d27e0648ab59da1542164c3999f', pct: 97.982 },
  { name: 'dll_029E_Dummy29E.c', baseline: '27690f3b1fe1e4f17cad93207640c3cc', pct: 100.0 },
  { name: 'dll_02A0_ring.c', baseline: '6918f1dd8c1ae37329b9148c6965e8b7', pct: 99.044 },
  { name: 'dll_02A4.c', baseline: '661e9da5b703061690481c5c09fae552', pct: 99.784 },
  { name: 'dll_02AE_waterflowwe.c', baseline: '3a9d12139dd8ba5f2b634027adbda32d', pct: 98.81 },
  { name: 'dll_02B0_brokenpipe.c', baseline: '1f4532ca951598290659342eb285eee7', pct: 100.0 },
  { name: 'dll_02B1_cmbsrc.c', baseline: '234f4e1779935f3ea10a82c5b84b7930', pct: 96.363 },
  { name: 'dll_02B2_dustmotesou.c', baseline: 'b662aba8768729392bb5b906a31819b9', pct: 100.0 },
  { name: 'dll_02B6_cnthitobjec.c', baseline: 'e96e337d15b75bac612b6e42921a8380', pct: 100.0 },
  { name: 'dll_02B7_mcupgrade.c', baseline: '2a4c0398fa163325719862bf60357cda', pct: 100.0 },
  { name: 'dll_02B8_mcupgradema.c', baseline: '6b1d5bd46c15a4b8f97444229175fdfb', pct: 100.0 },
  { name: 'dll_02B9_mcstaffeffe.c', baseline: 'e467bb81f1dcd16feae8e8a0ab17d94a', pct: 100.0 },
  { name: 'dll_02BB_gflevelcon.c', baseline: 'b3ffd3d04aa3d8b3ee0c03983dee2d80', pct: 98.954 },
  { name: 'dll_02BC_andross.c', baseline: '83d199fae3a62d338c7eca8933834d04', pct: 96.72 },
  { name: 'dll_02BF_androssligh.c', baseline: '73d9a3f658b4845ad13dda7cd6c4cf1a', pct: 100.0 },
  { name: 'dll_1e7.c', baseline: '597bc03f6185c05ca1abecc5f8e3041f', pct: 95.471 },
  { name: 'dll_3b.c', baseline: '04decc38e941bbfb5fa49740c04e6e7a', pct: 99.337 },
  { name: 'dll_3e.c', baseline: '5c28efdf1fb01a3f169f6b8f76f1174b', pct: 94.464 },
  { name: 'dll_43.c', baseline: 'f51b7cc44888d32eec239c81b561e940', pct: 100.0 },
  { name: 'dll_4d.c', baseline: '5f8a105af4c59520057c3ea79be3d2f6', pct: 100.0 },
  { name: 'dll_60.c', baseline: 'd886ac2abd6169510daa74a1530b3a3a', pct: 100.0 },
  { name: 'dll_8011d918.c', baseline: '7c567f80d97a1ff0bd187966b1a5b083', pct: 100.0 },
  { name: 'dll_80136a40.c', baseline: '0c7554114e00c5a3af95133d8191dbb7', pct: 90.447 },
  { name: 'dll_80161130.c', baseline: '994720f4fb18d4f8922ee7c6e1673f8d', pct: 100.0 },
  { name: 'dll_801ac01c.c', baseline: '4bb13653a65f25d611cf8635ba7f44b9', pct: 100.0 },
  { name: 'dll_801b9ecc.c', baseline: '6c9f88bd2b451cbfdbf9ee3aac9a83ed', pct: 91.21 },
  { name: 'dll_801d0828.c', baseline: '7a2a6996ba207bb95358bc191ac377ee', pct: 100.0 },
  { name: 'dll_801d4198.c', baseline: '39a3d08be23cd4e4d01b4ce32b97016c', pct: 100.0 },
  { name: 'dll_801e66dc.c', baseline: '6514ef81d0c700d5e6ed9055e34676c6', pct: 100.0 },
  { name: 'dll_8b.c', baseline: '3c0c2ecee64ec5ac90d25e91efdc7507', pct: 100.0 },
  { name: 'dll_a6.c', baseline: 'f55eaee83acb802053acb1eccaea9730', pct: 100.0 },
  { name: 'dll_b2.c', baseline: '6261ca0130ab294f74b8cb5786146195', pct: 100.0 },
  { name: 'dll_b3.c', baseline: '0e6826627815ca07597235f9b3e1eb99', pct: 100.0 },
  { name: 'dll_b4.c', baseline: '8b40333f4a7d61513a2dcee02fc149e9', pct: 100.0 },
  { name: 'dll_b6.c', baseline: 'de93aaeac52b26a31b81a071d9dccf49', pct: 97.2 },
  { name: 'dll_b7.c', baseline: '7c0b9bb18d4f113364f6dd629e6f1e5a', pct: 97.612 },
  { name: 'dll_b8.c', baseline: '8ca8719a3e5ccf0b649f5efea5f7605c', pct: 100.0 },
  { name: 'dll_bb.c', baseline: '40a5fc21d48237606a3b4fdd8912dfe3', pct: 99.327 },
  { name: 'dll_bc.c', baseline: 'a3573bd15d9953d998bd80aa5993b700', pct: 100.0 },
  { name: 'drcloudcage.c', baseline: '88b79a164828cd0b1b1c28d5e6a125cb', pct: 97.863 },
  { name: 'drpickup.c', baseline: 'c107f558f2cd18817b82a2768375e22f', pct: 100.0 },
  { name: 'duster.c', baseline: 'd3d644edc5a0fa662728d3b7eda98ca5', pct: 99.058 },
  { name: 'fall_ladders.c', baseline: '41e9986df405a2c7a8038ad60163ac02', pct: 98.94 },
  { name: 'fireflylantern.c', baseline: '644ec21c101cc06f00880ba9166c6e91', pct: 99.26 },
  { name: 'frontend_control.c', baseline: '7f3be6d8b4772a02f8b58784efe85b2d', pct: 100.0 },
  { name: 'landedarwing.c', baseline: '166a28cb5af01b4d9a396985f2ba3d10', pct: 100.0 },
  { name: 'magicplant.c', baseline: '39b94b4aeb99cf3e79f79fb6abcfe3d0', pct: 98.641 },
  { name: 'maybetemplate.c', baseline: '4d8e024054e0711eb4976ea856f40d5a', pct: 93.288 },
  { name: 'mmp_cratercritter.c', baseline: 'b34c0e6bbff87a170e59ee7f6d0ee3a3', pct: 91.531 },
  { name: 'mmsh_waterspike.c', baseline: 'dfa33bf1fb594eec8688201648836e4d', pct: 100.0 },
  { name: 'n_options.c', baseline: 'c5e4c26653322fcc23625d0a2df20c77', pct: 94.866 },
  { name: 'newseqobj.c', baseline: '3f2d2de1ab70065b6ddcf97e94e1eec1', pct: 95.886 },
  { name: 'objfx.c', baseline: '8e566327d60843a27132dc481e14df77', pct: 98.0 },
  { name: 'picmenu.c', baseline: '155666a71bee9da8e7ec0050fee7b9df', pct: 99.246 },
  { name: 'prof.c', baseline: '3a18b25e245190d00a61f2714fcca226', pct: 98.917 },
  { name: 'scchieflightfoot.c', baseline: '43636bfcb09cf3f0f6012bd48a344212', pct: 100.0 },
  { name: 'seqobj11d.c', baseline: 'c272b898c61e074ef1f8b50a78634753', pct: 94.112 },
  { name: 'seqobj11e.c', baseline: '53c70cbc96938727c9050403ac199a22', pct: 99.52 },
  { name: 'skeetla.c', baseline: 'bc19786cf8731e0b30574c39dbaaae0a', pct: 96.061 },
  { name: 'staffactivated_helpers.c', baseline: 'e55024d12c1cd78e8633e6497c190559', pct: 100.0 },
  { name: 'swarmbaddie.c', baseline: 'f760bb4373e372e2d67fc7b51630bd44', pct: 93.321 },
  { name: 'texscroll2.c', baseline: 'd011d1c37aab5746bd2d843f88e3a84b', pct: 100.0 },
  { name: 'trex_lazerwall.c', baseline: '219dc6d59a02e7c7b29ed9e67de761fd', pct: 97.183 },
  { name: 'tricky.c', baseline: '47950d8e45a3c225c7206366a403d4c3', pct: 95.312 },
  { name: 'tumbleweedbush.c', baseline: '67a480b42279c7357a8c992b2aabb9b4', pct: 97.916 },
  { name: 'viewfinder.c', baseline: 'de1f6dd3dd83c464254c7043c60e57d5', pct: 100.0 },
  { name: 'warppad.c', baseline: '72a6ad76ddc089887b896147a6873438', pct: 100.0 },
  { name: 'weapone6.c', baseline: 'a67691c71bfd8777dab06f54c93cb354', pct: 98.765 },
]

const CLEAN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['file', 'verified', 'final_pct', 'changes', 'notes'],
  properties: {
    file: { type: 'string' },
    verified: { type: 'boolean', description: 'true if final build compiles AND final_pct >= baseline pct' },
    final_pct: { type: 'number' },
    changes: { type: 'array', items: { type: 'string' } },
    removed_functions: { type: 'array', items: { type: 'string' }, description: 'dead FUN_ bodies removed' },
    removed_decls: { type: 'array', items: { type: 'string' }, description: 'unused includes/externs/forward-decls removed' },
    kept_funcs: { type: 'array', items: { type: 'string' }, description: 'FUN_ left in place + why (called / load-bearing / match dropped)' },
    notes: { type: 'string' },
  },
}
const REVIEW_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['file', 'findings', 'overall'],
  properties: {
    file: { type: 'string' },
    overall: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['severity', 'issue', 'suggestion'],
        properties: {
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          issue: { type: 'string' },
          suggestion: { type: 'string' },
        },
      },
    },
  },
}
const FIX_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['file', 'verified', 'final_pct', 'applied', 'skipped'],
  properties: {
    file: { type: 'string' },
    verified: { type: 'boolean' },
    final_pct: { type: 'number' },
    applied: { type: 'array', items: { type: 'string' } },
    skipped: { type: 'array', items: { type: 'string' } },
  },
}

const GATES = (path, baseline, pct) => `VERIFICATION — two gates, use the right one:
  (A) BYTE-NEUTRAL edits (renames, comments, struct typing, reordering, removing UNUSED includes/externs/forward-declarations): must keep the .o identical. Check with:
        python3 /tmp/dllclean/verify_unit.py ${path}
      It prints an md5 (compiles to a temp; does NOT touch the build). It MUST equal ${baseline}. If a removed include/extern/decl was actually needed, this prints COMPILE FAILED or a different md5 -> revert that one removal.
  (B) FUNCTION-SET changes (removing a dead FUN_ body) legitimately change the .o, so md5 will differ. Gate these on MATCH instead:
        python3 /tmp/dllclean/match_pct.py ${path}
      It compiles the unit to its real .o and prints "<fuzzy_pct> (matched_fns x/y)". The fuzzy_pct MUST stay >= ${pct} (the baseline). If it drops, the function was real/load-bearing -> revert it.
  FINAL gate before finishing: python3 /tmp/dllclean/match_pct.py ${path} must compile and report fuzzy_pct >= ${pct}.
  NEVER run ninja. NEVER add inline asm. NEVER edit any file other than ${path}.`

function cleanPrompt(name, baseline, pct) {
  const path = `src/main/dll/${name}`
  return `Turn this Ghidra-derived decomp C file into plausible ORIGINAL source while preserving the build.

TARGET: ${path}
BASELINE .o md5: ${baseline}   BASELINE match %: ${pct}
REFERENCE (gold-standard style): read ${REFERENCE} in full FIRST, then read the ENTIRE target file.

${GATES(path, baseline, pct)}

DO THE FOLLOWING:
1. File-header block comment: what the object is, role/behavior, key game bits/modes — inferred ONLY from code. Factual.
2. **Remove dead FUN_ function BODIES.** Ghidra leaves uncalled drift duplicates named FUN_xxxxxxxx. For EACH FUN_ definition in this file:
   - Grep the WHOLE repo for callers:  grep -rn 'FUN_xxxxxxxx' src/   (use the real symbol).
   - If it is NOT called anywhere (a mirrored declaration in a header is fine; a real call/address-take is NOT), DELETE the whole function body AND tidy what it leaves behind: the orphaned preceding comment, any now-pointless #pragma around it, and collapse the doubled blank lines so the file reads naturally. Do NOT leave dangling pragmas/comments/whitespace.
   - Then run match_pct.py: if it compiles and fuzzy_pct >= ${pct}, keep the removal; otherwise revert it (it was load-bearing) and record it in kept_funcs.
   - A FUN_ that IS called must stay (renaming it needs symbols.txt edits, out of scope) — leave it, note in kept_funcs.
3. **Aggressively prune unused symbols** (there is a LOT of this): unused #includes, unused file-scope externs, unused forward declarations (including unused FUN_ DECLARATIONS). Remove each and confirm via verify_unit.py (compile + md5 unchanged); if a removal breaks the build or changes md5, it was needed — revert just that one.
4. Dedupe duplicate #includes; consolidate remaining file-scope externs into one block near the top (short origin comment where the home TU is obvious).
5. Name magic numbers via #define/enum where meaning is clear (game bits, object/seq type ids, anim event ids, vtable slots, map ids). Skeptical of sfx-id literals. A wrong name is worse than the literal.
6. Type raw derefs where byte-neutral; rename cryptic locals (always byte-neutral); /* 0xNN */ struct field comments + STATIC_ASSERT only where offsets are confirmable. Rename unkNN/padNN only when usage is clear.
7. Fix Ghidra idioms (byte-neutral): 'i = i + 1' -> 'i++'; '(float*)0x0' -> NULL; 'memset(&x,0,0xNN)' where 0xNN==sizeof(x) -> sizeof(x); bare 'return;' in a value-returning fn -> explicit value.

Comments terse: default none; one short line only when the WHY is non-obvious.
Finish with the FINAL match_pct.py gate. verified MUST be true. Return the structured result.`
}

function reviewPrompt(name) {
  const path = `src/main/dll/${name}`
  return `Read-only review. Do NOT edit. Do NOT build.
Read ${REFERENCE} (gold standard) and ${path} (just cleaned).
Assess for: leftover dead FUN_ bodies that should have been removed; leftover unused includes/externs/forward-decls; orphaned pragmas/comments/odd blank-line gaps left behind by removals; readability, naming (locals/#defines/struct fields), file-header quality; struct typing; Ghidra idioms; value-returning fns with bare returns.
Report concrete, actionable findings only (no praise). Each: severity + issue + specific suggestion. If genuinely clean, return empty findings with an 'overall' saying so.`
}

function fixPrompt(name, baseline, pct, findings) {
  const path = `src/main/dll/${name}`
  const list = (findings || []).map((f, i) => `${i + 1}. [${f.severity}] ${f.issue}\n   -> ${f.suggestion}`).join('\n')
  return `Apply the SAFE review findings below to ${path}, preserving the build.

${GATES(path, baseline, pct)}

REVIEW FINDINGS:
${list || '(none)'}

Apply each finding only if it is safe under the gates above. SKIP (and report why) anything that: drops match % / breaks the build, is speculative (guessing a name/offset/return you can't confirm), or needs another file. For dead-FUN_-removal findings, do the whole-repo caller grep + match_pct gate just as in the clean stage and tidy orphaned pragmas/comments/blanks.
Finish with the FINAL match_pct.py gate. verified MUST be true. Return what you applied and skipped.`
}

phase('Clean')
const files = (Array.isArray(args) ? args : BATCH).slice(CHUNK_START, CHUNK_START + CHUNK_SIZE)
let next = 0
async function lane() {
  const out = []
  while (next < files.length) {
    const f = files[next++]
    const clean = await agent(cleanPrompt(f.name, f.baseline, f.pct), {
      label: `clean:${f.name}`, phase: 'Clean', schema: CLEAN_SCHEMA,
    })
    const review = await agent(reviewPrompt(f.name), {
      label: `review:${f.name}`, phase: 'Review', schema: REVIEW_SCHEMA, model: 'sonnet',
    })
    let fix = null
    const findings = (review && review.findings) || []
    if (findings.length) {
      fix = await agent(fixPrompt(f.name, f.baseline, f.pct, findings), {
        label: `fix:${f.name}`, phase: 'Fix', schema: FIX_SCHEMA,
      })
    }
    out.push({ name: f.name, baseline: f.baseline, pct: f.pct, clean, review, fix })
  }
  return out
}
const lanes = await parallel(Array.from({ length: CONCURRENCY }, () => lane))
const results = lanes.filter(Boolean).flat()

const ok = results.filter(Boolean)
return {
  total: files.length,
  completed: ok.length,
  verified: ok.filter((r) => (r.fix ? r.fix.verified : r.clean && r.clean.verified)).length,
  unverified: ok.filter((r) => (r.fix ? !r.fix.verified : !(r.clean && r.clean.verified))).map((r) => r.name),
  per_file: ok.map((r) => ({
    name: r.name,
    baseline_pct: r.pct,
    final_pct: r.fix ? r.fix.final_pct : (r.clean && r.clean.final_pct),
    verified: r.fix ? r.fix.verified : (r.clean && r.clean.verified),
    removed_functions: r.clean && r.clean.removed_functions,
    removed_decls: r.clean && r.clean.removed_decls,
    kept_funcs: r.clean && r.clean.kept_funcs,
    review_count: (r.review && r.review.findings || []).length,
    applied: r.fix && r.fix.applied,
  })),
}
