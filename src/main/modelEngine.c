#include "dlls/objects/597_SnowBike.h"
#include "dlls/objects/226.h"
#include "dlls/objects/201_Baddie.h"
#include "dlls/object_descriptor.h"
#include "dlls/objects/198_AnimatedObj.h"
#include "dlls/objects/199_DIM2RoofRub.h"
#include "dlls/objects/200_DepthOfFieldPoint.h"
#include "dlls/objects/202.h"
#include "dlls/objects/203.h"
#include "dlls/objects/204_ChukChuk.h"
#include "dlls/objects/205_IceBall.h"
#include "dlls/objects/206.h"
#include "dlls/objects/207_CannonClaw.h"
#include "dlls/objects/208_Grimble.h"
#include "dlls/objects/209_TumbleWeedB.h"
#include "dlls/objects/210.h"
#include "dlls/objects/212_SkeetlaWall.h"
#include "dlls/objects/213_Kaldachom.h"
#include "dlls/objects/214_KaldachomMe.h"
#include "dlls/objects/215.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "dlls/objects/217_Pollen.h"
#include "dlls/objects/219_MikaBomb.h"
#include "dlls/objects/220_MikaBombShadow.h"
#include "dlls/objects/221_GCbaddieShield.h"
#include "dlls/objects/222_BaddieInterestP.h"
#include "dlls/objects/223_Hagabon.h"
#include "dlls/objects/224_SwarmBaddie.h"
#include "dlls/objects/225_WispBaddie.h"
#include "dlls/objects/227_Fireball.h"
#include "dlls/objects/228_FlameThrowerspe.h"
#include "dlls/objects/229_Shield.h"
#include "dlls/objects/230_ReStartMark.h"
#include "dlls/objects/231.h"
#include "dlls/objects/232_Checkpoint4.h"
#include "dlls/objects/233_Setuppoint.h"
#include "dlls/objects/234_Sideload.h"
#include "dlls/objects/235.h"
#include "dlls/objects/236_InfoPoint.h"
#include "dlls/objects/237.h"
#include "dlls/objects/238_EffectBox.h"
#include "dlls/objects/239.h"
#include "dlls/objects/240_WarpPoint.h"
#include "dlls/objects/241_InvHit.h"
#include "dlls/objects/242_iceblast.h"
#include "dlls/objects/243_flameblast.h"
#include "dlls/objects/244.h"
#include "dlls/objects/245_SidekickBal.h"
#include "dlls/objects/246_Area.h"
#include "dlls/objects/247.h"
#include "dlls/objects/248_LevelName.h"
#include "dlls/objects/249.h"
#include "dlls/objects/250_InvisibleHi.h"
#include "dlls/objects/251.h"
#include "dlls/objects/252.h"
#include "dlls/objects/253.h"
#include "dlls/objects/254_MagicPlant.h"
#include "dlls/objects/255.h"
#include "dlls/objects/256_TrickyWarp.h"
#include "dlls/objects/257_TrickyGuard.h"
#include "dlls/objects/258_StayPoint.h"
#include "dlls/objects/259_CurveFish.h"
#include "dlls/objects/260_SmallBasket.h"
#include "dlls/objects/261_LargeCrate.h"
#include "dlls/objects/262.h"
#include "dlls/objects/263.h"
#include "dlls/objects/264_EndObject.h"
#include "dlls/objects/265.h"
#include "dlls/objects/266_Fall_Ladder.h"
#include "dlls/objects/267_FireFlyLant.h"
#include "dlls/objects/268_LanternFire.h"
#include "dlls/objects/269_PortalSpell.h"
#include "dlls/objects/270.h"
#include "dlls/objects/271_MMP_Bridge.h"
#include "dlls/objects/272.h"
#include "dlls/objects/273.h"
#include "dlls/objects/274.h"
#include "dlls/objects/275.h"
#include "dlls/objects/276_IMMultiSeq.h"
#include "dlls/objects/277.h"
#include "dlls/objects/278_WM_Column.h"
#include "dlls/objects/279_AppleOnTree.h"
#include "dlls/objects/280_Duster.h"
#include "dlls/objects/281_coldWaterCo.h"
#include "dlls/objects/282.h"
#include "dlls/objects/283_Landed_Arwi.h"
#include "dlls/objects/284.h"
#include "dlls/objects/285.h"
#include "dlls/objects/286_MagicCaveBo.h"
#include "dlls/objects/287_MagicCaveTo.h"
#include "dlls/objects/288_TrickyGuard.h"
#include "dlls/objects/289.h"
#include "dlls/objects/290_CCTestInfot.h"
#include "dlls/objects/291_fuelCell.h"
#include "dlls/objects/292.h"
#include "dlls/objects/293_curve.h"
#include "dlls/objects/295.h"
#include "dlls/objects/296_KT_Torch.h"
#include "dlls/objects/297_CampFire.h"
#include "dlls/objects/298_CFCrate.h"
#include "dlls/objects/299_FXEmit.h"
#include "dlls/objects/300_Transporter.h"
#include "dlls/objects/301_LFXEmitter.h"
#include "dlls/objects/302.h"
#include "dlls/objects/303_BarrelPad.h"
#include "dlls/objects/304_AreaFXEmit.h"
#include "dlls/objects/305.h"
#include "dlls/objects/306_WaterFallSp.h"
#include "dlls/objects/307_sfxPlayer.h"
#include "dlls/objects/308_texscroll2.h"
#include "dlls/objects/309_texscroll.h"
#include "dlls/objects/310_WaveAnimato.h"
#include "dlls/objects/311_AlphaAnimat.h"
#include "dlls/objects/312_GroundAnima.h"
#include "dlls/objects/313_HitAnimator.h"
#include "dlls/objects/314_VisAnimator.h"
#include "dlls/objects/315_WallAnimato.h"
#include "dlls/objects/316_XYZAnimator.h"
#include "dlls/objects/317_ExplodeAnim.h"
#include "dlls/objects/318.h"
#include "dlls/objects/319_TexFrameAni.h"
#include "dlls/objects/320_fogControl.h"
#include "dlls/objects/321_Lightning.h"
#include "dlls/objects/322_FElevContro.h"
#include "dlls/objects/323_FEseqobject.h"
#include "dlls/objects/324.h"
#include "dlls/objects/325_CloudPrison.h"
#include "dlls/objects/328_CFGuardian.h"
#include "dlls/objects/329.h"
#include "dlls/objects/330_CFPowerBase.h"
#include "dlls/objects/331_CFMainCryst.h"
#include "dlls/objects/332.h"
#include "dlls/objects/334_CFPrisonGua.h"
#include "dlls/objects/335_CFPrisonUnc.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dlls/objects/339_CFPerch.h"
#include "dlls/objects/340.h"
#include "dlls/objects/343_SpiritDoorS.h"
#include "dlls/objects/344.h"
#include "dlls/objects/345.h"
#include "dlls/objects/346.h"
#include "dlls/objects/347_CFForceFiel.h"
#include "dlls/objects/349.h"
#include "dlls/objects/351.h"
#include "dlls/objects/354_CFMagicWall.h"
#include "dlls/objects/356_CFLevelCont.h"
#include "dlls/objects/358.h"
#include "dlls/objects/359_SpiritDoorL.h"
#include "dlls/objects/361_IMIceMounta.h"
#include "dlls/objects/362_CRrockfall.h"
#include "dlls/objects/363.h"
#include "dlls/objects/364.h"
#include "dlls/objects/365_IMIcePillar.h"
#include "dlls/objects/366_IMAnimSpace.h"
#include "dlls/objects/367_IMSpaceThru.h"
#include "dlls/objects/368_IMSpaceRing.h"
#include "dlls/objects/369_IMSpaceRing.h"
#include "dlls/objects/370_LINKB_levco.h"
#include "dlls/objects/371_LINK_levcon.h"
#include "dlls/objects/372_CCriverflow.h"
#include "dlls/objects/373_DFropenode.h"
#include "dlls/objects/375.h"
#include "dlls/objects/376_DFSH_Shrine.h"
#include "dlls/objects/377_DFSH_ObjCre.h"
#include "dlls/objects/378_SpiritPrize.h"
#include "dlls/objects/379_DFSH_LaserB.h"
#include "dlls/objects/381.h"
#include "dlls/objects/382_MMP_levelco.h"
#include "dlls/objects/383.h"
#include "dlls/objects/384_MMP_asteroi.h"
#include "dlls/objects/385_MMP_trenchF.h"
#include "dlls/objects/386_MMP_moonroc.h"
#include "dlls/objects/387_MMP_gyserve.h"
#include "dlls/objects/388.h"
#include "dlls/objects/389_CCgasvent.h"
#include "dlls/objects/390_CCgasventCo.h"
#include "dlls/objects/391_CCqueen.h"
#include "dlls/objects/392_CClightfoot.h"
#include "dlls/objects/393_CCSharpclaw.h"
#include "dlls/objects/394_CCpedstal.h"
#include "dlls/objects/395_CClevcontro.h"
#include "dlls/objects/396_MMSH_Shrine.h"
#include "dlls/objects/397_MMSH_Scales.h"
#include "dlls/objects/398_MMSH_WaterS.h"
#include "dlls/objects/399_ECSH_Shrine.h"
#include "dlls/objects/400_ECSH_Cup.h"
#include "dlls/objects/401_ECSH_Creato.h"
#include "dlls/objects/402_GPSH_Shrine.h"
#include "dlls/objects/403_GPSH_ObjCre.h"
#include "dlls/objects/404_GPSH_Scene.h"
#include "dlls/objects/405_DBSH_Shrine.h"
#include "dlls/objects/406_DBSH_Symbol.h"
#include "dlls/objects/407.h"
#include "dlls/objects/408_NWSH_levcon.h"
#include "dlls/objects/409.h"
#include "dlls/objects/410.h"
#include "dlls/objects/411.h"
#include "dlls/objects/412.h"
#include "dlls/objects/413.h"
#include "dlls/objects/414.h"
#include "dlls/objects/415_NW_treebrid.h"
#include "dlls/objects/416_NW_geyser.h"
#include "dlls/objects/417_NW_mammoth.h"
#include "dlls/objects/418_NW_tricky.h"
#include "dlls/objects/419.h"
#include "dlls/objects/420.h"
#include "dlls/objects/421_NW_levcontr.h"
#include "dlls/objects/422_SH_tricky.h"
#include "dlls/objects/423.h"
#include "dlls/objects/424_SH_killermu.h"
#include "dlls/objects/425_BombPlant.h"
#include "dlls/objects/426_BombPlantSp.h"
#include "dlls/objects/427_BombPlantin.h"
#include "dlls/objects/428_SH_queenear.h"
#include "dlls/objects/429_SH_thorntai.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "dlls/objects/431_SH_swaplift.h"
#include "dlls/objects/432_SH_swapston.h"
#include "dlls/objects/433_SH_staff.h"
#include "dlls/objects/434_SH_staffHaz.h"
#include "dlls/objects/435_SH_Beacon.h"
#include "dlls/objects/436_SH_EmptyTum.h"
#include "dlls/objects/437.h"
#include "dlls/objects/438_SC_levelcon.h"
#include "dlls/objects/439.h"
#include "dlls/objects/440_SC_totempol.h"
#include "dlls/objects/441_SC_Cloudrun.h"
#include "dlls/objects/442_SC_totempuz.h"
#include "dlls/objects/443_SC_totembon.h"
#include "dlls/objects/444_SC_totemstr.h"
#include "dlls/objects/445.h"
#include "dlls/objects/446.h"
#include "dlls/objects/447_DIMLavaBall.h"
#include "dlls/objects/448_DIMLogFire.h"
#include "dlls/objects/449_DIMSnowBall.h"
#include "dlls/objects/450_DIMSnowBall.h"
#include "dlls/objects/451_DIMGate.h"
#include "dlls/objects/452_DIMIceWall.h"
#include "dlls/objects/453_DIMBarrier.h"
#include "dlls/objects/454_DIMCannon.h"
#include "dlls/objects/455_DIMLavaSmas.h"
#include "dlls/objects/456_DIMBridgeCo.h"
#include "dlls/objects/457_DIMDismount.h"
#include "dlls/objects/458_DIMExplosio.h"
#include "dlls/objects/459_DIMWoodDoor.h"
#include "dlls/objects/460_DIMMagicBri.h"
#include "dlls/objects/461_DIM_LevelCo.h"
#include "dlls/objects/462.h"
#include "dlls/objects/463.h"
#include "dlls/objects/465_DIMTruthHor.h"
#include "dlls/objects/466_WORLDplanet.h"
#include "dlls/objects/467.h"
#include "dlls/objects/468_WORLDAstero.h"
#include "dlls/objects/469_DIM2Conveyo.h"
#include "dlls/objects/470.h"
#include "dlls/objects/471_DIM2SnowBal.h"
#include "dlls/objects/472_DIM2PathGen.h"
#include "dlls/objects/473_DIM2PrisonM.h"
#include "dlls/objects/474.h"
#include "dlls/objects/475.h"
#include "dlls/objects/476_DIM2IceFloe.h"
#include "dlls/objects/477_DIM2Icicle.h"
#include "dlls/objects/478_DIM2LavaCon.h"
#include "dlls/objects/479.h"
#include "dlls/objects/480_DIM_Boss.h"
#include "dlls/objects/481_DIM_BossGut.h"
#include "dlls/objects/482_DIM_BossTon.h"
#include "dlls/objects/483_DIM_BossGut.h"
#include "dlls/objects/484_MAGICMaker.h"
#include "dlls/objects/485_DIM_BossSpi.h"
#include "dlls/objects/486_DIMbosscrac.h"
#include "dlls/objects/487_DIMbossfire.h"
#include "dlls/objects/488_SB_Galleon.h"
#include "dlls/objects/489_SB_Propelle.h"
#include "dlls/objects/490_SB_ShipHead.h"
#include "dlls/objects/491_SB_ShipMast.h"
#include "dlls/objects/492_SB_ShipGun.h"
#include "dlls/objects/493_SB_FireBall.h"
#include "dlls/objects/494_SB_CannonBa.h"
#include "dlls/objects/495_SB_CloudBal.h"
#include "dlls/objects/496_SB_KyteCage.h"
#include "dlls/objects/497_SB_SeqDoor.h"
#include "dlls/objects/498_SB_CageKyte.h"
#include "dlls/objects/499_SB_MiniFire.h"
#include "dlls/objects/500.h"
#include "dlls/objects/501.h"
#include "dlls/objects/502.h"
#include "dlls/objects/503_SB_ShipGunB.h"
#include "dlls/objects/504_WM_Galleon.h"
#include "dlls/objects/505_WM_ObjCreat.h"
#include "dlls/objects/506_WM_seqobjec.h"
#include "dlls/objects/507.h"
#include "dlls/objects/508.h"
#include "dlls/objects/509_WM_LaserTar.h"
#include "dlls/objects/510.h"
#include "dlls/objects/511.h"
#include "dlls/objects/512.h"
#include "dlls/objects/513_WM_colrise.h"
#include "dlls/objects/516_WM_Torch.h"
#include "dlls/objects/518_LightSource.h"
#include "dlls/objects/519_WM_Worm.h"
#include "dlls/objects/521_WM_LevelCon.h"
#include "dlls/objects/522_WM_GeneralS.h"
#include "dlls/objects/525_WM_seqpoint.h"
#include "dlls/objects/529.h"
#include "dlls/objects/544.h"
#include "dlls/objects/592_KT_Rex.h"
#include "dlls/objects/599_DR_EarthWar.h"
#include "dlls/objects/601_SB_Cloudrun.h"
#include "dlls/objects/609_DR_LaserCan.h"
#include "dlls/objects/684_LGTControlL.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "dlls/objects/598_DIMSnowHorn.h"
#include "main/dll/LGT/dll_02AA_lgtdirectionallight.h"
#include "main/dll/LGT/dll_02A9_lgtpointlight.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/dll/dll_0043_cameramodestaffanim.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/dll_0046_cameramodedebug.h"
#include "main/dll/dll_0047_cameramodepath.h"
#include "main/dll/dll_0048_cameramodestatic.h"
#include "main/dll/dll_0049_cameramodecombat.h"
#include "main/dll/dll_004A_cameramodeshipbattle.h"
#include "main/dll/dll_004B_cameramodeclimb.h"
#include "main/dll/dll_004C_cameramodefixed.h"
#include "main/dll/dll_004D_cameramodenpcspeak.h"
#include "main/dll/dll_004E_cameramodeworldmap.h"
#include "main/dll/dll_004F_cameramode.h"
#include "main/dll/dll_0050_cameramodecrawl.h"
#include "main/dll/dll_0051_cameramodecannon.h"
#include "main/dll/dll_0052_cameramodeforcebehind.h"
#include "main/dll/dll_0053_cameramodecloudrunner.h"
#include "main/dll/dll_0054_dll54.h"
#include "main/dll/dll_0055_cameramode.h"
#include "main/dll/dll_0056_cameramodearwing.h"
#include "main/dll/dll_0057_cameramodetitle.h"
#include "main/dll/dll_0058_dummy58.h"
#include "main/dll/dll_0059_dll59func0.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/dll_005B_modgfx.h"
#include "main/dll/dll_005C_modgfx.h"
#include "main/dll/dll_005D_modgfx.h"
#include "main/dll/dll_005E_modgfx.h"
#include "main/dll/dll_005F_modgfx.h"
#include "main/dll/dll_0060_modgfx.h"
#include "main/dll/dll_0061_modgfx.h"
#include "main/dll/dll_0062_modgfx.h"
#include "main/dll/dll_0063_modgfx.h"
#include "main/dll/dll_0064_modgfx.h"
#include "main/dll/dll_0065_modgfx.h"
#include "main/dll/dll_0066_modgfx.h"
#include "main/dll/dll_0067_modgfx.h"
#include "main/dll/dll_0068_modgfx.h"
#include "main/dll/dll_0069_modgfx.h"
#include "main/dll/dll_006A_modgfx.h"
#include "main/dll/dll_006B_modgfx.h"
#include "main/dll/dll_006C_dummy6c.h"
#include "main/dll/dll_006D_modgfx.h"
#include "main/dll/dll_006E_modgfx.h"
#include "main/dll/dll_006F_modgfx.h"
#include "main/dll/dll_0070_modgfx.h"
#include "main/dll/dll_0071_modgfx.h"
#include "main/dll/dll_0072_modgfx.h"
#include "main/dll/dll_0073_modgfx.h"
#include "main/dll/dll_0074_modgfx.h"
#include "main/dll/dll_0075_modgfx.h"
#include "main/dll/dll_0076_modgfx.h"
#include "main/dll/dll_0077_modgfx.h"
#include "main/dll/dll_0078_modgfx.h"
#include "main/dll/dll_0079_modgfx.h"
#include "main/dll/dll_007A_modgfx.h"
#include "main/dll/dll_007B_modgfx.h"
#include "main/dll/dll_007C_modgfx.h"
#include "main/dll/dll_007D_modgfx.h"
#include "main/dll/dll_007E_modgfx.h"
#include "main/dll/dll_007F_modgfx.h"
#include "main/dll/dll_0080_modgfx.h"
#include "main/dll/dll_0081_modgfx.h"
#include "main/dll/dll_0082_modgfx.h"
#include "main/dll/dll_0083_modgfx.h"
#include "main/dll/dll_0084_modgfx.h"
#include "main/dll/dll_0085_modgfx.h"
#include "main/dll/dll_0086_modgfx.h"
#include "main/dll/dll_0087_modgfx.h"
#include "main/dll/dll_0088_modgfx.h"
#include "main/dll/dll_0089_modgfx.h"
#include "main/dll/dll_008A_modgfx.h"
#include "main/dll/dll_008B_modgfx.h"
#include "main/dll/dll_008C_modgfx.h"
#include "main/dll/dll_008D_modgfx.h"
#include "main/dll/dll_008E_modgfx.h"
#include "main/dll/dll_008F_modgfx.h"
#include "main/dll/dll_0090_modgfx.h"
#include "main/dll/dll_0091_modgfx.h"
#include "main/dll/dll_0092_modgfx.h"
#include "main/dll/dll_0093_modgfx.h"
#include "main/dll/dll_0094_modgfx.h"
#include "main/dll/dll_0095_modgfx.h"
#include "main/dll/dll_0096_modgfx.h"
#include "main/dll/dll_0097_modgfx.h"
#include "main/dll/dll_0098_modgfx.h"
#include "main/dll/dll_0099_modgfx.h"
#include "main/dll/dll_009A_modgfx.h"
#include "main/dll/dll_009B_modgfx.h"
#include "main/dll/dll_009C_modgfx.h"
#include "main/dll/dll_009D_modgfx.h"
#include "main/dll/dll_009E_modgfx.h"
#include "main/dll/dll_009F_modgfx.h"
#include "main/dll/dll_00A0_modgfx.h"
#include "main/dll/dll_00A1_modgfx.h"
#include "main/dll/dll_00A2_modgfx.h"
#include "main/dll/dll_00A3_modgfx.h"
#include "main/dll/dll_00A4_dummya4.h"
#include "main/dll/dll_00A5_modgfx.h"
#include "main/dll/dll_00A6_modgfx.h"
#include "main/dll/dll_00A7_modgfx.h"
#include "main/dll/dll_00A8_modgfx.h"
#include "main/dll/dll_00A9_modgfx.h"
#include "main/dll/dll_00AA_modgfx.h"
#include "main/dll/dll_00AB_projdummy.h"
#include "main/dll/dll_00AC_projmagicstream.h"
#include "main/dll/dll_00AD_projmagicemmit1.h"
#include "main/dll/dll_00AE_projroombeam.h"
#include "main/dll/dll_00AF_projlightning1.h"
#include "main/dll/dll_00B0_projlightning2.h"
#include "main/dll/dll_00B1_projlightning3.h"
#include "main/dll/dll_00B2_projrobotfire.h"
#include "main/dll/dll_00B3_projlightning4.h"
#include "main/dll/dll_00B4_projenergise1.h"
#include "main/dll/dll_00B5_projenergise2.h"
#include "main/dll/dll_00B6_projsquirt1.h"
#include "main/dll/dll_00B7_projship1.h"
#include "main/dll/dll_00B8_projlightning5.h"
#include "main/dll/dll_00B9_projlightning7.h"
#include "main/dll/dll_00BA_projlightning6.h"
#include "main/dll/dll_00BB_projwallpower.h"
#include "main/dll/dll_00BC_projquakeshock.h"
#include "main/dll/dll_00BD_projsunshock.h"
#include "main/dll/dll_00BE_projtesla.h"
#include "main/dll/dll_00BF_projcore1.h"
#include "main/dll/dll_00C0_projcore2.h"
#include "main/dll/dll_00C1_projcore3.h"
#include "main/dll/dll_00C2_projdfp1r.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/CF/laser.h"
#include "main/dll/dll_00DA_pollenfragment_api.h"
#include "dlls/objects/294.h"
#include "dlls/objects/557_DFP_seqpoin.h"
#include "dlls/objects/578_DBstealerwo.h"
#include "main/dll/DF/dll_022E_dfpdoorswitch.h"
#include "main/dll/DF/dll_0233_dfpstatue1.h"
#include "main/dll/DF/dll_0234_dfperchwitch.h"
#include "dlls/objects/547_VFP_corepla.h"
#include "dlls/objects/565_DFP_TargetB.h"
#include "main/dll/baddie/dll_022F_dfpfloorbar.h"
#include "main/dll/dll_023F_dbegg.h"
#include "main/dll/dll_025A_staticcamera.h"
#include "main/dll/dll_025B_msplantings.h"
#include "main/dll/DR/dll_0254_ktfallingrocks.h"
#include "main/dll/dll_0269_explodeplan.h"
#include "dlls/objects/611_GM_MazeWell.h"
#include "dlls/objects/626.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "dlls/objects/643_DR_BarrelGr.h"
#include "main/dll/dll_0293_suntemple.h"
#include "main/dll/dll_0294_wctemple.h"
#include "main/dll/WC/dll_0292_wctrexstatu.h"
#include "main/dll/WC/dll_028F_wcpressures.h"
#include "main/dll/WC/dll_0295_wcapertures.h"
#include "dlls/objects/662_WCTempleDia.h"
#include "dlls/objects/663_WCTempleBri.h"
#include "main/dll/WC/dll_0298_wcfloortile.h"
#include "main/dll/WC/WCbeacon.h"
#include "main/dll/ARW/dll_029C_arwarwingbo.h"
#include "main/dll/ARW/dll_029D_arwarwinggu.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_02A1_arwlevelcon.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/DR/dll_0281_drearthcal.h"
#include "main/dll/dll_0299.h"
#include "main/dll/dll_02B1_cmbsrc.h"
#include "main/dll/dll_02B2_dustmotesou.h"
#include "main/dll/dll_02B4_cntcounter.h"
#include "main/dll/dll_02B6_cnthitobjec.h"
#include "main/dll/dll_02B7_mcupgrade.h"
#include "main/dll/dll_02B8_mcupgradema.h"
#include "main/dll/dll_02B9_mcstaffeffe.h"
#include "main/dll/dll_02BA_mclightning.h"
#include "main/dll/dll_02BB_gflevelcon.h"
#include "main/dll/dll_02BC_andross.h"
#include "main/dll/dll_02BF_androssligh.h"
#include "main/dll/dll_02BE_androssbrain.h"
#include "main/dll/dll_02BD_androsshand.h"
#include "main/dll/dll_02AF_tree.h"
#include "main/dll/dll_02B0_brokenpipe.h"
#include "main/dll/dll_02AD_softbody.h"
#include "main/dll/SP/dll_0287_spscarab.h"
#include "main/dll/VF/platform1.h"
#include "main/dll/WM/dll_0210_wmplanets.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/gametext_box_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_color_api.h"
#include "main/minimap_api.h"
#include "main/model_engine.h"
#include "main/mm.h"
#include "main/pause_menu_api.h"
#include "main/resource.h"
#include "main/textblock.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/string.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/hud_visibility_api.h"

s32 gModelEngineHudNumber = -1;

f32 gModelEngineTimerValue;
f32 gModelEngineTimerDuration;
s8 gModelEngineTimerFlags;
u8 gModelEngineTimerState;
int gModelEnginePrevUiDll;
int curUiDll;
int gModelEnginePendingUiDll;
UiDllVTable** gModelEngineCurUiDllRes;
int gModelEngineTimerDigitPairXOffset = 0x10;
int gModelEngineTimerFieldXStride = 0x26;
int gModelEngineTimerColonX = 0x24;
int gModelEngineTimerDotX = 0x4A;
s32 gMenuState = -1;
char sModelEngineHudNumberFormat[] = "%d";
char sModelEngineTimerDigitFormat[] = "%01d";
char sModelEngineTimerColonText[] = ":";
char sModelEngineTimerDotText[] = ".";

#define RESOURCE_DESCRIPTOR_COUNT 0x2c1

/* gModelEngineTimerState bits (roles from accessor fns: timerSetToCountUp,
 * isGameTimerDisabled, gameTimerIsRunning). */
#define MODELENGINE_TIMER_COUNTDOWN 1
#define MODELENGINE_TIMER_DISABLED  2
#define MODELENGINE_TIMER_RUNNING   4

extern ResourceDescriptor Carryable_funcs, boneParticleEffect_funcs, dll_19;
extern ResourceDescriptor gDll219ObjDescriptor, gDll21BObjDescriptor, gDll224ObjDescriptor, gDll28BObjDescriptor;
extern ResourceDescriptor gDll2A3ObjDescriptor;
extern ResourceDescriptor gDll2A4ObjDescriptor, dll_2E, gDllD3ObjDescriptor, expgfx_funcs;
extern ResourceDescriptor gARWBlockerObjDescriptor, gARWBombCollObjDescriptor, gARWGeneratoObjDescriptor,
    gARWProximitObjDescriptor;
extern ResourceDescriptor gARWSpeedStrObjDescriptor, gARWSquadronObjDescriptor;
extern ResourceDescriptor gBossDrakorObjDescriptor;
extern ResourceDescriptor gChukaObjDescriptor;
extern ResourceDescriptor gCrCloudRaceObjDescriptor, gCrFuelTankObjDescriptor;
extern ResourceDescriptor gDBHoleControl1ObjDescriptor, gDFP_LevelControlObjDescriptor,
    gDFP_ObjCreatorObjDescriptor, gDFP_TorchObjDescriptor;
extern ResourceDescriptor gDIM_trickyObjDescriptor, gDR_CloudRunnerObjDescriptor;
extern ResourceDescriptor gDfplightniObjDescriptor, gDfppowerslObjDescriptor;
extern ResourceDescriptor gDrCageControlObjDescriptor,
    gDrCageWithObjDescriptor, gDrChimmeyObjDescriptor, gDrCloudPerObjDescriptor, gDrCreatorObjDescriptor;
extern ResourceDescriptor gDrEnergyDiscObjDescriptor, gDrGeneratorObjDescriptor,
    gDrLightBeaObjDescriptor, gDrMusicContObjDescriptor, gDrShackleObjDescriptor, gDrakorDThornBushObjDescriptor,
    gDrakorEnergyObjDescriptor;
extern ResourceDescriptor gDrakorHoverPadObjDescriptor, gDrakorMissileObjDescriptor;
extern ResourceDescriptor gEarthWalkerObjDescriptor;
extern ResourceDescriptor gFireFlyObjDescriptor, gFireObjDescriptor;
extern ResourceDescriptor gKtLazerlightObjDescriptor, gKtLazerwallObjDescriptor, gKtRexFloorSwitchObjDescriptor,
    gKtRexLevelObjDescriptor, gKytesMumObjDescriptor;
extern ResourceDescriptor gProjectedLightObjDescriptor, gProximityMineObjDescriptor;
extern ResourceDescriptor gRingObjDescriptor;
extern ResourceDescriptor gSPDrapeObjDescriptor, gSPitembeamObjDescriptor, gSeqPointObjDescriptor;
extern ResourceDescriptor gDFP_RotatePObjDescriptor, gShopItemObjDescriptor, gShopKeeperObjDescriptor,
    gShopObjDescriptor;
extern ResourceDescriptor gSnowClawObjDescriptor;
extern ResourceDescriptor gSpellStoneObjDescriptor;
extern ResourceDescriptor gTimerObjDescriptor;
extern ResourceDescriptor gTitleScreenObjDescriptor, gTrickyCurveObjDescriptor;
extern ResourceDescriptor gVFPDragHeadObjDescriptor, gVFPLiftObjDescriptor, gVFP_Block1ObjDescriptor;
extern ResourceDescriptor gVFP_LaddersObjDescriptor, gVFP_LevelControlObjDescriptor,
    gVFP_MiniFireObjDescriptor, gVFP_ObjCreatorObjDescriptor, gVFP_PlatformObjDescriptor,
    gVFP_SpellPlaceObjDescriptor, gVFP_flamepointObjDescriptor;
extern ResourceDescriptor gVFP_lavapoolObjDescriptor, gVFP_lavastarObjDescriptor, gVFP_statueballObjDescriptor,
    gVortexObjDescriptor, gWCBouncyCraObjDescriptor;
extern ResourceDescriptor gWCLevelContObjDescriptor,
    gWCPushBlockObjDescriptor,
    gWCTileObjDescriptor;
extern ResourceDescriptor gWM_SpiritSetObjDescriptor, gWM_newcrystalObjDescriptor;
extern ResourceDescriptor gWM_spiritplaceObjDescriptor, gWM_sunObjDescriptor, gWaterFlowWeObjDescriptor;
extern ResourceDescriptor ObjSeq_funcs;
extern ResourceDescriptor sky_funcs, sky2_funcs, newclouds_funcs, Dummy08_funcs, cloudaction_funcs, waterfx_funcs,
    dll_0B_funcs, partfx_funcs;
extern ResourceDescriptor Effect1_funcs, Effect2_funcs, Effect3_funcs, Effect4_funcs, Effect5_funcs, Effect6_funcs,
    Effect7_funcs, Effect8_funcs;
extern ResourceDescriptor Effect9_funcs, Effect10_funcs, Effect11_funcs, Effect12_funcs, Effect14_funcs, Effect16_funcs,
    Effect15_funcs, Effect13_funcs;
extern ResourceDescriptor Effect17_funcs, Effect18_funcs, Effect19_funcs, Effect20_funcs, Checkpoint_funcs, screenTransition_funcs,
    Dummy04_funcs, player_funcs;
extern ResourceDescriptor UIController_funcs, Dummy12_funcs, RomCurve_funcs, dll_15_funcs, SaveGame_funcs, screens_funcs;
extern ResourceDescriptor Dummy30_funcs;
extern ResourceDescriptor TitleScreenInit_funcs, n_rareware_funcs, n_attractmode_funcs, SaveSelectScreen_funcs, EnterSaveNameScreen_funcs, OptionsScreen_funcs,
    WeirdUnusedMenu_funcs, Dummy39_funcs;
extern ResourceDescriptor Dummy3A_funcs, GameUI_funcs, Menu_funcs, Link_funcs, TitleMenuItem_funcs, Dummy3E_funcs,
    Minimap_funcs, dll_3F_funcs;
extern ResourceDescriptor gCreditsDescriptor, gWarpStoneUiDescriptor;
extern ResourceDescriptor gWM_VConsoleNullResourceDescriptor, gGCRobotBlastObjDescriptor;
extern ResourceDescriptor gDll22CObjDescriptor, Dummy245, Dummy246, Dummy244, Dummy247, Dummy248, Dummy24A, Dummy24B;
extern ResourceDescriptor Dummy24C_funcs, gDll27BNullResourceDescriptor, gDll27DNullResourceDescriptor,
    gDll29EObjDescriptor;
extern ResourceDescriptor gDll212NullResourceDescriptor, gWM_TransTopNullResourceDescriptor,
    gDBPointMumNullResourceDescriptor;
extern ResourceDescriptor gDll23ENullResourceDescriptor, gDll264NullResourceDescriptor, gDll267NullResourceDescriptor,
    gDR_GeezerNullResourceDescriptor, gDR_VinesNullResourceDescriptor, gDR_RockNullResourceDescriptor,
    gDR_cradleNullResourceDescriptor, gDR_pulleyNullResourceDescriptor;
extern ResourceDescriptor gDll276NullResourceDescriptor, gCFWindLiftLNullResourceDescriptor,
    gDll278NullResourceDescriptor, gDR_CollapseNullResourceDescriptor, gDll27FNullResourceDescriptor,
    gDll249NullResourceDescriptor, playerShadow_funcs, projgfx_funcs;
extern ResourceDescriptor gDllC5NullResourceDescriptor, gCloudShipControlNullResourceDescriptor,
    gDll147NullResourceDescriptor, gLaserBeamNullResourceDescriptor, gCFScalesGalNullResourceDescriptor,
    gCFObjCreatNullResourceDescriptor, gDll155NullResourceDescriptor, gDll156NullResourceDescriptor;
extern ResourceDescriptor gCFForceField15CNullResourceDescriptor, gDll15ENullResourceDescriptor,
    gDll160NullResourceDescriptor, gCFTreasRoboNullResourceDescriptor, gDll163NullResourceDescriptor,
    gCFRemovalShNullResourceDescriptor, gHoloPointNullResourceDescriptor;
extern ResourceDescriptor gDFSH_Door1SNullResourceDescriptor, gGCRobotPatrNullResourceDescriptor,
    gDll202NullResourceDescriptor, gDll203NullResourceDescriptor, gWMVeinNullResourceDescriptor,
    gWM_WallpoweNullResourceDescriptor;

void* gResourceLoadedHandles[0x2C1];
u16 gResourceRefCounts[0x2C2];
char gModelEngineTextBuf[0x10];

RingBufferQueue* Queue_Alloc(int capacity, int elemSize)
{
    RingBufferQueue* queue = mmAlloc(elemSize * capacity + sizeof(RingBufferQueue), 0x1a, 0);
    queue->data = (u8*)queue + sizeof(RingBufferQueue);
    queue->count = 0;
    queue->capacity = capacity;
    queue->elemSize = elemSize;
    queue->writeIndex = 0;
    return queue;
}

s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state)
{
    return state->bit;
}

void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit)
{
    state->bit = bit;
}

void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC)
{
    state->byteCount = bitCount >> 3;
    if ((bitCount & 7) != 0)
    {
        state->byteCount++;
    }
    state->bitCount = bitCount;
    state->fieldC = fieldC;
    state->instrs = instrs;
    state->bit = 0;
}

void objList_remove(ObjLinkedList* list, int item)
{
    int head;
    int prev;
    int current;
    int next;

    head = list->head;
    if (head == item)
    {
        list->head = *(int*)(head + list->nextOffset);
        list->count--;
        return;
    }

    current = head;
    prev = head;
    while (current != 0 && current != item)
    {
        prev = current;
        current = *(int*)(current + list->nextOffset);
    }

    if (current == 0)
    {
        return;
    }

    next = *(int*)(current + list->nextOffset);
    if (current == head)
    {
        list->head = next;
    }
    else
    {
        *(int*)(prev + list->nextOffset) = next;
    }
    list->count--;
}

void objListAdd(ObjLinkedList* list, int prev, int item)
{
    int next;

    if (list->head == 0)
    {
        list->head = item;
    }
    else
    {
        if (prev == 0)
        {
            next = list->head;
            list->head = item;
        }
        else
        {
            next = *(int*)(prev + list->nextOffset);
            *(int*)(prev + list->nextOffset) = item;
        }
        *(int*)(item + list->nextOffset) = next;
    }
    list->count++;
}

void objListInit(ObjLinkedList* list, s16 nextOffset)
{
    list->head = 0;
    list->nextOffset = nextOffset;
}

BOOL model_findIdxInModelList(ModelList* list, void* header, int* outIndex)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end)
    {
        if (memcmp(entry + 1, header, list->dataSize) == 0)
        {
            *outIndex = *entry;
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}

BOOL ModelList_getHeader(ModelList* list, int index, void* outHeader) {
    s16* entry = list->entries;
    while (entry < list->end) {
        if (*entry == index) {
            memcpy(outHeader, entry + 1, list->dataSize);
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}

void model_adjustModelList(ModelList* list, int index) {
    s16* entry = list->entries;
    while (entry < list->end) {
        if (*entry == index) {
            *entry = -1;
            break;
        }
        entry += list->strideShorts;
    }

    while (list->end > list->entries && list->end[-1] == -1) {
        list->end -= list->strideShorts;
    }
}

void modelInitModelList(ModelList* list, s16 index, void* header) {
    s16* entry;

    for (entry = list->entries; entry < list->end; entry += list->strideShorts) {
        if (*entry == -1) {
            break;
        }
    }

    *entry = index;
    memcpy(entry + 1, header, list->dataSize);
    if (entry == list->end) {
        list->end += list->strideShorts;
    }
}

ModelList* allocModelStruct(int capacity, int dataSize) {
    int entryBytes = dataSize + 2;
    ModelList* list = mmAlloc(capacity * entryBytes + sizeof(ModelList), 0x1a, 0);
    list->entries = (s16*)((u8*)list + sizeof(ModelList));
    list->dataSize = dataSize;
    list->strideShorts = (u32)entryBytes >> 1;
    list->end = list->entries;
    list->capacityEnd = list->entries + capacity * list->strideShorts;
    memset(list->entries, -1, capacity * (list->strideShorts * 2));
    return list;
}

BOOL Resource_Release(void* handleSlot) {
    s32 i = 0;
    ResourceDescriptor* descriptor = handleSlot;
    while (i < RESOURCE_DESCRIPTOR_COUNT) {
        if ((void*)&gResourceLoadedHandles[i] == handleSlot) {
            descriptor = gResourceDescriptors[i];
            break;
        }
        i++;
    }

    gResourceRefCounts[i]--;
    if (gResourceRefCounts[i] == 0)
    {
        if (descriptor->release != NULL)
        {
            descriptor->release();
        }
        return TRUE;
    }
    return FALSE;
}

void* Resource_Acquire(u16 id, int unused)
{
    u32 index;
    ResourceDescriptor* descriptor;

    index = id;
    descriptor = gResourceDescriptors[index];
    if (gResourceRefCounts[index] == 0 && descriptor->acquire != NULL)
    {
        descriptor->acquire(descriptor);
    }
    gResourceRefCounts[index]++;
    gResourceLoadedHandles[index] = descriptor->data;
    return &gResourceLoadedHandles[index];
}

void Resource_ResetRefCounts(void)
{
    u32 i;

    for (i = 0; i < RESOURCE_DESCRIPTOR_COUNT; i++)
    {
        gResourceRefCounts[i] = 0;
    }
}

void menuSetState(s32 value)
{
    gMenuState = value;
}

u8 gameTimerIsRunning(void)
{
    return gModelEngineTimerState & MODELENGINE_TIMER_RUNNING;
}

void hudNumberRender(void* context)
{
    if (gModelEngineHudNumber != -1)
    {
        sprintf(gModelEngineTextBuf, sModelEngineHudNumberFormat, gModelEngineHudNumber);
        gameTextShowStr(gModelEngineTextBuf, 13, 0, 0);
    }
}

void hudNumberSet(s32 value)
{
    gModelEngineHudNumber = value;
}

void gameTimerRun(void* context)
{
    f32 dt = timeDelta;
    u8 colorFlag = 0;
    TextSlot* box = gameTextGetBox(0xD);
    int hours;
    int minutes;
    int hundredths;
    u16 boxY;
    char clamped;
    int totalSecs;
    int mins;

    if ((gModelEngineTimerState & MODELENGINE_TIMER_COUNTDOWN) || getHudHiddenFrameCount() != 0)
    {
        dt = 0.0f;
    }

    clamped = 0;
    if ((gModelEngineTimerFlags & 1) != 0)
    {
        gModelEngineTimerValue -= dt;
        if (gModelEngineTimerValue <= 0.0f)
        {
            clamped = 1;
            gModelEngineTimerValue = 0.0f;
        }
        if (gModelEngineTimerValue < 600.0f)
        {
            colorFlag = 1;
        }
    }
    else
    {
        gModelEngineTimerValue += dt;
        if (gModelEngineTimerValue > gModelEngineTimerDuration)
        {
            clamped = 1;
            gModelEngineTimerValue = gModelEngineTimerDuration;
        }
        if (gModelEngineTimerValue > gModelEngineTimerDuration - 600.0f)
        {
            colorFlag = 1;
        }
    }

    if (clamped)
    {
        if ((gModelEngineTimerFlags & 8) != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_sc_lockon22);
        }
        gModelEngineTimerState &= ~MODELENGINE_TIMER_RUNNING;
        gModelEngineTimerState |= MODELENGINE_TIMER_DISABLED;
    }

    if ((gModelEngineTimerFlags & 4) != 0)
    {
        f32 panByte;
        f32 volume;
        Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_sc_commsbleep_28c);
        if ((gModelEngineTimerFlags & 1) != 0)
        {
            panByte = (f32)(0x7F - ((int)(80.0f * (gModelEngineTimerValue / gModelEngineTimerDuration)) & 0xFF));
            volume = 1.3f - 0.6f * (gModelEngineTimerValue / gModelEngineTimerDuration);
        }
        else
        {
            panByte = (f32)(((int)(80.0f * (gModelEngineTimerValue / gModelEngineTimerDuration)) & 0xFF) + 0x2F);
            volume = 0.6f * (gModelEngineTimerValue / gModelEngineTimerDuration) + 0.7f;
        }
        Sfx_SetObjectSfxVolume(0, SFXTRIG_sc_commsbleep_28c, panByte, volume);
    }

    if ((gModelEngineTimerFlags & 0x10) != 0 && pauseMenuState == 0 && getHudHiddenFrameCount() == 0)
    {
        totalSecs = gModelEngineTimerValue;
        mins = totalSecs / 60;
        hours = mins / 60;
        minutes = mins - hours * 60;
        hundredths = (int)(100.0f * (gModelEngineTimerValue / 60.0f));
        hundredths = hundredths - hundredths / 100 * 100;

        boxY = getMinimapY() - 0x28;
        drawHudBox(0x32, (s16)(boxY - 4), 0x78, 0x28, 0xFF, 1);
        box->y = boxY;

        if (colorFlag && hundredths < 0x32)
        {
        gameTextSetColor(0xFF, 0x40, 0x40, 0xFF);
        }
        else
        {
        gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        }

        sprintf(gModelEngineTextBuf, sModelEngineTimerDigitFormat, hours / 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, 5, 3);
        sprintf(gModelEngineTextBuf, sModelEngineTimerDigitFormat, hours % 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, gModelEngineTimerDigitPairXOffset + 5, 3);
        sprintf(gModelEngineTextBuf, sModelEngineTimerDigitFormat, minutes / 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, gModelEngineTimerFieldXStride + 5, 3);
        sprintf(gModelEngineTextBuf, sModelEngineTimerDigitFormat, minutes % 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, 5 + gModelEngineTimerFieldXStride + gModelEngineTimerDigitPairXOffset, 3);
        sprintf(gModelEngineTextBuf, sModelEngineTimerDigitFormat, hundredths / 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, gModelEngineTimerFieldXStride * 2 + 5, 3);
        sprintf(gModelEngineTextBuf, sModelEngineTimerDigitFormat, hundredths % 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, 5 + gModelEngineTimerFieldXStride * 2 + gModelEngineTimerDigitPairXOffset, 3);
        if (minutes & 1)
        {
            gameTextShowStr(sModelEngineTimerColonText, 0xD, gModelEngineTimerColonX, 3);
            gameTextShowStr(sModelEngineTimerDotText, 0xD, gModelEngineTimerDotX, 3);
        }
    }
}

f32 gameTimerGetElapsedMilliseconds(void) {
    if ((gModelEngineTimerFlags & 1) != 0) {
        return 1000.0f * ((gModelEngineTimerDuration - gModelEngineTimerValue) / 60.0f);
    }
    return 1000.0f * (gModelEngineTimerValue / 60.0f);
}

f32 gameTimerGetValue(void)
{
    return gModelEngineTimerValue;
}

int isGameTimerDisabled(void)
{
    return gModelEngineTimerState & MODELENGINE_TIMER_DISABLED;
}

void gameTimerStop(void)
{
    gModelEngineTimerState &= ~MODELENGINE_TIMER_RUNNING;
    gModelEngineTimerState |= MODELENGINE_TIMER_DISABLED;
}

void timerSetToCountUp(void)
{
    if ((gModelEngineTimerState & MODELENGINE_TIMER_COUNTDOWN) != 0)
    {
        gModelEngineTimerState &= ~MODELENGINE_TIMER_COUNTDOWN;
    }
}

void gameTimerInit(s8 flags, int minutes)
{
    gModelEngineTimerFlags = flags;
    if ((flags & 1) != 0)
    {
        gModelEngineTimerValue = minutes * 60;
    }
    else
    {
        gModelEngineTimerValue = 0.0f;
    }
    gModelEngineTimerDuration = minutes * 60;
    gModelEngineTimerState |= MODELENGINE_TIMER_COUNTDOWN;
    gModelEngineTimerState &= ~MODELENGINE_TIMER_DISABLED;
    if ((flags & 3) != 0)
    {
        gModelEngineTimerState |= MODELENGINE_TIMER_RUNNING;
    }
    else
    {
        gModelEngineTimerState &= ~MODELENGINE_TIMER_RUNNING;
    }
}

void curUiDllDraw(int a, int b, int c, int d)
{
    UiDllVTable* callbacks;

    if (gModelEngineCurUiDllRes != NULL)
    {
        callbacks = *gModelEngineCurUiDllRes;
        callbacks->draw(a, b, c);
    }
}

void uiDll_runFrameEndAndLoadNext(void)
{
    UiDllVTable* callbacks;
    s32 resourceId;

    if (gModelEngineCurUiDllRes != NULL)
    {
        callbacks = *gModelEngineCurUiDllRes;
        callbacks->frameEnd();
    }

    if (gModelEnginePendingUiDll != 0)
    {
        gModelEnginePendingUiDll--;
        gModelEnginePrevUiDll = curUiDll;
        if (gModelEngineCurUiDllRes != NULL)
        {
            Resource_Release(gModelEngineCurUiDllRes);
            gModelEngineCurUiDllRes = NULL;
        }

        resourceId = gModelEngineUiDllResourceIds[gModelEnginePendingUiDll];
        if (resourceId != -1)
        {
            gModelEngineCurUiDllRes = Resource_Acquire((u16)resourceId, 1);
        }
        else
        {
            gModelEngineCurUiDllRes = NULL;
            gModelEnginePendingUiDll = 0;
        }
        curUiDll = gModelEnginePendingUiDll;
        gModelEnginePendingUiDll = 0;
    }
}

int uiDll_runFrameStartAndLoadNext(void)
{
    UiDllVTable* callbacks;
    int result;
    s32 resourceId;

    result = 0;
    if (gModelEngineCurUiDllRes != NULL)
    {
        callbacks = *gModelEngineCurUiDllRes;
        result = callbacks->frameStart();
    }

    if (gModelEnginePendingUiDll != 0)
    {
        gModelEnginePendingUiDll--;
        gModelEnginePrevUiDll = curUiDll;
        if (gModelEngineCurUiDllRes != NULL)
        {
            Resource_Release(gModelEngineCurUiDllRes);
            gModelEngineCurUiDllRes = NULL;
        }

        resourceId = gModelEngineUiDllResourceIds[gModelEnginePendingUiDll];
        if (resourceId != -1)
        {
            gModelEngineCurUiDllRes = Resource_Acquire((u16)resourceId, 1);
        }
        else
        {
            gModelEngineCurUiDllRes = NULL;
            gModelEnginePendingUiDll = 0;
        }
        curUiDll = gModelEnginePendingUiDll;
        gModelEnginePendingUiDll = 0;
    }
    return result;
}

void setCurUiDll(int idx)
{
    curUiDll = idx;
}

int getPrevUiDll(void)
{
    return gModelEnginePrevUiDll;
}

UiDllVTable** getCurUiDllInterface(void)
{
    return gModelEngineCurUiDllRes;
}

int getCurUiDll(void)
{
    return curUiDll;
}

void loadUiDll(int index)
{
    s32 next;
    s32 current;
    s32 resourceId;

    current = curUiDll;
    if (index != current)
    {
        next = index + 1;
        gModelEnginePendingUiDll = next;
        if (gModelEngineCurUiDllRes == NULL && next != 0)
        {
            gModelEnginePendingUiDll = next - 1;
            gModelEnginePrevUiDll = current;
            if (gModelEngineCurUiDllRes != NULL)
            {
                Resource_Release(gModelEngineCurUiDllRes);
                gModelEngineCurUiDllRes = NULL;
            }

            resourceId = gModelEngineUiDllResourceIds[gModelEnginePendingUiDll];
            if (resourceId != -1)
            {
                gModelEngineCurUiDllRes = Resource_Acquire((u16)resourceId, 1);
            }
            else
            {
                gModelEngineCurUiDllRes = NULL;
                gModelEnginePendingUiDll = 0;
            }
            curUiDll = gModelEnginePendingUiDll;
            gModelEnginePendingUiDll = 0;
        }
    }
}

void initGameTimer(void)
{
    gModelEngineCurUiDllRes = NULL;
    gModelEnginePendingUiDll = 0;
    gModelEnginePrevUiDll = 0;
    curUiDll = 0;
    gModelEngineTimerState = MODELENGINE_TIMER_DISABLED;
    gModelEngineTimerFlags = 0;
    gModelEngineTimerValue = 0.0f;
    gModelEngineTimerDuration = 0.0f;
}

ResourceDescriptor* gResourceDescriptors[] = {
    &GameUI_funcs,
    (ResourceDescriptor*)&gCamcontrolResourceDescriptor,
    &ObjSeq_funcs,
    &Checkpoint_funcs,
    &Dummy04_funcs,
    &sky_funcs,
    &sky2_funcs,
    &newclouds_funcs,
    &Dummy08_funcs,
    &cloudaction_funcs,
    &expgfx_funcs,
    &dll_0B_funcs,
    &projgfx_funcs,
    &playerShadow_funcs,
    &partfx_funcs,
    &player_funcs,
    &UIController_funcs,
    &screens_funcs,
    &Dummy12_funcs,
    &waterfx_funcs,
    &RomCurve_funcs,
    &dll_15_funcs,
    &screenTransition_funcs,
    &SaveGame_funcs,
    &boneParticleEffect_funcs,
    &dll_19,
    &Effect1_funcs,
    &Effect2_funcs,
    &Effect3_funcs,
    &Effect4_funcs,
    &Effect5_funcs,
    &Effect6_funcs,
    &Effect7_funcs,
    &Effect8_funcs,
    &Effect9_funcs,
    &Effect10_funcs,
    &Effect11_funcs,
    &Effect12_funcs,
    &Effect13_funcs,
    &Effect14_funcs,
    &Effect15_funcs,
    &Effect16_funcs,
    &Effect17_funcs,
    &Effect18_funcs,
    &Effect19_funcs,
    &Effect20_funcs,
    &dll_2E,
    &Carryable_funcs,
    &Dummy30_funcs,
    &Minimap_funcs,
    &TitleScreenInit_funcs,
    &n_rareware_funcs,
    &n_attractmode_funcs,
    &SaveSelectScreen_funcs,
    &EnterSaveNameScreen_funcs,
    &OptionsScreen_funcs,
    &WeirdUnusedMenu_funcs,
    &Dummy39_funcs,
    &Dummy3A_funcs,
    &Menu_funcs,
    &Link_funcs,
    &TitleMenuItem_funcs,
    &Dummy3E_funcs,
    &dll_3F_funcs,
    &gCreditsDescriptor,
    &gWarpStoneUiDescriptor,
    (ResourceDescriptor*)&gCameraModeNormalDescriptor,
    (ResourceDescriptor*)&gCameraModeStaffAnimDescriptor,
    (ResourceDescriptor*)&gCameraModeViewfinderDescriptor,
    (ResourceDescriptor*)&gCameraModeTalkDescriptor,
    (ResourceDescriptor*)&gCameraModeDebugDescriptor,
    (ResourceDescriptor*)&gCameraModePathDescriptor,
    (ResourceDescriptor*)&gCameraModeStaticDescriptor,
    (ResourceDescriptor*)&gCameraModeCombatDescriptor,
    (ResourceDescriptor*)&gCameraModeShipBattleDescriptor,
    (ResourceDescriptor*)&gCameraModeClimbDescriptor,
    (ResourceDescriptor*)&gCameraModeFixedDescriptor,
    (ResourceDescriptor*)&gCameraModeNpcSpeakDescriptor,
    (ResourceDescriptor*)&gCameraModeWorldMapDescriptor,
    (ResourceDescriptor*)&gCameraMode4FDescriptor,
    (ResourceDescriptor*)&gCameraModeCrawlDescriptor,
    (ResourceDescriptor*)&gCameraModeCannonDescriptor,
    (ResourceDescriptor*)&gCameraModeForceBehindDescriptor,
    (ResourceDescriptor*)&gCameraModeCloudRunnerDescriptor,
    (ResourceDescriptor*)&gCameraMode54Descriptor,
    (ResourceDescriptor*)&gCameraMode55Descriptor,
    (ResourceDescriptor*)&gCameraModeArwingDescriptor,
    (ResourceDescriptor*)&gCameraModeTitleDescriptor,
    (ResourceDescriptor*)&gDummy58Descriptor,
    (ResourceDescriptor*)&gDll59ResourceDescriptor,
    (ResourceDescriptor*)&gStaffCollisionResourceDescriptor,
    (ResourceDescriptor*)&gDll5BResourceDescriptor,
    (ResourceDescriptor*)&gDll5CResourceDescriptor,
    (ResourceDescriptor*)&gDll5DResourceDescriptor,
    (ResourceDescriptor*)&gDll5EResourceDescriptor,
    (ResourceDescriptor*)&gDll5FResourceDescriptor,
    (ResourceDescriptor*)&gDll60ResourceDescriptor,
    (ResourceDescriptor*)&gDll61ResourceDescriptor,
    (ResourceDescriptor*)&gDll62ResourceDescriptor,
    (ResourceDescriptor*)&gDll63ResourceDescriptor,
    (ResourceDescriptor*)&gDll64ResourceDescriptor,
    (ResourceDescriptor*)&gDll65ResourceDescriptor,
    (ResourceDescriptor*)&gDll66ResourceDescriptor,
    (ResourceDescriptor*)&gDll67ResourceDescriptor,
    (ResourceDescriptor*)&gDll68ResourceDescriptor,
    (ResourceDescriptor*)&gDll69ResourceDescriptor,
    (ResourceDescriptor*)&gDll6AResourceDescriptor,
    (ResourceDescriptor*)&gDll6BResourceDescriptor,
    (ResourceDescriptor*)&gDummy6CDescriptor,
    (ResourceDescriptor*)&gDll6DResourceDescriptor,
    (ResourceDescriptor*)&gDll6EResourceDescriptor,
    (ResourceDescriptor*)&gDll6FResourceDescriptor,
    (ResourceDescriptor*)&gDll70ResourceDescriptor,
    (ResourceDescriptor*)&gDll71ResourceDescriptor,
    (ResourceDescriptor*)&gDll72ResourceDescriptor,
    (ResourceDescriptor*)&gDll73ResourceDescriptor,
    (ResourceDescriptor*)&gDll74ResourceDescriptor,
    (ResourceDescriptor*)&gDll75ResourceDescriptor,
    (ResourceDescriptor*)&gDll76ResourceDescriptor,
    (ResourceDescriptor*)&gDll77ResourceDescriptor,
    (ResourceDescriptor*)&gDll78ResourceDescriptor,
    (ResourceDescriptor*)&gDll79ResourceDescriptor,
    (ResourceDescriptor*)&gDll7AResourceDescriptor,
    (ResourceDescriptor*)&gDll7BResourceDescriptor,
    (ResourceDescriptor*)&gDll7CResourceDescriptor,
    (ResourceDescriptor*)&gDll7DResourceDescriptor,
    (ResourceDescriptor*)&gDll7EResourceDescriptor,
    (ResourceDescriptor*)&gDll7FResourceDescriptor,
    (ResourceDescriptor*)&gDll80ResourceDescriptor,
    (ResourceDescriptor*)&gDll81ResourceDescriptor,
    (ResourceDescriptor*)&gDll82ResourceDescriptor,
    (ResourceDescriptor*)&gDll83ResourceDescriptor,
    (ResourceDescriptor*)&gDll84ResourceDescriptor,
    (ResourceDescriptor*)&gDll85ResourceDescriptor,
    (ResourceDescriptor*)&gDll86ResourceDescriptor,
    (ResourceDescriptor*)&gDll87ResourceDescriptor,
    (ResourceDescriptor*)&gDll88ResourceDescriptor,
    (ResourceDescriptor*)&gDll89ResourceDescriptor,
    (ResourceDescriptor*)&gDll8AResourceDescriptor,
    (ResourceDescriptor*)&gDll8BResourceDescriptor,
    (ResourceDescriptor*)&gDll8CResourceDescriptor,
    (ResourceDescriptor*)&gDll8DResourceDescriptor,
    (ResourceDescriptor*)&gDll8EResourceDescriptor,
    (ResourceDescriptor*)&gDll8FResourceDescriptor,
    (ResourceDescriptor*)&gDll90ResourceDescriptor,
    (ResourceDescriptor*)&gDll91ResourceDescriptor,
    (ResourceDescriptor*)&gDll92ResourceDescriptor,
    (ResourceDescriptor*)&gDll93ResourceDescriptor,
    (ResourceDescriptor*)&gDll94ResourceDescriptor,
    (ResourceDescriptor*)&gDll95ResourceDescriptor,
    (ResourceDescriptor*)&gDll96ResourceDescriptor,
    (ResourceDescriptor*)&gDll97ResourceDescriptor,
    (ResourceDescriptor*)&gDll98ResourceDescriptor,
    (ResourceDescriptor*)&gDll99ResourceDescriptor,
    (ResourceDescriptor*)&gDll9AResourceDescriptor,
    (ResourceDescriptor*)&gDll9BResourceDescriptor,
    (ResourceDescriptor*)&gDll9CResourceDescriptor,
    (ResourceDescriptor*)&gDll9DResourceDescriptor,
    (ResourceDescriptor*)&gDll9EResourceDescriptor,
    (ResourceDescriptor*)&gDll9FResourceDescriptor,
    (ResourceDescriptor*)&gDllA0ResourceDescriptor,
    (ResourceDescriptor*)&gDllA1ResourceDescriptor,
    (ResourceDescriptor*)&gDllA2ResourceDescriptor,
    (ResourceDescriptor*)&gDllA3ResourceDescriptor,
    (ResourceDescriptor*)&gDummyA4ResourceDescriptor,
    (ResourceDescriptor*)&gDllA5ResourceDescriptor,
    (ResourceDescriptor*)&gDllA6ResourceDescriptor,
    (ResourceDescriptor*)&gDllA7ResourceDescriptor,
    (ResourceDescriptor*)&gDllA8ResourceDescriptor,
    (ResourceDescriptor*)&gDllA9ResourceDescriptor,
    (ResourceDescriptor*)&gDllAAResourceDescriptor,
    (ResourceDescriptor*)&gProjdummyResourceDescriptor,
    (ResourceDescriptor*)&gProjmagicstreamResourceDescriptor,
    (ResourceDescriptor*)&gProjmagicemmit1ResourceDescriptor,
    (ResourceDescriptor*)&gProjroombeamResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning1ResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning2ResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning3ResourceDescriptor,
    (ResourceDescriptor*)&gProjrobotfireResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning4ResourceDescriptor,
    (ResourceDescriptor*)&gProjenergise1ResourceDescriptor,
    (ResourceDescriptor*)&gProjenergise2ResourceDescriptor,
    (ResourceDescriptor*)&gProjsquirt1ResourceDescriptor,
    (ResourceDescriptor*)&gProjship1ResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning5ResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning7ResourceDescriptor,
    (ResourceDescriptor*)&gProjlightning6ResourceDescriptor,
    (ResourceDescriptor*)&gProjwallpowerResourceDescriptor,
    (ResourceDescriptor*)&gProjquakeshockResourceDescriptor,
    (ResourceDescriptor*)&gProjsunshockResourceDescriptor,
    (ResourceDescriptor*)&gProjteslaResourceDescriptor,
    (ResourceDescriptor*)&gProjcore1ResourceDescriptor,
    (ResourceDescriptor*)&gProjcore2ResourceDescriptor,
    (ResourceDescriptor*)&gProjcore3ResourceDescriptor,
    (ResourceDescriptor*)&gProjdfp1rResourceDescriptor,
    NULL,
    (ResourceDescriptor*)&gTrickyObjDescriptor,
    &gDllC5NullResourceDescriptor,
    (ResourceDescriptor*)&gAnimatedObjDescriptor,
    (ResourceDescriptor*)&gDIM2RoofRubObjDescriptor,
    (ResourceDescriptor*)&gDepthOfFieldPointObjDescriptor,
    (ResourceDescriptor*)&gBaddieObjDescriptor,
    (ResourceDescriptor*)&gIceBaddieObjDescriptor,
    (ResourceDescriptor*)&gDllCBObjDescriptor,
    (ResourceDescriptor*)&gChukChukObjDescriptor,
    (ResourceDescriptor*)&gIceBallObjDescriptor,
    (ResourceDescriptor*)&gDllCEObjDescriptor,
    (ResourceDescriptor*)&gCannonClawObjDescriptor,
    (ResourceDescriptor*)&gGrimbleObjDescriptor,
    (ResourceDescriptor*)&gTumbleWeedBushObjDescriptor,
    (ResourceDescriptor*)&gTumbleweedObjDescriptor,
    &gDllD3ObjDescriptor,
    (ResourceDescriptor*)&gSkeetlaWallObjDescriptor,
    (ResourceDescriptor*)&gKaldachomObjDescriptor,
    (ResourceDescriptor*)&gKaldachomMeObjDescriptor,
    (ResourceDescriptor*)&gKaldachomSpObjDescriptor,
    (ResourceDescriptor*)&gPinPonSpikeObjDescriptor,
    (ResourceDescriptor*)&gPollenObjDescriptor,
    (ResourceDescriptor*)&gPollenFragmentObjDescriptor,
    (ResourceDescriptor*)&gMikaBombObjDescriptor,
    (ResourceDescriptor*)&gMikaBombShadowObjDescriptor,
    (ResourceDescriptor*)&gGCbaddieShieldObjDescriptor,
    (ResourceDescriptor*)&gBaddieInterestPObjDescriptor,
    (ResourceDescriptor*)&gHagabonObjDescriptor,
    (ResourceDescriptor*)&gSwarmBaddieObjDescriptor,
    (ResourceDescriptor*)&gWispBaddieObjDescriptor,
    (ResourceDescriptor*)&gStaffObjDescriptor,
    (ResourceDescriptor*)&gFireballObjDescriptor,
    (ResourceDescriptor*)&gFlameThrowerspeObjDescriptor,
    (ResourceDescriptor*)&gShieldObjDescriptor,
    (ResourceDescriptor*)&gReStartMarkObjDescriptor,
    (ResourceDescriptor*)&gFlammableVineObjDescriptor,
    (ResourceDescriptor*)&gCheckpoint4ObjDescriptor,
    (ResourceDescriptor*)&gSetuppointObjDescriptor,
    (ResourceDescriptor*)&gSideloadObjDescriptor,
    (ResourceDescriptor*)&gSiderepelObjDescriptor,
    (ResourceDescriptor*)&gInfoPointObjDescriptor,
    (ResourceDescriptor*)&gCollectibleObjDescriptor,
    (ResourceDescriptor*)&gEffectBoxObjDescriptor,
    (ResourceDescriptor*)&gPushableObjDescriptor,
    (ResourceDescriptor*)&gWarpPointObjDescriptor,
    (ResourceDescriptor*)&gInvHitObjDescriptor,
    (ResourceDescriptor*)&gIceblastObjDescriptor,
    (ResourceDescriptor*)&gFlameblastObjDescriptor,
    (ResourceDescriptor*)&gDoorF4ObjDescriptor,
    (ResourceDescriptor*)&gSidekickBallObjDescriptor,
    (ResourceDescriptor*)&gAreaObjDescriptor,
    (ResourceDescriptor*)&gDllF7ObjDescriptor,
    (ResourceDescriptor*)&gLevelNameObjDescriptor,
    (ResourceDescriptor*)&gProjectileSwitchObjDescriptor,
    (ResourceDescriptor*)&gInvisibleHitSwitchObjDescriptor,
    (ResourceDescriptor*)&gPressureSwitchFBObjDescriptor,
    (ResourceDescriptor*)&gDllFCObjDescriptor,
    (ResourceDescriptor*)&gDllFDObjDescriptor,
    (ResourceDescriptor*)&gMagicPlantObjDescriptor,
    (ResourceDescriptor*)&gMagicGemObjDescriptor,
    (ResourceDescriptor*)&gTrickyWarpObjDescriptor,
    (ResourceDescriptor*)&gTrickyGuardObjDescriptor,
    (ResourceDescriptor*)&gStayPointObjDescriptor,
    (ResourceDescriptor*)&gCurveFishObjDescriptor,
    (ResourceDescriptor*)&gSmallBasketObjDescriptor,
    (ResourceDescriptor*)&gLargeCrateObjDescriptor,
    (ResourceDescriptor*)&gScarabObjDescriptor,
    (ResourceDescriptor*)&gWindLift107ObjDescriptor,
    (ResourceDescriptor*)&gEndObjectObjDescriptor,
    (ResourceDescriptor*)&gBreakableCarryableObjDescriptor,
    (ResourceDescriptor*)&gFall_LaddersObjDescriptor,
    (ResourceDescriptor*)&gFireFlyLanternObjDescriptor,
    (ResourceDescriptor*)&gLanternFireFlyObjDescriptor,
    (ResourceDescriptor*)&gPortalSpellDoorObjDescriptor,
    (ResourceDescriptor*)&gDeathSeqObjDescriptor,
    (ResourceDescriptor*)&gMMP_BridgeObjDescriptor,
    (ResourceDescriptor*)&gDoorObjDescriptor,
    (ResourceDescriptor*)&gDoorLockObjDescriptor,
    (ResourceDescriptor*)&gSeqObjectObjDescriptor,
    (ResourceDescriptor*)&gSeqObj2ObjDescriptor,
    (ResourceDescriptor*)&gIMMultiSeqObjDescriptor,
    (ResourceDescriptor*)&gDll115ObjDescriptor,
    (ResourceDescriptor*)&gWM_ColumnObjDescriptor,
    (ResourceDescriptor*)&gAppleOnTreeObjDescriptor,
    (ResourceDescriptor*)&gDusterObjDescriptor,
    (ResourceDescriptor*)&gColdWaterControlObjDescriptor,
    (ResourceDescriptor*)&gDecoration11AObjDescriptor,
    (ResourceDescriptor*)&gLanded_ArwingObjDescriptor,
    (ResourceDescriptor*)&gStaffActivatedObjDescriptor,
    (ResourceDescriptor*)&gTreasureChestObjDescriptor,
    (ResourceDescriptor*)&gMagicCaveBottomObjDescriptor,
    (ResourceDescriptor*)&gMagicCaveTopObjDescriptor,
    (ResourceDescriptor*)&gTrickyGuardSpotObjDescriptor,
    (ResourceDescriptor*)&gInfoTextObjDescriptor,
    (ResourceDescriptor*)&gCCTestInfotObjDescriptor,
    (ResourceDescriptor*)&gFuelCellObjDescriptor,
    (ResourceDescriptor*)&gDeathGasObjDescriptor,
    (ResourceDescriptor*)&gCurveObjDescriptor,
    (ResourceDescriptor*)&gTriggerObjDescriptor,
    (ResourceDescriptor*)&gDll127ObjDescriptor,
    (ResourceDescriptor*)&gKT_TorchObjDescriptor,
    (ResourceDescriptor*)&gCampFireObjDescriptor,
    (ResourceDescriptor*)&gCFCrateObjDescriptor,
    (ResourceDescriptor*)&gFXEmitObjDescriptor,
    (ResourceDescriptor*)&gTransporterObjDescriptor,
    (ResourceDescriptor*)&gLFXEmitterObjDescriptor,
    (ResourceDescriptor*)&gCFLightWallObjDescriptor,
    (ResourceDescriptor*)&gBarrelPadObjDescriptor,
    (ResourceDescriptor*)&gAreaFXEmitObjDescriptor,
    (ResourceDescriptor*)&gCF_DoorLightObjDescriptor,
    (ResourceDescriptor*)&gWaterFallSprayObjDescriptor,
    (ResourceDescriptor*)&gSfxPlayerObjDescriptor,
    (ResourceDescriptor*)&gTexscroll2ObjDescriptor,
    (ResourceDescriptor*)&gTexscrollObjDescriptor,
    (ResourceDescriptor*)&gWaveAnimatorObjDescriptor,
    (ResourceDescriptor*)&gAlphaAnimatorObjDescriptor,
    (ResourceDescriptor*)&gGroundAnimatorObjDescriptor,
    (ResourceDescriptor*)&gHitAnimatorObjDescriptor,
    (ResourceDescriptor*)&gVisAnimatorObjDescriptor,
    (ResourceDescriptor*)&gWallAnimatorObjDescriptor,
    (ResourceDescriptor*)&gXYZAnimatorObjDescriptor,
    (ResourceDescriptor*)&gExplodeAnimatorObjDescriptor,
    (ResourceDescriptor*)&gDIMBossIceSmashObjDescriptor,
    (ResourceDescriptor*)&gTexFrameAnimatorObjDescriptor,
    (ResourceDescriptor*)&gFogControlObjDescriptor,
    (ResourceDescriptor*)&gLightningObjDescriptor,
    (ResourceDescriptor*)&gFElevControlObjDescriptor,
    (ResourceDescriptor*)&gFEseqobjectObjDescriptor,
    (ResourceDescriptor*)&gDll144ObjDescriptor,
    (ResourceDescriptor*)&gCloudPrisonControlObjDescriptor,
    &gCloudShipControlNullResourceDescriptor,
    &gDll147NullResourceDescriptor,
    (ResourceDescriptor*)&gCFGuardianObjDescriptor,
    (ResourceDescriptor*)&gWindLiftObjDescriptor,
    (ResourceDescriptor*)&gCFPowerBaseObjDescriptor,
    (ResourceDescriptor*)&gCFMainCrystalObjDescriptor,
    (ResourceDescriptor*)&gBabyCloudRunnerObjDescriptor,
    &gLaserBeamNullResourceDescriptor,
    (ResourceDescriptor*)&gCFPrisonGuardObjDescriptor,
    (ResourceDescriptor*)&gCFPrisonUncleObjDescriptor,
    (ResourceDescriptor*)&gGCRobotLightBeamObjDescriptor,
    &gCFScalesGalNullResourceDescriptor,
    &gCFObjCreatNullResourceDescriptor,
    (ResourceDescriptor*)&gCFPerchObjDescriptor,
    (ResourceDescriptor*)&gCFPrisonCageObjDescriptor,
    &gDll155NullResourceDescriptor,
    &gDll156NullResourceDescriptor,
    (ResourceDescriptor*)&gSpiritDoorSpiritObjDescriptor,
    (ResourceDescriptor*)&gGunpowderBarrelObjDescriptor,
    (ResourceDescriptor*)&gBlastedObjDescriptor,
    (ResourceDescriptor*)&gExplodableObjDescriptor,
    (ResourceDescriptor*)&gCFForceFieldObjDescriptor,
    &gCFForceField15CNullResourceDescriptor,
    (ResourceDescriptor*)&gSlidingDoorObjDescriptor,
    &gDll15ENullResourceDescriptor,
    (ResourceDescriptor*)&gAttractorObjDescriptor,
    &gDll160NullResourceDescriptor,
    &gCFTreasRoboNullResourceDescriptor,
    (ResourceDescriptor*)&gCFMagicWallObjDescriptor,
    &gDll163NullResourceDescriptor,
    (ResourceDescriptor*)&gCFLevelControlObjDescriptor,
    &gCFRemovalShNullResourceDescriptor,
    (ResourceDescriptor*)&gExplodedObjDescriptor,
    (ResourceDescriptor*)&gSpiritDoorLockObjDescriptor,
    &gHoloPointNullResourceDescriptor,
    (ResourceDescriptor*)&gIMIceMountainObjDescriptor,
    (ResourceDescriptor*)&gCRrockfallObjDescriptor,
    (ResourceDescriptor*)&gMagicLightObjDescriptor,
    (ResourceDescriptor*)&gIMSnowClawObjDescriptor,
    (ResourceDescriptor*)&gIMIcePillarObjDescriptor,
    (ResourceDescriptor*)&gIMAnimSpaceObjDescriptor,
    (ResourceDescriptor*)&gIMSpaceThrusterObjDescriptor,
    (ResourceDescriptor*)&gIMSpaceRingObjDescriptor,
    (ResourceDescriptor*)&gIMSpaceRingGeneratorObjDescriptor,
    (ResourceDescriptor*)&gLINKBLevelControlObjDescriptor,
    (ResourceDescriptor*)&gLINKLevelControlObjDescriptor,
    (ResourceDescriptor*)&gCCRiverFlowObjDescriptor,
    (ResourceDescriptor*)&gDFropenodeObjDescriptor,
    &gDFSH_Door1SNullResourceDescriptor,
    (ResourceDescriptor*)&gDll177ObjDescriptor,
    (ResourceDescriptor*)&gDFSHShrineObjDescriptor,
    (ResourceDescriptor*)&gDFSHObjCreatorObjDescriptor,
    (ResourceDescriptor*)&gSpiritPrizeObjDescriptor,
    (ResourceDescriptor*)&gDFSHLaserBeamObjDescriptor,
    &gGCRobotPatrNullResourceDescriptor,
    (ResourceDescriptor*)&gRollingBarrelObjDescriptor,
    (ResourceDescriptor*)&gMMPLevelControlObjDescriptor,
    (ResourceDescriptor*)&gMoonSeedBushObjDescriptor,
    (ResourceDescriptor*)&gMMPAsteroidReObjDescriptor,
    (ResourceDescriptor*)&gMMPTrenchFxObjDescriptor,
    (ResourceDescriptor*)&gMMPMoonRockObjDescriptor,
    (ResourceDescriptor*)&gMMPGeyserVentObjDescriptor,
    (ResourceDescriptor*)&gDll184ObjDescriptor,
    (ResourceDescriptor*)&gCCGasVentObjDescriptor,
    (ResourceDescriptor*)&gCCGasVentControlObjDescriptor,
    (ResourceDescriptor*)&gCCQueenObjDescriptor,
    (ResourceDescriptor*)&gCCLightfootObjDescriptor,
    (ResourceDescriptor*)&gCCSharpClawPadObjDescriptor,
    (ResourceDescriptor*)&gCCPedestalObjDescriptor,
    (ResourceDescriptor*)&gCCLevelControlObjDescriptor,
    (ResourceDescriptor*)&gMMSHShrineObjDescriptor,
    (ResourceDescriptor*)&gMMSHScalesObjDescriptor,
    (ResourceDescriptor*)&gMMSHWaterSpikeObjDescriptor,
    (ResourceDescriptor*)&gECSHShrineObjDescriptor,
    (ResourceDescriptor*)&gECSHCupObjDescriptor,
    (ResourceDescriptor*)&gECSHCreatorObjDescriptor,
    (ResourceDescriptor*)&gGPSHShrineObjDescriptor,
    (ResourceDescriptor*)&gGPSHObjCreatorObjDescriptor,
    (ResourceDescriptor*)&gGPSHSceneObjDescriptor,
    (ResourceDescriptor*)&gDBSHShrineObjDescriptor,
    (ResourceDescriptor*)&gDBSHSymbolObjDescriptor,
    (ResourceDescriptor*)&gDll197ObjDescriptor,
    (ResourceDescriptor*)&gNWSHLevelControlObjDescriptor,
    (ResourceDescriptor*)&gDll199ObjDescriptor,
    (ResourceDescriptor*)&gDll19AObjDescriptor,
    (ResourceDescriptor*)&gDll19BObjDescriptor,
    (ResourceDescriptor*)&gDll19CObjDescriptor,
    (ResourceDescriptor*)&gDll19DObjDescriptor,
    (ResourceDescriptor*)&gDll19EObjDescriptor,
    (ResourceDescriptor*)&gNWTreeBridgeObjDescriptor,
    (ResourceDescriptor*)&gNWGeyserObjDescriptor,
    (ResourceDescriptor*)&gNW_mammothObjDescriptor,
    (ResourceDescriptor*)&gNWTrickyObjDescriptor,
    (ResourceDescriptor*)&gDll1A3ObjDescriptor,
    (ResourceDescriptor*)&gNW_iceObjDescriptor,
    (ResourceDescriptor*)&gNWLevelControlObjDescriptor,
    (ResourceDescriptor*)&gSHTrickyObjDescriptor,
    (ResourceDescriptor*)&gEdibleMushroomObjDescriptor,
    (ResourceDescriptor*)&gEnemyMushroomObjDescriptor,
    (ResourceDescriptor*)&gBombPlantObjDescriptor,
    (ResourceDescriptor*)&gBombPlantSporeObjDescriptor,
    (ResourceDescriptor*)&gBombPlantingSpotObjDescriptor,
    (ResourceDescriptor*)&gSH_queenearthwalkerObjDescriptor,
    (ResourceDescriptor*)&gSH_thorntailObjDescriptor,
    (ResourceDescriptor*)&gSH_LevelControlObjDescriptor,
    (ResourceDescriptor*)&gWarpStoneLiftObjDescriptor,
    (ResourceDescriptor*)&gWarpStoneObjDescriptor,
    (ResourceDescriptor*)&gSH_staffObjDescriptor,
    (ResourceDescriptor*)&gSH_staffHazeObjDescriptor,
    (ResourceDescriptor*)&gSH_BeaconObjDescriptor,
    (ResourceDescriptor*)&gSH_EmptyTumbleWObjDescriptor,
    (ResourceDescriptor*)&gLightfootObjDescriptor,
    (ResourceDescriptor*)&gSC_levelcontrolObjDescriptor,
    (ResourceDescriptor*)&gSC_MusicTreeObjDescriptor,
    (ResourceDescriptor*)&gSC_totempoleObjDescriptor,
    (ResourceDescriptor*)&gSC_CloudrunnerAObjDescriptor,
    (ResourceDescriptor*)&gSC_totempuzzleObjDescriptor,
    (ResourceDescriptor*)&gSC_totembondObjDescriptor,
    (ResourceDescriptor*)&gSC_totemstrengthObjDescriptor,
    (ResourceDescriptor*)&gPaymentKioskObjDescriptor,
    (ResourceDescriptor*)&gLavaBall1BEObjDescriptor,
    (ResourceDescriptor*)&gLavaBall1BFObjDescriptor,
    (ResourceDescriptor*)&gDIMLogFireObjDescriptor,
    (ResourceDescriptor*)&gDIMSnowBallObjDescriptor,
    (ResourceDescriptor*)&gDIMSnowBall1C2ObjDescriptor,
    (ResourceDescriptor*)&gDIMGateObjDescriptor,
    (ResourceDescriptor*)&gDIMIceWallObjDescriptor,
    (ResourceDescriptor*)&gDIMBarrierObjDescriptor,
    (ResourceDescriptor*)&gDIMCannonObjDescriptor,
    (ResourceDescriptor*)&gDIMLavaSmashObjDescriptor,
    (ResourceDescriptor*)&gDIMBridgeCogMaiObjDescriptor,
    (ResourceDescriptor*)&gDIMDismountPointObjDescriptor,
    (ResourceDescriptor*)&gExplosionObjDescriptor,
    (ResourceDescriptor*)&gDIMWoodDoor2ObjDescriptor,
    (ResourceDescriptor*)&gDIMMagicBridgeObjDescriptor,
    (ResourceDescriptor*)&gDIM_LevelControlObjDescriptor,
    (ResourceDescriptor*)&gDll1CEObjDescriptor,
    (ResourceDescriptor*)&gDll1CFObjDescriptor,
    &gDIM_trickyObjDescriptor,
    (ResourceDescriptor*)&gDIMTruthHornIceObjDescriptor,
    (ResourceDescriptor*)&gWorldPlanetObjDescriptor,
    (ResourceDescriptor*)&gWorldObjObjDescriptor,
    (ResourceDescriptor*)&gWorldAsteroidsObjDescriptor,
    (ResourceDescriptor*)&gDIM2ConveyorObjDescriptor,
    (ResourceDescriptor*)&gDll1D6ObjDescriptor,
    (ResourceDescriptor*)&gDIM2SnowBallObjDescriptor,
    (ResourceDescriptor*)&gDIM2PathGeneratorObjDescriptor,
    (ResourceDescriptor*)&gDIM2PrisonMammothObjDescriptor,
    (ResourceDescriptor*)&gDll1DAObjDescriptor,
    (ResourceDescriptor*)&gDll1DBObjDescriptor,
    (ResourceDescriptor*)&gDIM2IceFloeObjDescriptor,
    (ResourceDescriptor*)&gDIM2IcicleObjDescriptor,
    (ResourceDescriptor*)&gDIM2LavaControlObjDescriptor,
    (ResourceDescriptor*)&gDll1DFObjDescriptor,
    (ResourceDescriptor*)&gDIM_BossObjDescriptor,
    (ResourceDescriptor*)&gDIM_BossGutObjDescriptor,
    (ResourceDescriptor*)&gDIM_BossTonsilObjDescriptor,
    (ResourceDescriptor*)&gDIM_BossGut2ObjDescriptor,
    (ResourceDescriptor*)&gMAGICMakerObjDescriptor,
    (ResourceDescriptor*)&gDIM_BossSpitObjDescriptor,
    (ResourceDescriptor*)&gDIMbosscrackparObjDescriptor,
    (ResourceDescriptor*)&gDIMbossfireObjDescriptor,
    (ResourceDescriptor*)&gSB_GalleonObjDescriptor,
    (ResourceDescriptor*)&gSB_PropellerObjDescriptor,
    (ResourceDescriptor*)&gSB_ShipHeadObjDescriptor,
    (ResourceDescriptor*)&gSB_ShipMastObjDescriptor,
    (ResourceDescriptor*)&gSB_ShipGunObjDescriptor,
    (ResourceDescriptor*)&gSB_FireBallObjDescriptor,
    (ResourceDescriptor*)&gSB_CannonBallObjDescriptor,
    (ResourceDescriptor*)&gSB_CloudBallObjDescriptor,
    (ResourceDescriptor*)&gSB_KyteCageObjDescriptor,
    (ResourceDescriptor*)&gSB_SeqDoorObjDescriptor,
    (ResourceDescriptor*)&gSB_CageKyteObjDescriptor,
    (ResourceDescriptor*)&gSB_MiniFireObjDescriptor,
    (ResourceDescriptor*)&gDll1F4ObjDescriptor,
    (ResourceDescriptor*)&gDll1F5ObjDescriptor,
    (ResourceDescriptor*)&gDll1F6ObjDescriptor,
    (ResourceDescriptor*)&gSB_ShipGunBrokeObjDescriptor,
    (ResourceDescriptor*)&gWM_GalleonObjDescriptor,
    (ResourceDescriptor*)&gWM_ObjCreatorObjDescriptor,
    (ResourceDescriptor*)&gWM_seqobjectObjDescriptor,
    (ResourceDescriptor*)&gDll1FBObjDescriptor,
    (ResourceDescriptor*)&gLaserBeamObjDescriptor,
    (ResourceDescriptor*)&gWM_LaserTargetObjDescriptor,
    (ResourceDescriptor*)&gPressureSwitchObjDescriptor,
    (ResourceDescriptor*)&gDll1FFObjDescriptor,
    (ResourceDescriptor*)&gDll200ObjDescriptor,
    (ResourceDescriptor*)&gWM_colriseObjDescriptor,
    &gDll202NullResourceDescriptor,
    &gDll203NullResourceDescriptor,
    (ResourceDescriptor*)&gWM_TorchObjDescriptor,
    &gWMVeinNullResourceDescriptor,
    (ResourceDescriptor*)&gLightSourceObjDescriptor,
    (ResourceDescriptor*)&gWM_WormObjDescriptor,
    &gWM_WallpoweNullResourceDescriptor,
    (ResourceDescriptor*)&gWM_LevelControlObjDescriptor,
    (ResourceDescriptor*)&gWM_GeneralScalesObjDescriptor,
    &gFireFlyObjDescriptor,
    &gWM_spiritplaceObjDescriptor,
    (ResourceDescriptor*)&gWM_seqpointObjDescriptor,
    &gWM_sunObjDescriptor,
    &gWM_SpiritSetObjDescriptor,
    (ResourceDescriptor*)&gWM_PlanetsObjDescriptor,
    (ResourceDescriptor*)&gWM_WallCrawlerObjDescriptor,
    &gDll212NullResourceDescriptor,
    &gWM_VConsoleNullResourceDescriptor,
    &gWM_TransTopNullResourceDescriptor,
    &gWM_newcrystalObjDescriptor,
    &gVFP_LevelControlObjDescriptor,
    &gVFP_ObjCreatorObjDescriptor,
    &gVFP_MiniFireObjDescriptor,
    &gDll219ObjDescriptor,
    &gVFP_statueballObjDescriptor,
    &gDll21BObjDescriptor,
    &gVFP_LaddersObjDescriptor,
    &gVFPLiftObjDescriptor,
    &gVFP_Block1ObjDescriptor,
    &gVFP_PlatformObjDescriptor,
    (ResourceDescriptor*)&gVFP_DoorSwitchObjDescriptor,
    &gSeqPointObjDescriptor,
    &gVFPDragHeadObjDescriptor,
    (ResourceDescriptor*)&gVFP_coreplatObjDescriptor,
    &gDll224ObjDescriptor,
    &gVFP_flamepointObjDescriptor,
    &gVFP_lavapoolObjDescriptor,
    &gVFP_lavastarObjDescriptor,
    &gVFP_SpellPlaceObjDescriptor,
    &gDFP_LevelControlObjDescriptor,
    &gDFP_ObjCreatorObjDescriptor,
    &gDFP_TorchObjDescriptor,
    &gDll22CObjDescriptor,
    (ResourceDescriptor*)&gDFP_seqpointObjDescriptor,
    (ResourceDescriptor*)&gDoorswitchObjDescriptor,
    (ResourceDescriptor*)&gDfpfloorbarObjDescriptor,
    &gChukaObjDescriptor,
    &gTrickyCurveObjDescriptor,
    &gDFP_RotatePObjDescriptor,
    (ResourceDescriptor*)&gDfpstatue1ObjDescriptor,
    (ResourceDescriptor*)&gDfperchwitchObjDescriptor,
    (ResourceDescriptor*)&gDfptargetblockObjDescriptor,
    (ResourceDescriptor*)&gLaserUnsupportedObjDescriptor,
    (ResourceDescriptor*)&gLaserObjDescriptor,
    &gFireObjDescriptor,
    (ResourceDescriptor*)&gTextBlockObjDescriptor,
    (ResourceDescriptor*)&gPlatform1ObjDescriptor,
    &gDfplightniObjDescriptor,
    &gDfppowerslObjDescriptor,
    &gDBPointMumNullResourceDescriptor,
    &gDll23ENullResourceDescriptor,
    (ResourceDescriptor*)&gDB_eggObjDescriptor,
    &gGCRobotBlastObjDescriptor,
    &gDrakorEnergyObjDescriptor,
    (ResourceDescriptor*)&gDBstealerwormObjDescriptor,
    &gDBHoleControl1ObjDescriptor,
    &Dummy244,
    &Dummy245,
    &Dummy246,
    &Dummy247,
    &Dummy248,
    &gDll249NullResourceDescriptor,
    &Dummy24A,
    &Dummy24B,
    &Dummy24C_funcs,
    &gBossDrakorObjDescriptor,
    &gDrakorDThornBushObjDescriptor,
    &gKtRexLevelObjDescriptor,
    (ResourceDescriptor*)&gKtRexObjDescriptor,
    &gKtRexFloorSwitchObjDescriptor,
    &gKtLazerwallObjDescriptor,
    &gKtLazerlightObjDescriptor,
    (ResourceDescriptor*)&gKtFallingrocksObjDescriptor,
    (ResourceDescriptor*)&gSnowBikeObjDescriptor,
    (ResourceDescriptor*)&gDIMSnowHorn1ObjDescriptor,
    (ResourceDescriptor*)&gDR_EarthWarriorObjDescriptor,
    &gDR_CloudRunnerObjDescriptor,
    (ResourceDescriptor*)&gSB_CloudRunnerObjDescriptor,
    (ResourceDescriptor*)&gStaticCameraObjDescriptor,
    (ResourceDescriptor*)&gMoonSeedPlantingSpotObjDescriptor,
    &gSnowClawObjDescriptor,
    &gCrCloudRaceObjDescriptor,
    &gSpellStoneObjDescriptor,
    &gCrFuelTankObjDescriptor,
    &gProximityMineObjDescriptor,
    (ResourceDescriptor*)&gDrLaserCannonObjDescriptor,
    &gDrakorMissileObjDescriptor,
    (ResourceDescriptor*)&gGmMazeWellObjDescriptor,
    &gDll264NullResourceDescriptor,
    &gDrCreatorObjDescriptor,
    &gKytesMumObjDescriptor,
    &gDll267NullResourceDescriptor,
    &gDrCageControlObjDescriptor,
    (ResourceDescriptor*)&gExplodePlanObjDescriptor,
    &gDR_GeezerNullResourceDescriptor,
    &gDrChimmeyObjDescriptor,
    &gDrCageWithObjDescriptor,
    &gDR_VinesNullResourceDescriptor,
    &gDrShackleObjDescriptor,
    &gDrGeneratorObjDescriptor,
    &gDR_RockNullResourceDescriptor,
    &gDrakorHoverPadObjDescriptor,
    (ResourceDescriptor*)&gHighTopObjDescriptor,
    (ResourceDescriptor*)&gFirePipeObjDescriptor,
    &gDR_pulleyNullResourceDescriptor,
    &gDR_cradleNullResourceDescriptor,
    &gDll276NullResourceDescriptor,
    &gCFWindLiftLNullResourceDescriptor,
    &gDll278NullResourceDescriptor,
    &gDrEnergyDiscObjDescriptor,
    &gDR_CollapseNullResourceDescriptor,
    &gDll27BNullResourceDescriptor,
    &gDrLightBeaObjDescriptor,
    &gDll27DNullResourceDescriptor,
    &gDrMusicContObjDescriptor,
    &gDll27FNullResourceDescriptor,
    &gDrCloudPerObjDescriptor,
    (ResourceDescriptor*)&gDrEarthCalObjDescriptor,
    (ResourceDescriptor*)&gBarrelGenerObjDescriptor,
    (ResourceDescriptor*)&gDrBarrelGrObjDescriptor,
    &gShopItemObjDescriptor,
    &gShopObjDescriptor,
    &gShopKeeperObjDescriptor,
    (ResourceDescriptor*)&gSPScarabObjDescriptor,
    &gSPDrapeObjDescriptor,
    &gSPitembeamObjDescriptor,
    &gEarthWalkerObjDescriptor,
    &gDll28BObjDescriptor,
    &gWCBouncyCraObjDescriptor,
    &gWCLevelContObjDescriptor,
    (ResourceDescriptor*)&gWCBeaconObjDescriptor,
    (ResourceDescriptor*)&gWCPressureSObjDescriptor,
    &gWCPushBlockObjDescriptor,
    &gWCTileObjDescriptor,
    (ResourceDescriptor*)&gWCTrexStatuObjDescriptor,
    (ResourceDescriptor*)&gSunTempleObjDescriptor,
    (ResourceDescriptor*)&gWCTempleObjDescriptor,
    (ResourceDescriptor*)&gWCApertureSObjDescriptor,
    (ResourceDescriptor*)&gWCTempleDiaObjDescriptor,
    (ResourceDescriptor*)&gWCTempleBriObjDescriptor,
    (ResourceDescriptor*)&gWCFloorTileObjDescriptor,
    (ResourceDescriptor*)&gDll299ObjDescriptor,
    (ResourceDescriptor*)&gARWArwingObjDescriptor,
    (ResourceDescriptor*)&gArwingAndrossStuffObjDescriptor,
    (ResourceDescriptor*)&gARWArwingBoObjDescriptor,
    (ResourceDescriptor*)&gARWArwingGuObjDescriptor,
    &gDll29EObjDescriptor,
    &gARWBombCollObjDescriptor,
    &gRingObjDescriptor,
    (ResourceDescriptor*)&gARWLevelConObjDescriptor,
    &gARWSpeedStrObjDescriptor,
    &gDll2A3ObjDescriptor,
    &gDll2A4ObjDescriptor,
    &gARWGeneratoObjDescriptor,
    &gARWSquadronObjDescriptor,
    &gARWProximitObjDescriptor,
    &gARWBlockerObjDescriptor,
    (ResourceDescriptor*)&gPointLightObjDescriptor,
    (ResourceDescriptor*)&gDirectionalLightObjDescriptor,
    &gProjectedLightObjDescriptor,
    (ResourceDescriptor*)&gControlLightObjDescriptor,
    (ResourceDescriptor*)&gSoftBodyObjDescriptor,
    &gWaterFlowWeObjDescriptor,
    (ResourceDescriptor*)&gTreeObjDescriptor,
    (ResourceDescriptor*)&gBrokenPipeObjDescriptor,
    (ResourceDescriptor*)&gCmbSrcObjDescriptor,
    (ResourceDescriptor*)&gDustMoteSouObjDescriptor,
    &gVortexObjDescriptor,
    (ResourceDescriptor*)&gCNTcounterObjDescriptor,
    &gTimerObjDescriptor,
    (ResourceDescriptor*)&gCNThitObjecObjDescriptor,
    (ResourceDescriptor*)&gMCUpgradeObjDescriptor,
    (ResourceDescriptor*)&gMCUpgradeMaObjDescriptor,
    (ResourceDescriptor*)&gMCStaffEffeObjDescriptor,
    (ResourceDescriptor*)&gMCLightningObjDescriptor,
    (ResourceDescriptor*)&gGF_LevelConObjDescriptor,
    (ResourceDescriptor*)&gAndrossObjDescriptor,
    (ResourceDescriptor*)&gAndrossHandObjDescriptor,
    (ResourceDescriptor*)&gAndrossBrainObjDescriptor,
    (ResourceDescriptor*)&gAndrossLighObjDescriptor,
    &gTitleScreenObjDescriptor,
    NULL,
};

s32 gModelEngineUiDllResourceIds[] = {
    -1, 16, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, 58, -1, 63, 64, 65, -1,
};
