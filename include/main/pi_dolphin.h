#ifndef MAIN_PI_DOLPHIN_H_
#define MAIN_PI_DOLPHIN_H_

#include "ghidra_import.h"

u32 mapLoadDataFile(int param_1, int param_2);
void FUN_800443fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80044400(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,u32 *param_13,
                 int param_14,u32 param_15,u32 param_16);
u32 FUN_80044404(int param_1);
void FUN_80044424(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void piRomLoadSection(int param_1,int param_2,int param_3);
void FUN_80044840(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 *param_11,u32 *param_12,
                 int param_13,u32 param_14,int param_15,u32 param_16);
void FUN_80044bc4(u32 param_1,u32 param_2,u32 *param_3,u32 *param_4,
                 int param_5,u32 param_6,int param_7);
void FUN_80044d44(u32 param_1,u32 param_2,u32 *param_3,u32 *param_4,
                 int param_5,u32 param_6,int param_7);
void FUN_80044e24(u32 param_1,u32 param_2,u32 *param_3,u32 *param_4,
                 u32 *param_5);
void FUN_80044f74(int param_1,int *param_2,int *param_3,u32 *param_4,int param_5);
void FUN_80044fc4(u32 param_1,u32 param_2,u32 *param_3);
void FUN_80045148(u32 param_1,u32 param_2,u32 *param_3);
u32 FUN_800452f8(int param_1);
void FUN_80045328(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_800455b8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9,u32 param_10,u32 param_11,u32 param_12,
                u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_80045734(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9);
void FUN_800458ac(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800458b0(void);
void FUN_800458fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80045900(void);
void FUN_80045a58(void);
void FUN_80045b94(void);
void FUN_80045bd0(void);
void FUN_80045bd4(u8 param_1,u8 param_2,u8 param_3);
void FUN_80045be8(void);
u32 FUN_80045c4c(char param_1);
void FUN_80045d68(u8 param_1);
void FUN_80045da4(void);
void fn_8004A8F8(char param_1);
void FUN_80045fcc(void);
void FUN_8004600c(void);
u32 FUN_800461b4(int *param_1,int *param_2);
void FUN_80046270(int param_1,int param_2,int param_3);
void FUN_800462f8(u32 param_1,u32 param_2,u8 param_3,u32 param_4,int param_5);
void fn_8004B11C(u32 param_1,u32 param_2,u8 param_3);
u32 FUN_800469d0(int param_1);
int FUN_80046a00(int *param_1);
void fn_8004B394(void);
u32 FUN_80046cd0(int *param_1,int param_2,int param_3,int param_4,u8 param_5);
void FUN_80046f44(u32 *param_1);
void FUN_80046f84(int *param_1);
void FUN_80046fd4(void);
u32 FUN_80047000(int param_1,u32 param_2,int param_3);
void FUN_80047d88(char *param_1,char param_2,char param_3,u32 *param_4,u32 *param_5);
void FUN_80047fdc(double param_1,u8 param_2);
void FUN_80048000(void);
void FUN_8004800c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 u8 param_6);
void FUN_80048048(u32 *param_1,u32 *param_2);
u8 FUN_80048094(void);
int FUN_800480a0(int param_1,int param_2);
void FUN_800480b4(int param_1,int param_2);
void FUN_8004812c(int param_1,int param_2);
void FUN_80048178(void);
void FUN_8004817c(u32 param_1,u32 param_2,u32 param_3,u32 param_4,u32 param_5);
void FUN_800487e0(float *param_1);
void FUN_80048bc4(void);
void FUN_80048f00(int param_1);
void FUN_80049024(void);
void FUN_80049260(void);
void FUN_8004938c(int param_1);
void FUN_80049390(void);
void FUN_80049910(u32 *param_1);
void FUN_80049ee0(void);
void FUN_80049fb0(u32 *param_1);
void FUN_8004a094(void);
void FUN_8004a2c4(void);
void FUN_8004a394(double param_1,u32 *param_2,float *param_3);
void FUN_8004a670(double param_1,u32 *param_2,float *param_3);
void FUN_8004a94c(double param_1,u32 *param_2,float *param_3);
void FUN_8004ac40(int param_1,float *param_2);
void FUN_8004adc4(int param_1);
void FUN_8004afc0(float *param_1);
void FUN_8004b41c(u32 param_1,u32 param_2,int param_3,int param_4,int param_5);
void FUN_8004b8cc(u32 param_1);
void FUN_8004b960(u32 param_1,u32 param_2,u32 param_3,u32 param_4);
void FUN_8004bc68(char param_1);
void FUN_8004bd68(void);
void FUN_8004be30(char param_1);
void FUN_8004bf28(int param_1,char param_2,u32 param_3);
void FUN_8004c174(int param_1,char param_2);
void FUN_8004c178(int param_1,float *param_2);


/* extern-cleanup: defining-file public prototypes */
void setDisplayCopyFilter(void);
void gxTransformFn_8004a83c(void);
void allocSomething32bytes(void);
void initViewport(void);
void tvInit(void);
void fn_8004AFA0(int* q, int* elem, int idx);
void fn_8004AB5C(int* q, int* elem, int idx, u32 d, char* obj);


/* extern-cleanup: defining-file public prototypes */
u8 isHeavyFogEnabled(void);


/* Resource fileIds indexed into sResourceFileNameTable[] / used by fileLoad(),
 * fileLoadToBuffer(), fileLoadToBufferOffset() and mapLoadDataFile().
 * _A/_B suffixes mark the two physical slots of a dual-buffered per-map resource. */
enum MldfFileId {
    MLDF_FILEID_AUDIO_TAB       = 0x00, /* AUDIO.tab */
    MLDF_FILEID_AUDIO_BIN       = 0x01, /* AUDIO.bin */
    MLDF_FILEID_SFX_TAB         = 0x02, /* SFX.tab (string defined outside pi_dolphin.c) */
    MLDF_FILEID_SFX_BIN         = 0x03, /* SFX.bin */
    MLDF_FILEID_AMBIENT_TAB     = 0x04, /* AMBIENT.tab */
    MLDF_FILEID_AMBIENT_BIN     = 0x05, /* AMBIENT.bin */
    MLDF_FILEID_MUSIC_TAB       = 0x06, /* MUSIC.tab */
    MLDF_FILEID_MUSIC_BIN       = 0x07, /* MUSIC.bin */
    MLDF_FILEID_MPEG_TAB        = 0x08, /* MPEG.tab */
    MLDF_FILEID_MPEG_BIN        = 0x09, /* MPEG.bin */
    MLDF_FILEID_MUSICACT_BIN    = 0x0a, /* MUSICACT.bin */
    MLDF_FILEID_CAMACTIO_BIN    = 0x0b, /* CAMACTIO.bin */
    MLDF_FILEID_LACTIONS_BIN    = 0x0c, /* LACTIONS.bin */
    MLDF_FILEID_ANIMCURV_BIN_A  = 0x0d, /* ANIMCURV.bin, slot A */
    MLDF_FILEID_ANIMCURV_TAB_A  = 0x0e, /* ANIMCURV.tab, slot A */
    MLDF_FILEID_OBJSEQ2C_TAB    = 0x0f, /* OBJSEQ2C.tab */
    MLDF_FILEID_FONTS_BIN       = 0x10, /* FONTS.bin */
    MLDF_FILEID_CACHEFON_BIN_A  = 0x11, /* CACHEFON.bin, slot A */
    MLDF_FILEID_CACHEFON_BIN_B  = 0x12, /* CACHEFON.bin, slot B (dup) */
    MLDF_FILEID_GAMETEXT_BIN    = 0x13, /* GAMETEXT.bin (old/root copy) */
    MLDF_FILEID_GAMETEXT_TAB    = 0x14, /* GAMETEXT.tab (old/root copy) */
    MLDF_FILEID_GLOBALMA_BIN    = 0x15, /* globalma.bin */
    MLDF_FILEID_TABLES_BIN      = 0x16, /* TABLES.bin */
    MLDF_FILEID_TABLES_TAB      = 0x17, /* TABLES.tab */
    MLDF_FILEID_SCREENS_BIN     = 0x18, /* SCREENS.bin */
    MLDF_FILEID_SCREENS_TAB     = 0x19, /* SCREENS.tab */
    MLDF_FILEID_VOXMAP_TAB_A    = 0x1a, /* VOXMAP.tab, slot A */
    MLDF_FILEID_VOXMAP_BIN_A    = 0x1b, /* VOXMAP.bin, slot A */
    MLDF_FILEID_WARPTAB_BIN     = 0x1c, /* WARPTAB.bin - 16-byte WarpDestination records */
    MLDF_FILEID_MAPS_BIN        = 0x1d, /* MAPS.bin */
    MLDF_FILEID_MAPS_TAB        = 0x1e, /* MAPS.tab */
    MLDF_FILEID_MAPINFO_BIN     = 0x1f, /* MAPINFO.bin */
    MLDF_FILEID_TEX1_BIN_A      = 0x20, /* TEX1.bin, slot A */
    MLDF_FILEID_TEX1_TAB_A      = 0x21, /* TEX1.tab, slot A */
    MLDF_FILEID_TEXTABLE_BIN    = 0x22, /* TEXTABLE.bin */
    MLDF_FILEID_TEX0_BIN_A      = 0x23, /* TEX0.bin, slot A */
    MLDF_FILEID_TEX0_TAB_A      = 0x24, /* TEX0.tab, slot A */
    MLDF_FILEID_BLOCKS_BIN_A    = 0x25, /* BLOCKS.bin, slot A */
    MLDF_FILEID_BLOCKS_TAB_A    = 0x26, /* BLOCKS.tab, slot A */
    MLDF_FILEID_TRKBLK_TAB      = 0x27, /* TRKBLK.tab */
    MLDF_FILEID_HITS_BIN        = 0x28, /* HITS.bin */
    MLDF_FILEID_HITS_TAB        = 0x29, /* HITS.tab */
    MLDF_FILEID_MODELS_TAB_A    = 0x2a, /* MODELS.tab, slot A */
    MLDF_FILEID_MODELS_BIN_A    = 0x2b, /* MODELS.bin, slot A */
    MLDF_FILEID_MODELIND_BIN    = 0x2c, /* MODELIND.bin - model id -> index, 8-byte records */
    MLDF_FILEID_MODANIM_TAB     = 0x2d, /* MODANIM.TAB - per-model anim header index */
    MLDF_FILEID_MODANIM_BIN     = 0x2e, /* MODANIM.BIN - per-model anim header buffer */
    MLDF_FILEID_ANIM_TAB_A      = 0x2f, /* ANIM.TAB, slot A */
    MLDF_FILEID_ANIM_BIN_A      = 0x30, /* ANIM.BIN, slot A */
    MLDF_FILEID_AMAP_TAB        = 0x31, /* AMAP.TAB - anim id -> offset index */
    MLDF_FILEID_AMAP_BIN        = 0x32, /* AMAP.BIN - anim data payload */
    MLDF_FILEID_BITTABLE_BIN    = 0x33, /* BITTABLE.bin */
    MLDF_FILEID_WEAPONDA_BIN    = 0x34, /* WEAPONDA.bin - weaponDaTable entries */
    MLDF_FILEID_VOXOBJ_TAB      = 0x35, /* VOXOBJ.tab */
    MLDF_FILEID_VOXOBJ_BIN      = 0x36, /* VOXOBJ.bin */
    MLDF_FILEID_MODLINES_BIN    = 0x37, /* MODLINES.bin - 20-byte records */
    MLDF_FILEID_MODLINES_TAB    = 0x38, /* MODLINES.tab - u32 offset pairs */
    MLDF_FILEID_SAVEGAME_BIN    = 0x39, /* SAVEGAME.bin */
    MLDF_FILEID_SAVEGAME_TAB    = 0x3a, /* SAVEGAME.tab */
    MLDF_FILEID_OBJSEQ_BIN      = 0x3b, /* OBJSEQ.bin */
    MLDF_FILEID_OBJSEQ_TAB      = 0x3c, /* OBJSEQ.tab */
    MLDF_FILEID_OBJECTS_TAB     = 0x3d, /* OBJECTS.tab - -1-terminated u32 offsets */
    MLDF_FILEID_OBJECTS_BIN     = 0x3e, /* OBJECTS.bin - object definitions */
    MLDF_FILEID_OBJINDEX_BIN    = 0x3f, /* OBJINDEX.bin - s16 array */
    MLDF_FILEID_OBJEVENT_BIN    = 0x40, /* OBJEVENT.bin - eventTable entries (used) */
    MLDF_FILEID_OBJHITS_BIN     = 0x41, /* OBJHITS.bin - sparse per-move hit-reaction data */
    MLDF_FILEID_DLLS_BIN        = 0x42, /* DLLS.bin */
    MLDF_FILEID_DLLS_TAB        = 0x43, /* DLLS.tab */
    MLDF_FILEID_DLLSIMPO_BIN    = 0x44, /* DLLSIMPO.bin */
    MLDF_FILEID_MODELS_TAB_B    = 0x45, /* MODELS.tab, slot B */
    MLDF_FILEID_MODELS_BIN_B    = 0x46, /* MODELS.bin, slot B */
    MLDF_FILEID_BLOCKS_BIN_B    = 0x47, /* BLOCKS.bin, slot B */
    MLDF_FILEID_BLOCKS_TAB_B    = 0x48, /* BLOCKS.tab, slot B */
    MLDF_FILEID_ANIM_TAB_B      = 0x49, /* ANIM.TAB, slot B */
    MLDF_FILEID_ANIM_BIN_B      = 0x4a, /* ANIM.BIN, slot B */
    MLDF_FILEID_TEX1_BIN_B      = 0x4b, /* TEX1.bin, slot B */
    MLDF_FILEID_TEX1_TAB_B      = 0x4c, /* TEX1.tab, slot B */
    MLDF_FILEID_TEX0_BIN_B      = 0x4d, /* TEX0.bin, slot B */
    MLDF_FILEID_TEX0_TAB_B      = 0x4e, /* TEX0.tab, slot B */
    MLDF_FILEID_TEXPRE_BIN      = 0x4f, /* TEXPRE.bin */
    MLDF_FILEID_TEXPRE_TAB      = 0x50, /* TEXPRE.tab */
    MLDF_FILEID_PREANIM_BIN     = 0x51, /* PREANIM.bin */
    MLDF_FILEID_PREANIM_TAB     = 0x52, /* PREANIM.tab */
    MLDF_FILEID_VOXMAP_TAB_B    = 0x53, /* VOXMAP.tab, slot B */
    MLDF_FILEID_VOXMAP_BIN_B    = 0x54, /* VOXMAP.bin, slot B */
    MLDF_FILEID_ANIMCURV_BIN_B  = 0x55, /* ANIMCURV.bin, slot B */
    MLDF_FILEID_ANIMCURV_TAB_B  = 0x56, /* ANIMCURV.tab, slot B */
    MLDF_FILEID_ENVFXACT_BIN    = 0x57, /* ENVFXACT.bin */
    MLDF_FILEID_UNUSED_58       = 0x58, /* sResourceFileNameNull */
    MLDF_FILEID_UNUSED_59       = 0x59, /* sResourceFileNameNull */
};

#endif /* MAIN_PI_DOLPHIN_H_ */
