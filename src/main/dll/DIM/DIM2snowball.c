#include "main/audio/sfx_ids.h"
#include "main/asset_load.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIM2snowball.h"
#include "main/objanim_internal.h"
#include "global.h"

typedef struct DimtruthhorniceObjectDef {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} DimtruthhorniceObjectDef;


typedef struct Dim2snowballObjectDef {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} Dim2snowballObjectDef;


typedef struct Dll1CFObjectDef {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} Dll1CFObjectDef;


typedef struct Dim2pathgeneratorObjectDef {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} Dim2pathgeneratorObjectDef;


typedef struct Dim2pathgeneratorPlacement {
    u8 pad0[0x3 - 0x0];
    u8 unk3;
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x14 - 0x8];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u16 unk1E;
    s16 unk20;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} Dim2pathgeneratorPlacement;


/* dim2conveyor_getExtraSize == 0x14. */
typedef struct Dim2ConveyorState {
    f32 scrollX;    /* 0x00: per-area conveyor scroll vector */
    f32 scrollY;    /* 0x04 */
    u8 pad08[4];
    f32 swapTimer;  /* 0x0c: 0x49b23 direction-swap countdown */
    int musicHold;  /* 0x10: frames left keeping music track 0xdf alive */
} Dim2ConveyorState;
STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

/* dll_1D6_getExtraSize == 0x20 (crusher platform). */
typedef struct Dll1D6State {
    void *bufA;     /* 0x00: mmAlloc'd 40B getTabEntry rows */
    void *bufB;     /* 0x04 */
    f32 hitRangeSqA;/* 0x08 */
    f32 hitRangeSqB;/* 0x0c */
    f32 bobPhase;   /* 0x10 */
    f32 bobRate;    /* 0x14 */
    s16 upTimer;    /* 0x18 */
    s16 downTimer;  /* 0x1a */
    s8 dizzyTimer;  /* 0x1c */
    u8 flags1D;     /* 0x1d: 1 = raised, 2 = armed, 4 = bobbing */
    u8 hitRow;      /* 0x1e */
    u8 slot;        /* 0x1f: index into the lbl_803DBF20 slot table */
} Dll1D6State;
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

/* dimtruthhornice_getExtraSize == 0x8. */
typedef struct TruthHornIceState {
    s16 gameBit;    /* 0x00 */
    s8 hitsLeft;    /* 0x02 */
    s8 phase;       /* 0x03 */
    f32 timer;      /* 0x04 */
} TruthHornIceState;
STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

/* dim2snowball_getExtraSize == 0xb0 (curve walker head + roll state). */
typedef struct Dim2SnowballState {
    u8 pad00[0x10];
    int curveCursor; /* 0x10 */
    u8 pad14[0x54];
    f32 curveX;      /* 0x68 */
    f32 curveY;      /* 0x6c */
    f32 curveZ;      /* 0x70 */
    f32 dirX;        /* 0x74 */
    u8 pad78[4];
    f32 dirZ;        /* 0x7c */
    int curveMode;   /* 0x80 */
    u8 pad84[0xc];   /* 0x84..0x8f: vcall outparams (address-used) */
    int curveResult; /* 0x90 */
    int evalFn;      /* 0x94 */
    int coeffsFn;    /* 0x98 */
    int *targetObj;  /* 0x9c */
    int targetId;    /* 0xa0 */
    f32 floorY;      /* 0xa4 */
    int *curveData;  /* 0xa8 (also address-used as a vcall outparam) */
    u8 flagsAC;      /* 0xac */
    u8 padAD[3];
} Dim2SnowballState;
STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */
typedef struct Dim2PathGeneratorState {
    f32 originX;     /* 0x000 */
    f32 originY;     /* 0x004 */
    f32 originZ;     /* 0x008 */
    f32 curveA[200]; /* 0x00c */
    f32 curveB[200]; /* 0x32c */
    f32 curveC[200]; /* 0x64c */
    f32 curveD[12];  /* 0x96c */
    u8 pad99C[2];
    s16 spawnTimer;  /* 0x99e */
    s16 spawnPeriod; /* 0x9a0 */
    s16 spawnTypes[2]; /* 0x9a2: object ids, alternated via the toggle bit */
    u8 curveValid;   /* 0x9a6 */
    u8 flags;        /* 0x9a7: 1 = toggle, 2 = curve built, 4 = enabled */
} Dim2PathGeneratorState;
STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int *DIM2snowball_GetActiveModel(void *obj) {
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    return (int *)objAnim->banks[objAnim->bankIndex];
}

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined8 FUN_80006824();
extern undefined4 FUN_800068c4();
extern int FUN_80006a10();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern undefined8 FUN_80017640();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017730();
extern undefined4 FUN_8001774c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_800178e4();
extern undefined4 FUN_800178e8();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80053b3c();
extern int FUN_800620e8();
extern int FUN_800632f4();
extern int FUN_800e8b98();
extern undefined4 FUN_800ea9b8();
extern undefined4 SH_LevelControl_runBloopEvent();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb80;
extern undefined4 DAT_803dcb88;
extern EffectInterface **gPartfxInterface;
extern MapEventInterface **gMapEventInterface;
extern f64 DOUBLE_803e56e8;
extern f64 DOUBLE_803e5708;
extern f64 DOUBLE_803e5730;
extern f64 DOUBLE_803e5760;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803E56BC;
extern f32 lbl_803E56C0;
extern f32 lbl_803E56D8;
extern f32 lbl_803E56DC;
extern f32 lbl_803E56E0;
extern f32 lbl_803E56E4;
extern f32 lbl_803E56F4;
extern f32 lbl_803E56F8;
extern f32 lbl_803E56FC;
extern f32 lbl_803E5710;
extern f32 lbl_803E5714;
extern f32 lbl_803E5718;
extern f32 lbl_803E571C;
extern f32 lbl_803E5720;
extern f32 lbl_803E5724;
extern f32 lbl_803E5728;
extern f32 lbl_803E573C;
extern f32 lbl_803E5740;
extern f32 lbl_803E5744;
extern f32 lbl_803E5748;
extern f32 lbl_803E574C;
extern f32 lbl_803E5754;
extern f32 lbl_803E5758;
extern f32 lbl_803E5768;

/*
 * --INFO--
 *
 * Function: dim_levelcontrol_update
 * EN v1.0 Address: 0x801B6464
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x801B6A18
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct DimLevelControlState {
    f32 timer;
    int latch;
    u8 saveState;
    u8 unk9;
    s16 musicTrack;
    u8 unkC;
    u8 unkD;
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
} DimLevelControlState;

extern int Sfx_PlayFromObject(int obj, int id);
extern void getEnvfxActImmediately(int a, int b, int id, int d);
extern void getEnvfxAct(int a, int b, int id, int d);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void Music_Trigger(int id, int value);
extern void SCGameBitLatch_Update(int *state, int mask, int a, int b, int bit, int value);
extern int *gSHthorntailAnimationInterface;
extern f32 lbl_803E4A24;
extern f32 timeDelta;

void dim_levelcontrol_update(int obj)
{
    u8 a;
    u8 b;
    u8 c;
    u8 d;
    DimLevelControlState *st;
    u32 t;
    u32 t2;

    a = GameBit_Get(0xd0b);
    b = GameBit_Get(0xd0c);
    c = GameBit_Get(0xd0d);
    d = GameBit_Get(0xd0e);
    st = ((GameObject *)obj)->extra;
    if ((a && !st->b7) || (b && !st->b6) || (c && !st->b5) || (d && !st->b4)) {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    st->b7 = a;
    st->b6 = b;
    st->b5 = c;
    st->b4 = d;
    if (!st->b3 && (u32)GameBit_Get(0xa21) != 0) {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
        st->b3 = 1;
    }
    if (((GameObject *)obj)->unkF4 != 0) {
        if ((u32)GameBit_Get(0xa82) == 0 ||
            ((u32)GameBit_Get(0x17) != 0 && (u32)GameBit_Get(0xead) == 0)) {
            if (((GameObject *)obj)->unkF4 == 2) {
                getEnvfxActImmediately(0, 0, 0x160, 0);
                getEnvfxActImmediately(0, 0, 0x15a, 0);
                getEnvfxActImmediately(0, 0, 0x15c, 0);
                getEnvfxActImmediately(0, 0, 0x15f, 0);
            } else {
                getEnvfxAct(0, 0, 0x160, 0);
                getEnvfxAct(0, 0, 0x15a, 0);
                getEnvfxAct(0, 0, 0x15c, 0);
                getEnvfxAct(0, 0, 0x15f, 0);
            }
        }
        ((GameObject *)obj)->unkF4 = 0;
    }
    if (st->unkD != 0) {
        if ((u32)GameBit_Get(0x651) == 0) {
            (*gMapEventInterface)->setAnimEvent(0x13, 0xd, 0);
            st->unkD = 0;
        }
    } else {
        if ((u32)GameBit_Get(0x651) != 0) {
            (*gMapEventInterface)->setAnimEvent(0x13, 0xd, 1);
            st->unkD = 1;
        }
    }
    if (st->timer > lbl_803E4A24) {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(0x430);
        st->timer = st->timer - timeDelta;
        if (st->timer < *(f32 *)&lbl_803E4A24) {
            st->timer = lbl_803E4A24;
        }
    }
    if (st->unkC == 0) {
        t = GameBit_Get(0x3e2);
        t2 = GameBit_Get(0x3e3);
        st->unkC = (u8)(t2 & t);
        if (st->unkC != 0) {
            (*gGameUIInterface)->showNpcDialogue(0x4ba, 0x14, 0x8c, 1);
        }
    }
    t = GameBit_Get(0x3e2);
    t = !GameBit_Get(0x3e3) & t;
    t2 = t & 0xff;
    if (t2 != st->saveState) {
        GameBit_Set(0x3e8, t2);
        st->saveState = t2;
    }
    if (!(u8)GameBit_Get(0x8a5) && (u32)GameBit_Get(0x89d) != 0) {
        GameBit_Set(0x8a4, 1);
    }
    if ((*(int (**)(int))(*(int *)gSHthorntailAnimationInterface + 0x24))(0) == 0) {
        if (st->musicTrack != 0xe2) {
            st->musicTrack = 0xe2;
            if (st->latch & 4) {
                Music_Trigger(0xc5, 0);
                Music_Trigger(0xe2, 1);
            }
        }
    } else {
        if (st->musicTrack != 0xc5) {
            st->musicTrack = 0xc5;
            if (st->latch & 4) {
                Music_Trigger(0xe2, 0);
                Music_Trigger(0xc5, 1);
            }
        }
    }
    SCGameBitLatch_Update(&st->latch, 1, 0x1a7, 0x64b, 0xc1e, 0xa1);
    SCGameBitLatch_Update(&st->latch, 2, 0x1a8, 0xc0, 0xc1f, 0xcf);
    SCGameBitLatch_Update(&st->latch, 4, 0x1ba, 0x1b9, 0xc20, st->musicTrack);
    SCGameBitLatch_Update(&st->latch, 8, -1, -1, 0xd8f, 0xdc);
    SCGameBitLatch_Update(&st->latch, 0x10, 0x1a7, 0x64b, 0xc1e, 0xed);
    SCGameBitLatch_Update(&st->latch, 0x20, 0x1a8, 0xc0, 0xc1f, 0x36);
    SCGameBitLatch_Update(&st->latch, 0x40, 0x1ba, 0x1b9, 0xc20, 0x35);
    SCGameBitLatch_Update(&st->latch, 0x100, -1, -1, 0x3e2, 0x2b);
}

/*
 * --INFO--
 *
 * Function: FUN_801b6d24
 * EN v1.0 Address: 0x801B6D24
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801B6F60
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b6f88
 * EN v1.0 Address: 0x801B6F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801B71F4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b6fa8
 * EN v1.0 Address: 0x801B6FA8
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801B721C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b7314
 * EN v1.0 Address: 0x801B7314
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B7708
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7314(int param_1,undefined4 param_2,float *param_3,float *param_4)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = ((GameObject *)param_1)->extra;
  if (pfVar3[4] == 0.0) {
    FUN_800067c0((int *)0xdf,1);
  }
  pfVar3[4] = 2.8026e-44;
  iVar2 = *(int *)(*(int *)&((GameObject *)param_1)->anim.placementData + 0x14);
  if (iVar2 == 0x49b23) {
    uVar1 = GameBit_Get(0xc5c);
    if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5b), uVar1 == 0)) {
      *param_3 = *pfVar3;
      *param_4 = pfVar3[1];
    }
    uVar1 = GameBit_Get(0xc5b);
    if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5c), uVar1 == 0)) {
      *param_3 = -*pfVar3;
      *param_4 = -pfVar3[1];
    }
    uVar1 = GameBit_Get(0xc5b);
    if (uVar1 != 0) {
      GameBit_Set(0xc5c,0);
    }
    uVar1 = GameBit_Get(0xc5b);
    if (uVar1 == 0) {
      GameBit_Set(0xc5c,1);
    }
  }
  else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9)) {
    *param_3 = *pfVar3;
    *param_4 = pfVar3[1];
  }
  else {
    *param_3 = *pfVar3;
    *param_4 = pfVar3[1];
  }
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801b7fcc
 * EN v1.0 Address: 0x801B7FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B8344
 * EN v1.1 Size: 1344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b7fd0
 * EN v1.0 Address: 0x801B7FD0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B8884
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on



/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_1CF_free(void) {}
void dll_1CF_hitDetect(void) {}
void dll_1CF_update(void) {}
void dll_1CF_release(void) {}
void dll_1CF_initialise(void) {}
void dim_tricky_free(void) {}
void dim_tricky_hitDetect(void) {}
void dim2conveyor_hitDetect(void) {}
void dim2conveyor_release(void) {}
void dim2conveyor_initialise(void) {}
void dll_1D6_hitDetect(void) {}
void dll_1D6_release(void) {}
void dll_1D6_initialise(void) {}
void dim2snowball_free(void) {}
void dim2snowball_hitDetect(void) {}
void dim2snowball_release(void) {}
void dim2snowball_initialise(void) {}
void dim2pathgenerator_free(void) {}
void dim2pathgenerator_render(void) {}
void dim2pathgenerator_hitDetect(void) {}
void dim2pathgenerator_release(void) {}
void dim2pathgenerator_initialise(void) {}
void dll_1DA_free(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_1CF_getExtraSize(void) { return 0x0; }
int dll_1CF_getObjectTypeId(void) { return 0x0; }
int dim_tricky_getExtraSize(void) { return 0x1; }
int dim_tricky_getObjectTypeId(void) { return 0x0; }
int dimtruthhornice_getExtraSize(void) { return 0x8; }
int dim2conveyor_getExtraSize(void) { return 0x14; }
int dim2conveyor_getObjectTypeId(void) { return 0x0; }
int dll_1D6_getExtraSize(void) { return 0x20; }
int dll_1D6_getObjectTypeId(void) { return 0x0; }
int dim2snowball_getExtraSize(void) { return 0xb0; }
int dim2snowball_getObjectTypeId(void) { return 0x0; }
int dim2pathgenerator_getExtraSize(void) { return 0x9a8; }
int dim2pathgenerator_getObjectTypeId(void) { return 0x0; }
int dll_1DA_getExtraSize(void) { return 0x8; }
int dll_1DA_getObjectTypeId(void) { return 0x0; }

/* 16b chained patterns. */
void dim_tricky_init(int *obj) { u8 v = 0x0; *((u8*)((int**)obj)[0xb8/4] + 0x0) = v; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4A30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4A58;
extern f32 lbl_803E4A78;
extern f32 lbl_803E4AA0;
extern f32 lbl_803E4AD8;
void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4A30); }
void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4A58); }
void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4A78); }
void dim2snowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4AA0); }
void dll_1DA_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4AD8); }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E4A38;
void dim_tricky_render(void) { objRenderFn_8003b8f4(lbl_803E4A38); }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void dim2conveyor_free(int x) { ObjGroup_RemoveObject(x, 0x16); }

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */
extern void Music_Trigger(int trackId, int restart);
void dim2conveyor_setScale(int *obj, int unused, f32 *outX, f32 *outY) {
    Dim2ConveyorState *state = ((GameObject *)obj)->extra;
    int id;
    if (state->musicHold == 0) {
        Music_Trigger(0xdf, 1);
    }
    state->musicHold = 20;
    id = *(int *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x14);
    switch (id) {
    case 7849:
        *outX = state->scrollX;
        *outY = state->scrollY;
        break;
    case 0x49B23:
        if (GameBit_Get(3164) != 0 && GameBit_Get(3163) == 0) {
            *outX = state->scrollX;
            *outY = state->scrollY;
        }
        if (GameBit_Get(3163) != 0 && GameBit_Get(3164) == 0) {
            *outX = -state->scrollX;
            *outY = -state->scrollY;
        }
        if (GameBit_Get(3163) != 0) {
            GameBit_Set(3164, 0);
        }
        if (GameBit_Get(3163) == 0) {
            GameBit_Set(3164, 1);
        }
        break;
    default:
        *outX = state->scrollX;
        *outY = state->scrollY;
        break;
    }
}

extern int ObjHits_GetPriorityHit(int obj, void **outHitObj, int *outSphereIdx, uint *outHitVolume);
extern float Vec_distance(float *a, float *b);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803E4ADC;

/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */
void dll_1DA_hitDetect(int obj) {
    void *hi;
    void *player;
    f32 k;
    int hit = ObjHits_GetPriorityHit(obj, &hi, NULL, NULL);
    if (hit == 0xE) {
        player = Obj_GetPlayerObject();
        Vec_distance((float*)&((GameObject *)obj)->anim.worldPosX, (float*)((int)player + 0x18));
        ((GameObject *)obj)->anim.velocityX = *(f32*)((int)hi + 0x24) * (k = lbl_803E4ADC);
        ((GameObject *)obj)->anim.velocityZ = *(f32*)((int)hi + 0x2c) * k;
        Sfx_PlayFromObject(obj, SFXchar_puts_out_fire);
    }
}

extern int ObjList_FindObjectById(int id);
extern void mm_free(void* p);
extern u8 lbl_803DBF20;
extern int* getTrickyObject(void);

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */
int fn_801B6D40(int* obj, int v)
{
    u8* state = ((GameObject *)obj)->extra;
    *(s8 *)(state + 2) = (s8)(state[2] - v);
    return *(s8 *)(state + 2) <= 0;
}

u8 dim2pathgenerator_getCurveVals(int* obj, int** p1, int** p2, int** p3, int** p4)
{
    int* state = ((GameObject *)obj)->extra;
    *p1 = (int*)((char*)state + 12);
    *p2 = (int*)((char*)state + 812);
    *p3 = (int*)((char*)state + 1612);
    if (p4 != NULL) {
        *p4 = (int*)((char*)state + 2412);
    }
    return ((Dim2PathGeneratorState*)state)->curveValid;
}

void dll_1D6_free(int* obj)
{
    Dll1D6State* state = ((GameObject *)obj)->extra;
    if ((state->flags1D & 4) != 0) {
        state->flags1D = (u8)(state->flags1D & ~4);
    }
    mm_free(state->bufA);
    mm_free(state->bufB);
    (&lbl_803DBF20)[state->slot] = 0;
}

void dim2pathgenerator_init(int* obj, int* def)
{
    Dim2PathGeneratorState* state;
    *(s16*)obj = (s16)((u32)*(u8*)((char*)def + 28) << 8);
    state = ((GameObject *)obj)->extra;
    state->spawnPeriod = ((Dim2pathgeneratorObjectDef *)def)->unk18;
    state->spawnTimer = (s16)*(u8*)((char*)def + 29);
    state->spawnTypes[0] = (s16)((Dim2pathgeneratorObjectDef *)def)->unk1E;
    {
        s16 v = ((Dim2pathgeneratorObjectDef *)def)->unk20;
        if (v == -1) {
            state->spawnTypes[1] = (s16)((Dim2pathgeneratorObjectDef *)def)->unk1E;
        } else {
            state->spawnTypes[1] = v;
        }
    }
    state->flags = (u8)(state->flags | 4);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
}

void dimtruthhornice_init(int* obj, int* def)
{
    TruthHornIceState* state = ((GameObject *)obj)->extra;
    state->hitsLeft = (s8)((DimtruthhorniceObjectDef *)def)->unk1A;
    state->gameBit = ((DimtruthhorniceObjectDef *)def)->unk1E;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);
    {
        s16 slot = state->gameBit;
        if (slot != -1 && (u32)GameBit_Get(slot) != 0u) {
            ObjHits_DisableObject(obj);
            state->phase = 2;
            ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

void dim2snowball_init(int* obj, int* def)
{
    Dim2SnowballState* state = ((GameObject *)obj)->extra;
    state->targetId = ((Dim2snowballObjectDef *)def)->unk14;
    state->flagsAC = (u8)(state->flagsAC | 4);
    ((Dim2snowballObjectDef *)def)->unk14 = -1;
    *(s16*)obj = (s16)((s32)((Dim2snowballObjectDef *)def)->unk18 << 8);
    *(s8*)((char*)obj + 54) = 0;
    {
        ObjModelState* p = ((GameObject *)obj)->anim.modelState;
        if (p != NULL) {
            p->flags |= 0xA10;
        }
    }
    state->targetObj = (int*)ObjList_FindObjectById(state->targetId);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
}

void dll_1CF_init(int* obj, int* def)
{
    if ((u32)GameBit_Get(((Dll1CFObjectDef *)def)->unk1E) != 0u) {
        ((GameObject *)obj)->anim.rotY = (s16)(((s32)((Dll1CFObjectDef *)def)->unk1A << 13) / 45);
    }
    *(s16*)obj = (s16)((s32)((Dll1CFObjectDef *)def)->unk18 << 8);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0xe000);
}

extern f32 lbl_803E4A28;
extern int getSaveGameLoadStatus(void);
extern void gameBitFn_800ea2e0(u8 n);
extern void unlockLevel(int a, int b, int c);
void dim_levelcontrol_init(int obj)
{
    DimLevelControlState *st;
    u8 i;

    randomGetRange(0, 11);
    st = ((GameObject *)obj)->extra;
    st->saveState = 0;
    st->timer = lbl_803E4A28;
    if (getSaveGameLoadStatus() != 0) {
        ((GameObject *)obj)->unkF4 = 2;
    } else {
        ((GameObject *)obj)->unkF4 = 1;
    }
    for (i = 1; i <= 38; i++) {
        gameBitFn_800ea2e0(i);
    }
    st->unkC = (u8)GameBit_Get(0xdc);
    GameBit_Set(0xf0a, 0);
    if ((u32)GameBit_Get(0x89d) != 0 && (u32)GameBit_Get(0x8a5) == 0) {
        GameBit_Set(0x89d, 0);
    }
    st->b7 = (u8)GameBit_Get(0xd0b);
    st->b6 = (u8)GameBit_Get(0xd0c);
    st->b5 = (u8)GameBit_Get(0xd0d);
    st->b4 = (u8)GameBit_Get(0xd0e);
    st->b3 = (u8)GameBit_Get(0xa21);
    (*gMapEventInterface)->setMode(((GameObject *)obj)->anim.mapEventSlot, 1);
    ((GameObject *)obj)->objectFlags |= 0x6000;
    unlockLevel(0, 0, 1);
}

void dim_tricky_update(int* obj)
{
    int* state = ((GameObject *)obj)->extra;
    int* trickyObj = getTrickyObject();
    if (trickyObj == NULL) return;
    switch (*(u8*)state) {
        case 0:
            if (GameBit_Get(0xa1b) != 0) {
                GameBit_Set(0x4e4, 0);
                GameBit_Set(0x4e5, 0);
                *(s8*)state = 1;
            }
            break;
        case 1:
            *(s8*)state = 2;
            break;
        case 2:
            ((void(*)(int*, int*))((void**)*(*(int***)((char*)trickyObj + 104)))[14])(trickyObj, obj);
            *(s8*)state = 3;
            break;
        case 3:
            break;
    }
}

extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 lbl_803E4A5C;
extern f32 lbl_803E4A60;
extern f32 lbl_803E4A64;
extern f32 lbl_803E4A68;
extern f32 lbl_803E4A6C;

void dim2conveyor_init(int *obj, u8 *params)
{
    f32 scale = (f32)*(s16 *)((char *)params + 0x1a) / lbl_803E4A64;
    Dim2ConveyorState *extra;
    *(s16 *)obj = (s16)(*(s8 *)((char *)params + 0x18) << 8);
    extra = ((GameObject *)obj)->extra;
    extra->scrollX = scale * mathSinf(lbl_803E4A68 * (f32)*(s16 *)obj / lbl_803E4A6C);
    extra->scrollY = scale * mathCosf(lbl_803E4A68 * (f32)*(s16 *)obj / lbl_803E4A6C);
    extra->swapTimer = lbl_803E4A60;
    extra->musicHold = 0;
    ObjGroup_AddObject(obj, 22);
    ((GameObject *)obj)->objectFlags |= 0x2000;
    if (*(u32 *)((char *)params + 0x14) == 0x49b23) {
        GameBit_Set(3164, 1);
    }
}

void dim2conveyor_update(int *obj)
{
    Dim2ConveyorState *extra = ((GameObject *)obj)->extra;
    Sfx_PlayFromObject((int)obj, SFXfoot_metal_scuff);
    if (extra->musicHold != 0) {
        extra->musicHold = extra->musicHold - 1;
        if (extra->musicHold == 0) {
            Music_Trigger(223, 0);
        }
    }
    switch (*(int *)((char *)*(int **)&((GameObject *)obj)->anim.placementData + 0x14)) {
    case 0x49b23:
        if (GameBit_Get(3169) != 0) {
            extra->swapTimer = extra->swapTimer + timeDelta;
            if (extra->swapTimer > lbl_803E4A5C) {
                if (GameBit_Get(3163) != 0) {
                    GameBit_Set(3164, 1);
                    GameBit_Set(3163, 0);
                } else if (GameBit_Get(3164) != 0) {
                    GameBit_Set(3164, 0);
                    GameBit_Set(3163, 1);
                }
                extra->swapTimer = lbl_803E4A60;
            }
        }
        if (GameBit_Get(3163) != 0) {
            GameBit_Set(3164, 0);
        }
        if (GameBit_Get(3163) == 0) {
            GameBit_Set(3164, 1);
        }
        break;
    case 7849:
        break;
    }
}

extern void *mmAlloc(int size, int a, int b);
extern void ObjModel_SetBlendChannelTargets(int *model, int a, int b, int c, f32 w, int d);
extern void ObjModel_SetBlendChannelWeight(int *model, int a, f32 w);
extern s16 lbl_803DBF18;
extern f32 lbl_803E4A88;

void dll_1D6_init(int *obj, u8 *params)
{
    Dll1D6State *extra;
    int *model;
    int i;

    *(s16 *)obj = (s16)(*(s8 *)((char *)params + 0x18) << 8);
    extra = ((GameObject *)obj)->extra;
    model = DIM2snowball_GetActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4A88, 0);
    ObjModel_SetBlendChannelWeight(model, 0, lbl_803E4A78);
    extra->upTimer = *(s16 *)((char *)params + 0x1a);
    if (extra->upTimer < 15) {
        extra->upTimer = 15;
    }
    extra->downTimer = *(s16 *)((char *)params + 0x1c);
    if (extra->downTimer < 15) {
        extra->downTimer = 15;
    }
    {
        f32 k = lbl_803E4A88;
        extra->hitRangeSqA = k * ((GameObject *)obj)->anim.rootMotionScale;
        extra->hitRangeSqA = extra->hitRangeSqA * extra->hitRangeSqA;
        extra->hitRangeSqB = k * ((GameObject *)obj)->anim.rootMotionScale;
        extra->hitRangeSqB = extra->hitRangeSqB * extra->hitRangeSqB;
    }
    extra->flags1D = GameBit_Get(496) ? 2 : 0;
    for (i = 0; i < 4; i++) {
        if ((&lbl_803DBF20)[i] == 0) {
            (&lbl_803DBF20)[i] = 1;
            extra->slot = i;
            i = 4;
        }
    }
    extra->bufA = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufA, 12, (&lbl_803DBF18)[extra->slot] * 40, 40);
    extra->bufB = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufB, 12,
                ((&lbl_803DBF18)[extra->slot] + 1) * 40, 40);
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

extern f32 lbl_803E4A40;
extern f32 lbl_803E4A44;
extern f32 lbl_803E4A48;
extern f32 lbl_803E4A4C;

void dimtruthhornice_update(int *obj)
{
    TruthHornIceState *extra = ((GameObject *)obj)->extra;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    switch (extra->phase) {
    case 0:
        if (extra->hitsLeft <= 0) {
            if (extra->gameBit != -1) {
                GameBit_Set(extra->gameBit, 1);
                ObjHits_DisableObject(obj);
                extra->phase = 1;
                extra->timer = lbl_803E4A40;
            }
        } else {
            int *tricky = (int *)getTrickyObject();
            if (tricky != NULL) {
                if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
                    (*(void (**)(int *, int *, int, int))(**(int **)((char *)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            }
        }
        break;
    case 1: {
        f32 desc2[6];
        extra->timer = extra->timer + timeDelta;
        if (extra->timer > lbl_803E4A44) {
            int i;
            extra->phase = 2;
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            Sfx_PlayFromObject((int)obj, 1147);
            for (i = 30; i != 0; i--) {
                f32 desc[6];
                desc[3] = 0.1f * (f32)(int)randomGetRange(-100, 100);
                desc[4] = 0.1f * (f32)(int)randomGetRange(0, 350);
                desc[5] = 0.1f * (f32)(int)randomGetRange(-100, 100);
                desc[2] = 1.0f;
                (*gPartfxInterface)->spawnObject(obj, 2043, desc, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 2044, desc, 2, -1, NULL);
            }
        }
        desc2[3] = 0.1f * (f32)(int)randomGetRange(-100, 100);
        desc2[4] = 0.1f * (f32)(int)randomGetRange(0, 350);
        desc2[5] = 0.1f * (f32)(int)randomGetRange(-100, 100);
        desc2[2] = 1.0f;
        (*gPartfxInterface)->spawnObject(obj, 2044, desc2, 2, -1, NULL);
        break;
    }
    case 2:
        ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    }
}

extern int **ObjGroup_GetObjects(int group, int *countOut);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

void dim2pathgenerator_update(int *obj)
{
    int *def;
    int *extra = ((GameObject *)obj)->extra;
    int toggle;
    int **objs;
    int i;
    int count;

    def = *(int **)&((GameObject *)obj)->anim.placementData;
    if (GameBit_Get(((Dim2pathgeneratorPlacement *)def)->unk22) == 0) {
        return;
    }
    if ((((Dim2PathGeneratorState *)extra)->flags & 4) != 0) {
        if ((((Dim2PathGeneratorState *)extra)->flags & 2) == 0) {
            int n = 21;
            int found = (*gRomCurveInterface)->find(&n, 1, 10, ((GameObject *)obj)->anim.localPosX,
                                                    ((GameObject *)obj)->anim.localPosY,
                                                    ((GameObject *)obj)->anim.localPosZ);
            if (found != -1) {
                int *cv = (int *)(*gRomCurveInterface)->getById(found);
                ((void (*)(int))(*gRomCurveInterface)->slot74)((int)cv);
                ((Dim2PathGeneratorState *)extra)->curveValid =
                    ((int (*)(int *, void *, void *, void *, void *))(*gRomCurveInterface)->slot78)(
                        cv, (char *)extra + 0xc, (char *)extra + 0x32c, (char *)extra + 0x64c,
                        (char *)extra + 0x96c);
                ((Dim2PathGeneratorState *)extra)->flags |= 2;
                ((Dim2PathGeneratorState *)extra)->originX = *(f32 *)((char *)cv + 8);
                ((Dim2PathGeneratorState *)extra)->originY = *(f32 *)((char *)cv + 0xc);
                ((Dim2PathGeneratorState *)extra)->originZ = *(f32 *)((char *)cv + 0x10);
            }
        }
    } else {
        ((Dim2PathGeneratorState *)extra)->originX = ((GameObject *)obj)->anim.localPosX;
        ((Dim2PathGeneratorState *)extra)->originY = ((GameObject *)obj)->anim.localPosY;
        ((Dim2PathGeneratorState *)extra)->originZ = ((GameObject *)obj)->anim.localPosZ;
    }
    {
        s16 t = ((Dim2PathGeneratorState *)extra)->spawnTimer - framesThisStep;
        ((Dim2PathGeneratorState *)extra)->spawnTimer = t;
        if (t > 0) {
            return;
        }
    }
    toggle = ((Dim2PathGeneratorState *)extra)->flags & 1;
    ((Dim2PathGeneratorState *)extra)->spawnTimer = ((Dim2PathGeneratorState *)extra)->spawnPeriod;
    ((Dim2PathGeneratorState *)extra)->flags &= ~1;
    objs = ObjGroup_GetObjects(47, &count);
    for (i = 0; i < count; i++) {
        if (((Dim2PathGeneratorState *)extra)->spawnTypes[toggle] == *(s16 *)((char *)objs[i] + 0x46)) {
            int *p = *(int **)((char *)objs[i] + 0x4c);
            int c2;
            int j;
            int **o2;
            *(f32 *)((char *)p + 8) = ((Dim2PathGeneratorState *)extra)->originX;
            *(f32 *)((char *)p + 0xc) = ((Dim2PathGeneratorState *)extra)->originY;
            *(f32 *)((char *)p + 0x10) = ((Dim2PathGeneratorState *)extra)->originZ;
            *(int *)((char *)p + 0x14) = ((Dim2pathgeneratorPlacement *)def)->unk14;
            (*(void (**)(int *, int))(**(int **)((char *)objs[i] + 0x68) + 4))(objs[i], 1);
            ObjGroup_RemoveObject(objs[i], 47);
            o2 = ObjGroup_GetObjects(47, &c2);
            for (j = 0; j < c2; j++) {
            }
            ((Dim2PathGeneratorState *)extra)->flags |= (toggle ^ 1) & 1;
            return;
        }
    }
    if (Obj_IsLoadingLocked()) {
        int *np = (int *)Obj_AllocObjectSetup(36, ((Dim2PathGeneratorState *)extra)->spawnTypes[toggle]);
        *(f32 *)((char *)np + 8) = ((Dim2PathGeneratorState *)extra)->originX;
        *(f32 *)((char *)np + 0xc) = ((Dim2PathGeneratorState *)extra)->originY;
        *(f32 *)((char *)np + 0x10) = ((Dim2PathGeneratorState *)extra)->originZ;
        *(u8 *)((char *)np + 4) = ((Dim2pathgeneratorPlacement *)def)->unk4;
        *(u8 *)((char *)np + 6) = ((Dim2pathgeneratorPlacement *)def)->unk6;
        *(u8 *)((char *)np + 5) = ((Dim2pathgeneratorPlacement *)def)->unk5;
        *(u8 *)((char *)np + 7) = ((Dim2pathgeneratorPlacement *)def)->unk7;
        *(u8 *)((char *)np + 7) = 255;
        *(u8 *)((char *)np + 3) = ((Dim2pathgeneratorPlacement *)def)->unk3;
        *(s8 *)((char *)np + 0x18) = (s8)*(u8 *)((char *)def + 0x1c);
        *(s16 *)((char *)np + 0x1a) = *(u8 *)((char *)def + 0x1a);
        *(s16 *)((char *)np + 0x1c) = *(u8 *)((char *)def + 0x1b);
        *(int *)((char *)np + 0x14) = ((Dim2pathgeneratorPlacement *)def)->unk14;
        Obj_SetupObject((int)np, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, 0);
        ((Dim2PathGeneratorState *)extra)->flags |= (toggle ^ 1) & 1;
    }
}

extern int *objFindTexture(int *obj, int a, int b);
extern void mtxRotateByVec3s(f32 *mtx, s16 *ang);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern f32 lbl_803E4A7C;
extern f32 lbl_803E4A80;
extern f32 lbl_803E4A84;
extern f32 lbl_803E4A8C;
extern f32 lbl_803E4A90;

void dll_1D6_update(int *obj)
{
    Dll1D6State *extra;
    int *def;
    int *model;
    int *tex;
    int *player;
    f32 mtx[20];
    s16 ang[6];
    f32 lx, ly, lz;

    def = *(int **)&((GameObject *)obj)->anim.placementData;
    extra = ((GameObject *)obj)->extra;

    if ((extra->flags1D & 1) != 0) {
        if ((extra->flags1D & 4) == 0) {
            extra->flags1D |= 4;
            extra->bobPhase = (f32)(int)randomGetRange(20, 40);
            extra->bobRate = (f32)(int)randomGetRange(6, 10) / lbl_803E4A7C;
        }
        extra->downTimer -= framesThisStep;
        extra->dizzyTimer = extra->dizzyTimer - framesThisStep;
        if (extra->dizzyTimer <= 0) {
            Sfx_PlayFromObject((int)obj, SFXmv_mushdizzylp12);
        }
        if (extra->downTimer <= 0) {
            model = DIM2snowball_GetActiveModel(obj);
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4A80, 16);
            extra->upTimer = *(s16 *)((char *)def + 0x1a);
            if (extra->upTimer < 15) {
                extra->upTimer = 15;
            }
            extra->flags1D &= ~1;
            Sfx_PlayFromObject((int)obj, SFXfoot_metal_land);
        }
    } else {
        model = DIM2snowball_GetActiveModel(obj);
        if (*(int *)((char *)model + 0x28) != 0 && (extra->flags1D & 4) != 0) {
            if (*(f32 *)*(int **)((char *)model + 0x28) >= lbl_803E4A78) {
                extra->flags1D &= ~4;
            }
        }
        extra->upTimer -= framesThisStep;
        if (extra->upTimer <= 0) {
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4A84, 16);
            extra->downTimer = *(s16 *)((char *)def + 0x1c);
            if (extra->downTimer < 15) {
                extra->downTimer = 15;
            }
            extra->flags1D |= 1;
            Sfx_PlayFromObject((int)obj, SFXfoot_ice_scuff);
            extra->dizzyTimer = 20;
        }
    }
    tex = objFindTexture(obj, 0, 0);
    {
        s16 v = -*(s16 *)((char *)tex + 0xa) + 256;
        if (v > 2048) {
            v = v - 2048;
        }
        *(s16 *)((char *)tex + 0xa) = -v;
    }
    tex = objFindTexture(obj, 1, 0);
    {
        s16 v = -*(s16 *)((char *)tex + 0xa) + 160;
        if (v > 2048) {
            v = v - 2048;
        }
        *(s16 *)((char *)tex + 0xa) = -v;
    }
    player = (int *)Obj_GetPlayerObject();
    mtx[0] = -((GameObject *)obj)->anim.localPosX;
    mtx[1] = -((GameObject *)obj)->anim.localPosY;
    mtx[2] = -((GameObject *)obj)->anim.localPosZ;
    ang[0] = -*(s16 *)obj;
    ang[1] = 0;
    ang[2] = 0;
    mtxRotateByVec3s(&mtx[3], ang);
    Matrix_TransformPoint(&mtx[3], ((GameObject *)player)->anim.localPosX, ((GameObject *)player)->anim.localPosY,
                          ((GameObject *)player)->anim.localPosZ, &lx, &ly, &lz);
    if ((extra->flags1D & 2) != 0) {
        ly = ((GameObject *)obj)->anim.localPosY - ((GameObject *)player)->anim.localPosY;
        if (ly < lbl_803E4A88) {
            ly = -ly;
        }
        if (ly < lbl_803E4A8C) {
            lz = lz * lz;
            if (lz <= extra->hitRangeSqA) {
                int *row;
                f32 lim;
                model = DIM2snowball_GetActiveModel(obj);
                row = *(int **)((char *)model + ((*(u16 *)((char *)model + 0x18) >> 1) & 1) * 4 + 4);
                lim = ((GameObject *)obj)->anim.rootMotionScale *
                      (f32)(int)*(s16 *)((char *)row + extra->hitRow * 16);
                if (lx <= lim) {
                    ObjHits_RecordObjectHit(player, obj, 11, 4, 0);
                }
            }
        }
    }
    if ((extra->flags1D & 4) != 0) {
        extra->bobPhase =
            extra->bobRate * timeDelta + extra->bobPhase;
        if (extra->bobPhase > lbl_803E4A90) {
            extra->bobRate = -(f32)(int)randomGetRange(6, 10) / lbl_803E4A7C;
            extra->bobPhase = lbl_803E4A90;
        } else if (extra->bobPhase < lbl_803E4A7C) {
            extra->bobRate = (f32)(int)randomGetRange(6, 10) / lbl_803E4A7C;
            extra->bobPhase = lbl_803E4A7C;
        }
    }
    if (GameBit_Get(496) != 0) {
        extra->flags1D |= 2;
    } else {
        extra->flags1D &= ~2;
    }
}

extern int Curve_AdvanceAlongPath(int *extra, f32 t);
extern void Curve_BuildHermiteCoeffs(void);
extern void Curve_EvalHermite(void);
extern void curvesMove(int *extra);
extern int **ObjList_GetObjects(int *startOut, int *countOut);
extern void objMove(int *obj, f32 dx, f32 dy, f32 dz);
extern int objBboxFn_800640cc(void *a, void *b, f32 c, int d, int e, int *f, int g, int h, int i, int j);
extern int getAngle(f32 a, f32 b);
extern int hitDetectFn_80065e50(int *obj, f32 x, f32 y, f32 z, int ***listOut, int p3, int p4);
extern void Sfx_KeepAliveLoopedObjectSound(int *obj, int sfx);
extern void Obj_FreeObject(int *obj);
extern f32 oneOverTimeDelta;
extern f32 lbl_803E4AA4;
extern f32 lbl_803E4AA8;
extern f32 lbl_803E4AAC;
extern f32 lbl_803E4AB0;
extern f32 lbl_803E4AB4;
extern f32 lbl_803E4AB8;
extern f32 lbl_803E4ABC;
extern f32 lbl_803E4AC0;
extern f64 lbl_803E4AC8;
extern f32 lbl_803E4AD0;

void dim2snowball_update(int *obj)
{
    int *extra = ((GameObject *)obj)->extra;
    int **p;
    int **results;
    int count;
    int start;
    f32 evt[6];
    f32 k;

    if ((((Dim2SnowballState *)extra)->flagsAC & 4) != 0) {
        int v = ((GameObject *)obj)->anim.alpha + framesThisStep * 2;
        if (v > 255) {
            v = 255;
            ((Dim2SnowballState *)extra)->flagsAC &= ~4;
        }
        ((GameObject *)obj)->anim.alpha = v;
    } else if ((((Dim2SnowballState *)extra)->flagsAC & 8) != 0) {
        int v = ((GameObject *)obj)->anim.alpha - framesThisStep * 2;
        if (v < 0) {
            v = 0;
            ((Dim2SnowballState *)extra)->flagsAC &= ~8;
        }
        ((GameObject *)obj)->anim.alpha = v;
    }

    if ((((Dim2SnowballState *)extra)->flagsAC & 1) == 0) {
        int *cobj = ((Dim2SnowballState *)extra)->targetObj;
        ((Dim2SnowballState *)extra)->curveResult =
            (*(int (**)(int *, void *, void *, void *, void *))(**(int **)((char *)cobj + 0x68) + 0x20))(
                cobj, (char *)extra + 0x84, (char *)extra + 0x88, (char *)extra + 0x8c, (char *)extra + 0xa8);
        ((Dim2SnowballState *)extra)->curveMode = 0;
        ((Dim2SnowballState *)extra)->evalFn = (int)Curve_EvalHermite;
        ((Dim2SnowballState *)extra)->coeffsFn = (int)Curve_BuildHermiteCoeffs;
        curvesMove(extra);
        ((Dim2SnowballState *)extra)->flagsAC |= 1;
    }

    if ((((Dim2SnowballState *)extra)->flagsAC & 2) != 0) {
        if (((GameObject *)obj)->anim.localPosY < ((Dim2SnowballState *)extra)->floorY) {
            ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4AA4);
            ((GameObject *)obj)->anim.velocityY = lbl_803E4AA8;
            ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
            if ((((Dim2SnowballState *)extra)->flagsAC & 0x10) == 0) {
                int **list;
                int *hit;
                ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4AAC);
                ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
                ((Dim2SnowballState *)extra)->flagsAC |= 0x18;
                list = ObjList_GetObjects(&start, &count);
                for (p = &list[start]; start < count; start++) {
                    if (*(s16 *)((char *)*p + 0x46) == 214) {
                        hit = list[start];
                        goto checkHit;
                    }
                    p++;
                }
                hit = NULL;
checkHit:
                if (hit != NULL) {
                    (*(void (**)(int *))(**(int **)((char *)hit + 0x68) + 0x20))(hit);
                }
                Sfx_PlayFromObject((int)obj, SFXfoot_run_jingle1);
            }
            evt[3] = ((GameObject *)obj)->anim.localPosX;
            evt[4] = ((GameObject *)obj)->anim.localPosY;
            evt[5] = ((GameObject *)obj)->anim.localPosZ;
            (*gPartfxInterface)->spawnObject(obj, 518, evt, 4, -1, NULL);
            if (((GameObject *)obj)->anim.alpha == 0) {
                Obj_FreeObject(obj);
                return;
            }
            objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta,
                    ((GameObject *)obj)->anim.velocityY * timeDelta,
                    ((GameObject *)obj)->anim.velocityZ * timeDelta);
        } else {
            int bbox;
            ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4AB0);
            ((GameObject *)obj)->anim.velocityY =
                ((GameObject *)obj)->anim.velocityY - lbl_803E4AB4 * timeDelta;
            ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
            objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta,
                    ((GameObject *)obj)->anim.velocityY * timeDelta,
                    ((GameObject *)obj)->anim.velocityZ * timeDelta);
            bbox = objBboxFn_800640cc((char *)obj + 0x80, (char *)obj + 0xc, lbl_803E4AB8, 0, 0,
                                      obj, 8, -1, 0, 0);
            if (bbox != 0) {
                ((GameObject *)obj)->anim.velocityX = -((GameObject *)obj)->anim.velocityX;
                ((GameObject *)obj)->anim.velocityZ = -((GameObject *)obj)->anim.velocityZ;
                ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4ABC);
                ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
            }
        }
    } else {
        int done = Curve_AdvanceAlongPath(extra, lbl_803E4AC0);
        ((GameObject *)obj)->anim.localPosX = ((Dim2SnowballState *)extra)->curveX;
        ((GameObject *)obj)->anim.localPosY = (f32)(lbl_803E4AC8 + ((Dim2SnowballState *)extra)->curveY);
        ((GameObject *)obj)->anim.localPosZ = ((Dim2SnowballState *)extra)->curveZ;
        *(s16 *)obj = getAngle(((Dim2SnowballState *)extra)->dirX, ((Dim2SnowballState *)extra)->dirZ);
        ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY + framesThisStep * 800;
        ((GameObject *)obj)->anim.velocityX =
            oneOverTimeDelta * (((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX);
        ((GameObject *)obj)->anim.velocityY = lbl_803E4AD0;
        ((GameObject *)obj)->anim.velocityZ =
            oneOverTimeDelta * (((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ);
        if (done != 0) {
            Obj_FreeObject(obj);
            return;
        }
        if (*(u8 *)((char *)*(int **)((char *)extra + 0xa8) + (((Dim2SnowballState *)extra)->curveCursor >> 2)) == 32) {
            if (GameBit_Get(648) != 0) {
                int n;
                ((Dim2SnowballState *)extra)->flagsAC |= 2;
                n = hitDetectFn_80065e50(obj, ((GameObject *)obj)->anim.localPosX,
                                         ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ,
                                         &results, 0, 0);
                ((Dim2SnowballState *)extra)->floorY = ((GameObject *)obj)->anim.localPosY;
                while (n > 0) {
                    int *r;
                    n--;
                    r = results[n];
                    if (*(f32 *)r < ((GameObject *)obj)->anim.localPosY) {
                        s8 t = *(s8 *)((char *)r + 0x14);
                        if (t == 26 || t == 8) {
                            ((Dim2SnowballState *)extra)->floorY = *(f32 *)r;
                            n = 0;
                        }
                    }
                }
                ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (k = lbl_803E4ABC);
                ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * k;
            }
        }
    }

    if (((GameObject *)obj)->anim.alpha == 255) {
        int *m = *(int **)&((GameObject *)obj)->anim.hitReactState;
        if (m != NULL) {
            ((ObjHitsPriorityState *)m)->flags |= 1;
            *(u8 *)&((ObjHitsPriorityState *)m)->hitVolumePriority = 4;
            *(u8 *)&((ObjHitsPriorityState *)m)->hitVolumeId = 2;
            *(int *)&((ObjHitsPriorityState *)m)->objectHitMask = 16;
            *(int *)&((ObjHitsPriorityState *)m)->skeletonHitMask = 16;
        }
    }
    Sfx_KeepAliveLoopedObjectSound(obj, 1171);
}
