#include "main/dll/DIM/dimcannon_state.h"
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "global.h"

typedef struct Lavaball1bePlacement {
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x20 - 0x19];
} Lavaball1bePlacement;


typedef struct Lavaball1bfPlacement {
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
    u8 pad20[0x24 - 0x20];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} Lavaball1bfPlacement;


/* imanimspacecraft_getExtraSize == 0x4. */
typedef struct ImAnimSpacecraftState {
    s16 blinkTimer;  /* 0x00 */
    u8 maskBits;     /* 0x02: per-event toggle bits (bit4..6 = group) */
    u8 flags;        /* 0x03: 2 = blink phase, 4/8 = SeqFn toggles */
} ImAnimSpacecraftState;
STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* imspacethruster_getExtraSize == 0xc. */
typedef struct ImSpaceThrusterState {
    u8 kind;         /* 0x00: thruster slot from def+0x19 */
    u8 phase;        /* 0x01 */
    s16 blendTimer;  /* 0x02 */
    void *bufA;      /* 0x04: mmAlloc'd getTabEntry rows */
    void *bufB;      /* 0x08 */
} ImSpaceThrusterState;
STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

/* link_levcontrol_getExtraSize == 0x10. */
typedef struct LinkLevControlState {
    s8 areaCell;     /* 0x00 */
    u8 pad01[3];
    int unk04;       /* 0x04: init -1 */
    int musicTrack;  /* 0x08 */
    int latch;       /* 0x0c: SCGameBitLatch block */
} LinkLevControlState;
STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

/* lavaball1be extra (getExtraSize 0x14 for the non-0x1fa variant). */
typedef struct Lavaball1beState {
    char *targetObj; /* 0x00: ObjList_FindObjectById(linkedId) */
    u8 *light;       /* 0x04 */
    f32 floorY;      /* 0x08: spawn height; falling below it re-arms */
    int linkedId;    /* 0x0c */
    u8 flags;        /* 0x10: 8 = ticked, 0x10 = dormant, 0x20 = whistle sfx */
    u8 explodeCooldown; /* 0x11 */
    u8 pad12[2];
} Lavaball1beState;
STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

/* lavaball1bf_getExtraSize == 0x1c (launcher). */
typedef struct Lavaball1bfState {
    u8 pad00[8];
    int *spawnedObj; /* 0x08: the 0x18d cannon object */
    f32 fireTimer;   /* 0x0c */
    f32 firePeriod;  /* 0x10 */
    s16 gateA;       /* 0x14 */
    s16 pending;     /* 0x16 */
    u8 gateB;        /* 0x18 */
    u8 pad19;
    u8 gbState;      /* 0x1a */
    u8 soloLatch;    /* 0x1b */
} Lavaball1bfState;
STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

static inline int *DIMcannon_GetActiveModel(void *obj) {
  ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
  return (int *)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80017540();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern int FUN_800175c4();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined8 FUN_80017640();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined8 FUN_800178e4();
extern undefined4 FUN_800178e8();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined8 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern void* ObjGroup_GetObjects();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern int FUN_8005b024();
extern undefined4 FUN_8005fe14();
extern undefined8 FUN_80080f14();
extern undefined8 FUN_80080f18();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008112c();
extern int FUN_800e8b98();
extern undefined4 FUN_80135c84();
extern undefined4 FUN_801adca0();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined8 FUN_80286830();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern undefined4 DAT_802c2a98;
extern undefined4 DAT_802c2a9c;
extern undefined4 DAT_802c2aa0;
extern undefined4 DAT_80324458;
extern undefined4 DAT_80324464;
extern undefined4 DAT_80324518;
extern undefined4 DAT_80324550;
extern undefined4 DAT_80324588;
extern undefined4 DAT_803245c0;
extern undefined4 DAT_80324630;
extern undefined4 DAT_80324668;
extern undefined4 DAT_803246a0;
extern undefined4 DAT_803246d8;
extern undefined4 DAT_803ad5a8;
extern undefined4 DAT_803ad5b4;
extern undefined4 DAT_803ad5b8;
extern undefined4 DAT_803ad5bc;
extern undefined4 DAT_803dc070;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* DAT_803dd6d8;
extern EffectInterface **gPartfxInterface;
extern MapEventInterface **gMapEventInterface;
extern undefined4 DAT_803de7c8;
extern f64 DOUBLE_803e53e8;
extern f64 DOUBLE_803e5438;
extern f64 DOUBLE_803e5480;
extern f64 DOUBLE_803e54b0;
extern f32 lbl_803DC074;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53E4;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;
extern f32 lbl_803E53F8;
extern f32 lbl_803E53FC;
extern f32 lbl_803E5408;
extern f32 lbl_803E540C;
extern f32 lbl_803E5410;
extern f32 lbl_803E5414;
extern f32 lbl_803E541C;
extern f32 lbl_803E5420;
extern f32 lbl_803E5424;
extern f32 lbl_803E5428;
extern f32 lbl_803E542C;
extern f32 lbl_803E5430;
extern f32 lbl_803E5440;
extern f32 lbl_803E5444;
extern f32 lbl_803E5448;
extern f32 lbl_803E544C;
extern f32 lbl_803E545C;
extern f32 lbl_803E5460;
extern f32 lbl_803E5468;
extern f32 lbl_803E546C;
extern f32 lbl_803E5470;
extern f32 lbl_803E548C;
extern f32 lbl_803E5490;
extern f32 lbl_803E5494;
extern f32 lbl_803E5498;
extern f32 lbl_803E549C;
extern f32 lbl_803E54A0;
extern f32 lbl_803E54AC;

extern void imicepillar_free(void);
extern int imicepillar_getObjectTypeId(void);
extern int imicepillar_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801ae0_dropped_old_imicepillar_render(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  if (*(int *)&((GameObject *)param_9)->unkC8 != 0) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)&((GameObject *)param_9)->unkC8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae184(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)
{
  undefined uVar1;
  bool bVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286830();
  puVar3 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  if (puVar3[0x23] == 0x373) {
    FUN_8003b818((int)puVar3);
  }
  else {
    uVar4 = GameBit_Get(0x6e);
    if ((uVar4 == 0) || (uVar4 = GameBit_Get(0x382), uVar4 != 0)) {
      puVar8 = *(undefined4 **)(puVar3 + 0x5c);
      puVar7 = (undefined2 *)*puVar8;
      bVar2 = false;
      if ((puVar7 != (undefined2 *)0x0) &&
         (iVar5 = (**(code **)(**(int **)(puVar7 + 0x34) + 0x38))(puVar7), iVar5 == 2)) {
        bVar2 = true;
      }
      if (bVar2) {
        puVar3[3] = puVar3[3] | 8;
        uVar6 = FUN_80057690((int)puVar7);
        param_6 = (char)uVar6;
        FUN_801adca0(puVar3,puVar7,(int)uVar9,param_3,param_4,param_5,param_6,
                     (uint)*(byte *)(puVar8 + 8),1);
      }
      else {
        puVar3[3] = puVar3[3] & ~0x8;
      }
      if ((param_6 != '\0') && (*(char *)(puVar8 + 8) != '\0')) {
        uVar1 = *(undefined *)((int)puVar3 + 0x37);
        if (bVar2) {
          *(char *)((int)puVar3 + 0x37) = *(char *)(puVar8 + 8);
        }
        FUN_8003b818((int)puVar3);
        ObjPath_GetPointWorldPosition(puVar3,1,(float *)(puVar8 + 5),puVar8 + 6,(float *)(puVar8 + 7),0);
        *(undefined *)((int)puVar3 + 0x37) = uVar1;
      }
    }
  }
  FUN_8028687c();
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
 * EN v1.1 Size: 48b
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
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
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
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
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
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
 * EN v1.1 Size: 72b
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
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
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
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
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
void imicepillar_hitDetect(void) {}
void imicepillar_update(void) {}
void imicepillar_init(void) {}
void imicepillar_release(void) {}
void imicepillar_initialise(void) {}

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

void imanimspacecraft_modelMtxFn(void) {}
void imanimspacecraft_hitDetect(void) {}
void imanimspacecraft_release(void) {}
void imanimspacecraft_initialise(void) {}
void imspacethruster_hitDetect(void) {}
void imspacethruster_release(void) {}
void imspacethruster_initialise(void) {}

void imspacering_free(void) {}
void imspacering_hitDetect(void) {}
void imspacering_release(void) {}
void imspacering_initialise(void) {}
void imspaceringgen_hitDetect(void) {}
void imspaceringgen_release(void) {}
void imspaceringgen_initialise(void) {}
void lavaball1be_hitDetect(void) {}
void lavaball1be_release(void) {}
void lavaball1be_initialise(void) {}
void lavaball1bf_hitDetect(void) {}
void lavaball1bf_release(void) {}
void lavaball1bf_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int imanimspacecraft_getExtraSize(void) { return 0x4; }
int imanimspacecraft_getObjectTypeId(void) { return 0x0; }
int imspacethruster_getExtraSize(void) { return 0xc; }
int imspacethruster_getObjectTypeId(void) { return 0x0; }
int imspacering_getExtraSize(void) { return 0x0; }
int imspacering_getObjectTypeId(void) { return 0x0; }
int imspaceringgen_getExtraSize(void) { return 0xc; }
int imspaceringgen_getObjectTypeId(void) { return 0x0; }
int linkb_levcontrol_getExtraSize(void) { return 0x10; }
int link_levcontrol_getExtraSize(void) { return 0x10; }
int lavaball1bf_getExtraSize(void) { return 0x1c; }
int lavaball1bf_getObjectTypeId(void) { return 0x0; }
int dimlogfire_getExtraSize(void) { return 0x24; }
int dimlogfire_getObjectTypeId(void) { return 0x1; }

/* Pattern wrappers. */
extern u32 lbl_803DDB48;
void imspaceringgen_free(void) { lbl_803DDB48 = 0x0; }

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */
void imspaceringgen_init(int *obj) {
    ((GameObject *)obj)->unkF4 = 0;
    lbl_803DDB48 = (u32)obj;
}

/* If obj->_F4 == 0, set it to 1; else early-return. */
void imanimspacecraft_update(int *obj) {
    if (((GameObject *)obj)->unkF4 != 0) return;
    ((GameObject *)obj)->unkF4 = 1;
}

/* Free: call vtable[6] on obj through global dll-services pointer. */
void imanimspacecraft_free(int *obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

extern f32 lbl_803E4784;
extern char lbl_803AC948[];
void imanimspacecraft_init(int *obj) {
    f32 v;
    ((GameObject *)obj)->animEventCallback = (void *)imanimspacecraft_SeqFn;
    v = lbl_803E4784;
    *(f32 *)(lbl_803AC948 + 0xc) = v;
    *(f32 *)(lbl_803AC948 + 0x10) = v;
    *(f32 *)(lbl_803AC948 + 0x14) = v;
    GameBit_Set(0xbeb, 1);
    GameBit_Set(0xbec, 1);
    GameBit_Set(0xbed, 1);
    GameBit_Set(0xbee, 1);
    GameBit_Set(0xbef, 1);
}

/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */
int imanimspacecraft_setScale(int *obj, int bitIdx) {
    ImAnimSpacecraftState *p = (ImAnimSpacecraftState *)((GameObject *)obj)->extra;
    switch (p->maskBits & (1 << bitIdx)) {
    default:
        return TRUE;
    case 0:
        return FALSE;
    }
}

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */
void lavaball1bf_func11(int *obj) {
    Lavaball1bfState *p = (Lavaball1bfState*)((int**)obj)[0xb8/4];
    if (p->gateA == 0) return;
    if (p->pending == 0) return;
    p->pending = 0;
}

/* lavaball1bf "request" hook: set pending if gated, return success. */
int lavaball1bf_setScale(int *obj) {
    Lavaball1bfState *p;
    obj = (int*)((int**)obj)[0xb8/4];
    p = (Lavaball1bfState*)obj;
    if (p->gateA == 0) return 0;
    if (p->pending == 0) {
        p->pending = 1;
        return 1;
    }
    return 0;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4768;
extern f32 lbl_803E4780;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4788;
extern f32 lbl_803E47B8;
extern f32 lbl_803E4810;
void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4768); }
void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4780); }
void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4788); }
void imspacering_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E47B8); }
void lavaball1bf_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4810); }

/* if (o->_X == K) return A; else return B;  pattern. */
int lavaball1be_getExtraSize(int *obj) { if (((GameObject *)obj)->anim.seqId == 0x1fa) return 0x0; return 0x14; }
int lavaball1be_getObjectTypeId(int *obj) { if (((GameObject *)obj)->anim.seqId == 0x1fa) return 0x0; return 0x2; }

/* chained byte mask. */
u32 imanimspacecraft_func0B(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x3) & 0x4; }
u32 lavaball1be_func11(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x10) & 0x10; }

int fn_801B0784(int obj, int delta) {
    s8 *inner = ((GameObject *)obj)->extra;
    inner[0x1c] = (s8)(inner[0x1c] - delta);
    return inner[0x1c] <= 0;
}

extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern void *Obj_GetPlayerObject(void);
extern int coordsToMapCell(f32 x, f32 z);
void link_levcontrol_free(int obj) {
    switch ((s32)((GameObject *)obj)->anim.mapEventSlot) {
        case 0x45: Music_Trigger(0xda, 0); break;
        case 0x48:
        case 0x49: Music_Trigger(0x36, 0); break;
    }
}
void link_levcontrol_update(int *obj) {
    LinkLevControlState *inner = ((GameObject *)obj)->extra;
    f32 *player = (f32 *)Obj_GetPlayerObject();
    if (player == NULL) return;

    if ((s32)inner->areaCell != (s32)((GameObject *)obj)->anim.mapEventSlot) {
        if ((s32)((GameObject *)obj)->anim.mapEventSlot == coordsToMapCell(player[3], player[5])) {
            link_levcontrol_applyEnterAreaEffects(obj);
        } else {
            return;
        }
    }
    if ((s32)((GameObject *)obj)->anim.mapEventSlot == coordsToMapCell(player[3], player[5])) {
        link_levcontrol_updateAreaMusic(obj);
    }
    inner->areaCell = (s8)coordsToMapCell(player[3], player[5]);
}
extern void *gSHthorntailAnimationInterface;
extern void SCGameBitLatch_Update(void *p, int a, int b, int c, int d, int e);
void link_levcontrol_updateAreaMusic(int *obj) {
    LinkLevControlState *sub = ((GameObject *)obj)->extra;
    switch (((GameObject *)obj)->anim.mapEventSlot) {
    case 0x47:
        if (((int (*)(int))((void **)*(int *)gSHthorntailAnimationInterface)[9])(0) != 0) {
            if (sub->musicTrack != 0x2d) {
                sub->musicTrack = 0x2d;
                Music_Trigger(0x2d, 1);
            }
        } else {
            if (sub->musicTrack != 0x33) {
                sub->musicTrack = 0x33;
                Music_Trigger(0x33, 1);
            }
        }
        break;
    case 0x48:
        if (GameBit_Get(0xe1e) == 0) {
            if (GameBit_Get(0xb72) != 0) {
                if (sub->musicTrack != 0x95) {
                    sub->musicTrack = 0x95;
                    Music_Trigger(0x95, 1);
                }
            } else if (((int (*)(int))((void **)*(int *)gSHthorntailAnimationInterface)[9])(0) != 0) {
                if (sub->musicTrack != 0x2d) {
                    sub->musicTrack = 0x2d;
                    Music_Trigger(0x2d, 1);
                }
            } else {
                if (sub->musicTrack != 0x33) {
                    sub->musicTrack = 0x33;
                    Music_Trigger(0x33, 1);
                }
            }
        }
        SCGameBitLatch_Update(&sub->latch, 1, -1, -1, 0xe1e, 0x36);
        break;
    }
}
extern void fn_80088870(u8 *a, u8 *b, u8 *c, u8 *d);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int a, int b, int c, int d);
extern u8 lbl_803239F0[];
void link_levcontrol_applyEnterAreaEffects(int *obj) {
    u8 *tbl = lbl_803239F0;
    switch (((GameObject *)obj)->anim.mapEventSlot) {
    case 0x47:
        fn_80088870(tbl + 0x38, tbl, tbl + 0x70, tbl + 0xa8);
        if (((GameObject *)obj)->unkF4 == 2) {
            envFxActFn_800887f8(0x3f);
        } else {
            envFxActFn_800887f8(0x1f);
        }
        Music_Trigger(0xc2, 0);
        Music_Trigger(0xce, 0);
        Music_Trigger(0xcc, 0);
        Music_Trigger(0xdb, 0);
        Music_Trigger(0xf2, 0);
        break;
    case 0x45:
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        getEnvfxAct(0, 0, 0x13e, 0);
        getEnvfxAct(0, 0, 0x140, 0);
        getEnvfxAct(0, 0, 0x13f, 0);
        Music_Trigger(0xda, 1);
        break;
    case 0x49:
        Music_Trigger(0x36, 1);
        break;
    case 0x48:
        Music_Trigger(0xc8, 0);
        break;
    case 0x46:
        Music_Trigger(0xe1, 0);
        Music_Trigger(0x96, 1);
        break;
    }
}
extern void ObjModel_SetBlendChannelTargets(int *model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int *model, int channel, f32 weight);
extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4, lbl_803E4798, lbl_803E4788;
extern s16 lbl_80323818[], lbl_80323824[];
void imspacethruster_init(int *obj, u8 *param2) {
    ObjAnimComponent *objAnim;
    ImSpaceThrusterState *sub = ((GameObject *)obj)->extra;
    int *model;
    objAnim = (ObjAnimComponent *)obj;
    *(s16 *)obj = (s16)((s8)param2[0x18] << 8);
    ((GameObject *)obj)->anim.rotY = *(s16 *)((char *)param2 + 0x1a);
    objAnim->bankIndex = (s8)*(s16 *)((char *)param2 + 0x1c);
    sub->kind = param2[0x19];
    switch (sub->kind) {
    case 0:
    case 1:
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E47A8;
        break;
    case 2:
    case 3:
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E47AC;
        break;
    case 5:
    case 6:
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E47B0;
        break;
    case 4:
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E47B4;
        break;
    }
    model = DIMcannon_GetActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4798, 0);
    ObjModel_SetBlendChannelWeight(model, 0, lbl_803E4788);
    {
        u32 v = sub->kind;
        if (v < 5) {
            *(int *)&sub->bufA = (int)mmAlloc(0x28, 0x12, 0);
            getTabEntry(sub->bufA, 0xc, lbl_80323818[v] * 0x28, 0x28);
            *(int *)&sub->bufB = (int)mmAlloc(0x28, 0x12, 0);
            getTabEntry(sub->bufB, 0xc, lbl_80323824[v] * 0x28, 0x28);
        }
    }
    ((GameObject *)obj)->anim.alpha = 0;
}
void link_levcontrol_init(int *obj) {
    LinkLevControlState *inner = ((GameObject *)obj)->extra;
    inner->areaCell = -1;
    inner->unk04 = -1;
    inner->musicTrack = -1;
    ((GameObject *)obj)->objectFlags |= 0x4000;
    if (getSaveGameLoadStatus() != 0) {
        ((GameObject *)obj)->unkF4 = 2;
    } else {
        ((GameObject *)obj)->unkF4 = 1;
    }
}

extern u8 lbl_803238D8[];
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern int *getTrickyObject(void);
extern void fn_80138908(int *tricky, int mode);
extern f32 timeDelta;
extern f32 lbl_803E47C8;

typedef struct {
    int flags;
    s8 cnt : 2;
    u8 stage : 3;
    u8 low : 3;
    u8 flag5 : 1;
    u8 pad5 : 7;
    u8 pad6[2];
    f32 timer;
    s16 music;
} LinkbLevState;

void linkb_levcontrol_init(int *obj) {
    u8 *t = (u8 *)(int)lbl_803238D8;
    LinkbLevState *sub = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x6000);
    if (GameBit_Get(0x36e) != 0) {
        sub->flags &= 4;
    }
    if (GameBit_Get(0x543) != 0) {
        sub->stage = 5;
    } else if (GameBit_Get(0x387) != 0) {
        sub->stage = 4;
    } else if (GameBit_Get(0x386) != 0) {
        sub->stage = 3;
    } else if (GameBit_Get(0x385) != 0) {
        sub->stage = 2;
    } else if (GameBit_Get(0x384) != 0) {
        sub->stage = 1;
    }
    fn_80088870(t + 0x38, (u8 *)(int)lbl_803238D8, t + 0x70, t + 0xa8);
    if (getSaveGameLoadStatus() != 0) {
        if ((*gMapEventInterface)->getAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0) == 0) {
            envFxActFn_800887f8(0x3f);
        }
        getEnvfxActImmediately(0, 0, 0x23c, 0);
    } else {
        if ((*gMapEventInterface)->getAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0) == 0) {
            envFxActFn_800887f8(0x1f);
        }
        getEnvfxAct(0, 0, 0x23c, 0);
    }
    sub->music = 0;
}
void linkb_levcontrol_update(int *obj) {
    LinkbLevState *state;
    int *tricky;
    int *player;
    u8 *cur;

    state = ((GameObject *)obj)->extra;
    player = (int *)Obj_GetPlayerObject();
    tricky = getTrickyObject();
    cur = (*gMapEventInterface)->getProgressPtr();
    if (((int (*)(int))((void **)*(int *)gSHthorntailAnimationInterface)[9])(0) != 0) {
        if (state->music != -1) {
            state->music = -1;
            if (state->flags & 8) {
                Music_Trigger(0x1a, 0);
            }
        }
    } else {
        if (state->music != 0x1a) {
            state->music = 0x1a;
            if (state->flags & 8) {
                Music_Trigger(0x1a, 1);
            }
        }
    }
    SCGameBitLatch_Update(state, 1, -1, -1, 0x3a0, 0x35);
    SCGameBitLatch_Update(state, 2, -1, -1, 0xb36, 0x96);
    SCGameBitLatch_Update(state, 8, -1, -1, 0x3a1, state->music);
    if (state->flags & 4) {
        if (GameBit_Get(0x1fd) == 0 && GameBit_Get(0x256) == 0) {
            GameBit_Set(0x36e, 0);
            state->flags &= ~4;
        }
    } else {
        if (GameBit_Get(0x256) != 0 || GameBit_Get(0x1fd) != 0) {
            GameBit_Set(0x36e, 1);
            state->flags |= 4;
        }
    }
    if (tricky != NULL) {
        fn_80138908(tricky, 0);
        switch (state->stage) {
        case 0:
            if (GameBit_Get(0x384) != 0) {
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->low = 0;
                return;
            }
            break;
        case 1:
            if (GameBit_Get(0xc1) != 0) {
                if (!(((GameObject *)player)->objectFlags & 0x1000)) {
                    GameBit_Set(0x385, 1);
                    fn_80138908(tricky, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->low = 0;
                    return;
                }
            }
            break;
        case 2:
            if (cur[0] != 0) {
                fn_80138908(tricky, 1);
                if (state->cnt-- == -1 && !(*(u16 *)((char *)tricky + 0xb0) & 0x1000)) {
                    GameBit_Set(0x386, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->low = 0;
                    return;
                }
            }
            break;
        case 3:
            if (GameBit_Get(0x1fd) != 0) {
                GameBit_Set(0x387, 1);
                state->stage++;
                break;
            }
            if (GameBit_Get(0x380) != 0) {
                state->flag5 = 1;
                break;
            }
            if (state->flag5 != 0) {
                GameBit_Set(0x387, 1);
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->low = 0;
                return;
            }
            break;
        case 4:
            if (GameBit_Get(0x543) != 0) {
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->low = 0;
                return;
            }
            break;
        }
    }
    if (tricky != NULL) {
        if (!(*(u16 *)((char *)tricky + 0xb0) & 0x1000)) {
            state->timer = state->timer + timeDelta;
        }
        if (GameBit_Get(0x4e3) == 1 && cur[0] >= 4) {
            GameBit_Set(0x4e3, 0xff);
        }
        if (state->timer >= lbl_803E47C8) {
            state->timer = state->timer - lbl_803E47C8;
            if (GameBit_Get(0x4e3) == 0xff && cur[0] < 4) {
                GameBit_Set(0x4e3, 1);
            }
        }
    }
}

extern f32 lbl_803E47C0;
extern u8 framesThisStep;
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern void Obj_SetupObject(int obj, int a, int b, int c, int d);
extern f32 lbl_803E47C4;

typedef struct {
    int *ringA;
    int *ringB;
    u8 visible;
} RingGenState;

void imspacering_init(s16 *obj, s8 *p) {
    ((GameObject *)obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    ((GameObject *)obj)->unkF4 = randomGetRange(0, 1);
}
void imspacering_update(s16 *obj) {
    s16 *inner = *(s16 **)&((GameObject *)obj)->anim.placementData;
    if (((GameObject *)obj)->unkF4 != 0) {
        ((GameObject *)obj)->anim.rotX = (s16)(((GameObject *)obj)->anim.rotX + inner[0xd] * framesThisStep);
    } else {
        ((GameObject *)obj)->anim.rotY = (s16)(((GameObject *)obj)->anim.rotY + inner[0xd] * framesThisStep);
    }
    ((GameObject *)obj)->anim.rotZ = (s16)(((GameObject *)obj)->anim.rotZ + inner[0xe] * framesThisStep);
    if (lbl_803DDB48 != 0) {
        ((GameObject *)obj)->anim.alpha = ((GameObject *)lbl_803DDB48)->anim.alpha;
        objMove((int)obj,
            ((GameObject *)lbl_803DDB48)->anim.localPosX - ((GameObject *)obj)->anim.localPosX,
            ((GameObject *)lbl_803DDB48)->anim.localPosY - ((GameObject *)obj)->anim.localPosY,
            ((GameObject *)lbl_803DDB48)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ);
    }
}
void imspaceringgen_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    u8 *inner = ((GameObject *)obj)->extra;
    if (visible != 0 && (inner[8] != 0 || ((GameObject *)obj)->anim.alpha != 0)) {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E47C0);
    }
}
void imspaceringgen_update(s16 *obj) {
    int i;
    int ring;
    u8 *setup;
    RingGenState *state;
    int objIndex;
    int objCount;

    setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    if (state->ringA == NULL || state->ringB == NULL) {
        int *objs = ObjList_GetObjects(&objIndex, &objCount);
        for (objIndex = 0; objIndex < objCount; objIndex++) {
            int *o = (int *)objs[objIndex];
            if (((GameObject *)o)->anim.seqId == 0x164) {
                state->ringA = o;
            }
            if (((GameObject *)o)->anim.seqId == 0x168) {
                state->ringB = o;
            }
        }
    } else {
        int v;
        state->visible = ((int (*)(int *))((void **)*(void **)*(int *)((char *)state->ringB + 0x68))[9])(state->ringB);
        if (state->visible != 0) {
            v = ((GameObject *)obj)->anim.alpha + framesThisStep * 8;
            if (v > 0xff) {
                v = 0xff;
            }
        } else {
            v = ((GameObject *)obj)->anim.alpha - framesThisStep * 8;
            if (v < 0) {
                v = 0;
            }
        }
        ((GameObject *)obj)->anim.alpha = v;
        if (((GameObject *)obj)->unkF4 == 0 && Obj_IsLoadingLocked() != 0) {
            for (i = 0; i < 10; i++) {
                ring = Obj_AllocObjectSetup(0x24, 0x301);
                *(f32 *)(ring + 8) = ((GameObject *)obj)->anim.localPosX;
                *(f32 *)(ring + 0xc) = ((GameObject *)obj)->anim.localPosY;
                *(f32 *)(ring + 0x10) = ((GameObject *)obj)->anim.localPosZ;
                *(s8 *)(ring + 0x18) = (s8)randomGetRange(0, 0xffff);
                *(s16 *)(ring + 0x1a) = (s16)randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0) {
                    *(s16 *)(ring + 0x1a) = -*(s16 *)(ring + 0x1a);
                }
                *(s16 *)(ring + 0x1c) = (s16)randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0) {
                    *(s16 *)(ring + 0x1c) = -*(s16 *)(ring + 0x1c);
                }
                *(u8 *)(ring + 4) = setup[4];
                *(u8 *)(ring + 6) = setup[6];
                *(u8 *)(ring + 5) = 1;
                *(u8 *)(ring + 7) = 0xff;
                Obj_SetupObject(ring, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, *(int *)&((GameObject *)obj)->anim.parent);
            }
            ((GameObject *)obj)->unkF4 = 1;
        }
        objMove((int)obj,
            *(f32 *)((char *)state->ringA + 0xc) - ((GameObject *)obj)->anim.localPosX,
            (lbl_803E47C4 + *(f32 *)((char *)state->ringA + 0x10)) - ((GameObject *)obj)->anim.localPosY,
            *(f32 *)((char *)state->ringA + 0x14) - ((GameObject *)obj)->anim.localPosZ);
        ((GameObject *)obj)->anim.rotX = ((GameObject *)obj)->anim.rotX + framesThisStep * 0x100;
        ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY + framesThisStep * 0x20;
        ((GameObject *)obj)->anim.rotZ = ((GameObject *)obj)->anim.rotZ + framesThisStep * 0x40;
        *(int *)&((GameObject *)obj)->anim.parent = 0;
    }
}

extern void Obj_FreeObject(void *o);
extern void ModelLightStruct_free(void *light);
extern void mm_free(void *p);

extern f32 lbl_803E4814;
void lavaball1bf_init(s16 *obj, u8 *p) {
    Lavaball1bfState *inner;
    ((GameObject *)obj)->anim.rotX = (s16)((s32)p[0x1c] << 8);
    inner = ((GameObject *)obj)->extra;
    inner->firePeriod = (f32)*(s16 *)(p + 0x18);
    inner->fireTimer = lbl_803E4814;
    inner->gateA = p[0x1d];
    inner->gateB = (u8)GameBit_Get((int)*(s16 *)(p + 0x22));
    if (*(s16 *)(p + 0x24) == -1 && inner->gateB == 0) {
        inner->soloLatch = 1;
    }
    ((GameObject *)obj)->objectFlags |= 0x6000;
}
void lavaball1bf_free(int obj, int mode) {
    Lavaball1bfState *inner = ((GameObject *)obj)->extra;
    if (mode == 0 && inner->spawnedObj != 0) {
        Obj_FreeObject(inner->spawnedObj);
    }
}
void lavaball1be_free(int obj) {
    Lavaball1beState *inner = ((GameObject *)obj)->extra;
    if (inner->light != 0) {
        ModelLightStruct_free(inner->light);
        inner->light = 0;
    }
}
void imspacethruster_free(int obj) {
    ImSpaceThrusterState *inner = ((GameObject *)obj)->extra;
    if (inner->bufA != 0) mm_free(inner->bufA);
    if (inner->bufB != 0) mm_free(inner->bufB);
}

void dimlogfire_free(int *obj, int mode) {
    DimLogFireState *inner = ((GameObject *)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if ((void *)inner->subObj != NULL && mode == 0) {
        Obj_FreeObject((int *)inner->subObj);
    }
    ObjGroup_RemoveObject(obj, 0x31);
    if ((void *)inner->light != NULL) {
        ModelLightStruct_free((void *)inner->light);
    }
}

extern int Sfx_PlayFromObject(int *obj, int sfxId);
extern void Sfx_StopObjectChannel(int *obj, int channel);
int dimlogfire_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate) {
    DimLogFireState *state = ((GameObject *)obj)->extra;
    if (state->mode == 1) {
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    } else {
        Sfx_StopObjectChannel(obj, 64);
    }
    switch (animUpdate->triggerCommand) {
    case 1:
        state->smokeToggle = (u8)(state->smokeToggle ^ 1);
        break;
    case 2:
        GameBit_Set(46, 1);
        break;
    case 3:
        state->mode = 4;
        break;
    }
    if (state->smokeToggle != 0) {
        (*gPartfxInterface)->spawnObject(obj, 215, NULL, 0, -1, NULL);
        Sfx_StopObjectChannel(obj, 5);
    } else {
        Sfx_StopObjectChannel(obj, 1);
    }
    animUpdate->triggerCommand = 0;
    return 0;
}

extern void queueGlowRender(int *obj);
extern f32 lbl_803E4820;

void dimlogfire_render(int *obj, int p2, int p3, int p4, int p5, s8 visible) {
    DimLogFireState *state;
    int *subobj;
    if ((s32)visible != 0) {
        state = ((GameObject *)obj)->extra;
        subobj = (int *)state->subObj;
        if (subobj != NULL) {
            int *q = DIMcannon_GetActiveModel(subobj);
            *(u16 *)((char *)q + 0x18) = (u16)(*(u16 *)((char *)q + 0x18) & ~0x8);
            *(u8 *)((char *)(int *)state->subObj + 0x37) = *(u8 *)((char *)obj + 0x37);
            ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)((int *)state->subObj, p2, p3, p4, p5, lbl_803E4820);
        }
        ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4820);
        if (*(void **)&state->light != NULL) {
            if (*(u8 *)((char *)*(void **)&state->light + 0x2f8) != 0) {
                if (*(u8 *)((char *)*(void **)&state->light + 0x4c) != 0) {
                    queueGlowRender(*(int **)&state->light);
                }
            }
        }
    }
}

extern int modelLightStruct_getActiveState(int* p);
extern f32 lbl_803E47F0;

void lavaball1be_render(int* obj, int p2, int p3, int p4, int p5)
{
    Lavaball1beState* state = ((GameObject *)obj)->extra;
    if ((int*)state->light != NULL) {
        if (modelLightStruct_getActiveState((int*)state->light) != 0) {
            queueGlowRender((int*)state->light);
        }
    }
    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E47F0);
}

extern void spawnExplosion(s16 *obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void modelLightStruct_updateGlowAlpha(int p);
extern f32 lbl_803E47D0, lbl_803E47F4, lbl_803E47F8, lbl_803E47FC;
extern f32 lbl_803E47D4, lbl_803E47D8, lbl_803E47DC, lbl_803E47E0;
extern f32 lbl_803E4800, lbl_803E4804, lbl_803E4808;
extern u8 lbl_802C2318[];
extern void vecRotateZXY(void *in, void *out);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int ObjList_FindObjectById(int id);
extern u8 *objCreateLight(s16 *obj, int b);
extern void modelLightStruct_setLightKind(u8 *light, int value);
extern void modelLightStruct_setDiffuseColor(u8 *light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(u8 *light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(u8 *light, int p3, int p4, int p5, int p6, int p7, f32 a);
extern void modelLightStruct_setGlowProjectionRadius(u8 *light, f32 a);

typedef struct {
    f32 x, y, z;
} LavaVec;

void lavaball1be_init(s16 *obj, u8 *p) {
    Lavaball1beState *state;
    if (((GameObject *)obj)->anim.seqId == 0x1fa) {
        struct {
            LavaVec vec;
            s16 rot[3];
            u8 pad[18];
        } s;
        s.vec = *(LavaVec *)lbl_802C2318;
        s.rot[2] = 0;
        s.rot[1] = (s16)randomGetRange(-0x2ee0, 0x2ee0);
        s.rot[0] = (s16)randomGetRange(0, 0xfffe);
        vecRotateZXY((u8 *)&s + 12, &s.vec);
        ((GameObject *)obj)->unkF4 = 0x4b;
        ((GameObject *)obj)->anim.velocityX = s.vec.x;
        ((GameObject *)obj)->anim.velocityY = s.vec.y;
        ((GameObject *)obj)->anim.velocityZ = s.vec.z;
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * lbl_803E47D4;
    } else {
        f32 vy;
        f32 vxz;
        int *sub;
        u8 *light;

        ((GameObject *)obj)->anim.rotX = (s16)((s32)*(s8 *)(p + 0x18) << 8);
        state = ((GameObject *)obj)->extra;
        vy = lbl_803E47D8 * (f32)*(s16 *)(p + 0x1a);
        vxz = lbl_803E47D8 * (f32)*(s16 *)(p + 0x1c);
        state->floorY = ((GameObject *)obj)->anim.localPosY;
        state->linkedId = *(int *)(p + 0x14);
        *(int *)(p + 0x14) = -1;
        ((GameObject *)obj)->anim.velocityX = vxz * -mathSinf(lbl_803E47DC * (f32)((GameObject *)obj)->anim.rotX / lbl_803E47E0);
        ((GameObject *)obj)->anim.velocityY = vy;
        ((GameObject *)obj)->anim.velocityZ = vxz * -mathCosf(lbl_803E47DC * (f32)((GameObject *)obj)->anim.rotX / lbl_803E47E0);
        sub = *(int **)&((GameObject *)obj)->anim.hitReactState;
        if (sub != NULL) {
            *((u8 *)sub + 0x6a) = 0;
        }
        sub = (int *)((GameObject *)obj)->anim.modelState;
        if (sub != NULL) {
            ((GameObject *)obj)->anim.modelState->flags |= 0x810;
        }
        *(int *)&state->targetObj = ObjList_FindObjectById(state->linkedId);
        state->flags |= 0x10;
        ObjHits_DisableObject(obj);
        ((GameObject *)obj)->objectFlags |= 0x2000;
        state->light = objCreateLight(obj, 1);
        light = state->light;
        if (light != NULL) {
            modelLightStruct_setLightKind(light, 2);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0x80, 0, 0);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E4800, lbl_803E4804);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0x80, 0, 0x64, lbl_803E4808);
            modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E4808);
        }
    }
}
void lavaball1be_update(s16 *obj) {
    Lavaball1beState *state;
    int *sub;

    if (((GameObject *)obj)->anim.seqId == 0x1fa) {
        ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
        (*gPartfxInterface)->spawnObject(obj, 0x1f5, NULL, 1, -1, NULL);
        ((GameObject *)obj)->anim.rotX = ((GameObject *)obj)->anim.rotX + framesThisStep * 0x374;
        ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY + framesThisStep * 0x12c;
        ((GameObject *)obj)->anim.velocityY = -(lbl_803E47D0 * timeDelta - ((GameObject *)obj)->anim.velocityY);
        ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 - framesThisStep;
        if (((GameObject *)obj)->unkF4 < 0) {
            Obj_FreeObject(obj);
        }
    } else {
        state = ((GameObject *)obj)->extra;
        if (state->flags & 0x10) {
            ObjHits_DisableObject(obj);
        } else {
            f32 dt = timeDelta;
            u8 steps = framesThisStep;
            if (state->explodeCooldown != 0) {
                state->explodeCooldown--;
            }
            ((GameObject *)obj)->anim.rotX = ((GameObject *)obj)->anim.rotX + (steps << 6);
            ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY - (steps << 9);
            ((GameObject *)obj)->anim.velocityY = lbl_803E47F4 * dt + ((GameObject *)obj)->anim.velocityY;
            objMove((int)obj,
                ((GameObject *)obj)->anim.velocityX * dt,
                ((GameObject *)obj)->anim.velocityY * dt,
                ((GameObject *)obj)->anim.velocityZ * dt);
            if (((GameObject *)obj)->anim.velocityY < lbl_803E47F8) {
                if (!(state->flags & 0x20)) {
                    Sfx_PlayFromObject((int *)obj, 0x3dd);
                    state->flags |= 0x20;
                }
            } else {
                state->flags &= ~0x20;
            }
            sub = *(int **)&((GameObject *)obj)->anim.hitReactState;
            if (sub != NULL) {
                *((u8 *)sub + 0x6e) = 0xb;
                *((u8 *)sub + 0x6f) = 1;
                sub[0x48 / 4] = 0x10;
                sub[0x4c / 4] = 0x10;
                if (*(void **)&((ObjHitsPriorityState *)sub)->lastHitObject != NULL) {
                    if (state->explodeCooldown != 0) {
                        spawnExplosion(obj, lbl_803E47FC, 0, 1, 0, 0, 0, 0, 0);
                    } else {
                        state->explodeCooldown = 0xa;
                        spawnExplosion(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    }
                    state->flags |= 0x10;
                    ((GameObject *)obj)->anim.flags |= 0x4000;
                }
                if (((ObjAnimComponent *)sub)->bankIndex & 1) {
                    spawnExplosion(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    state->flags |= 0x10;
                    ((GameObject *)obj)->anim.flags |= 0x4000;
                    return;
                }
            }
            if (((GameObject *)obj)->anim.localPosY < state->floorY) {
                state->flags |= 0x10;
            }
            if (!(state->flags & 8)) {
                state->flags |= 8;
            }
            if ((void *)state->light != NULL && modelLightStruct_getActiveState((int *)state->light) != 0) {
                modelLightStruct_updateGlowAlpha((int)state->light);
            }
        }
    }
}

extern int *objFindTexture(int *obj, int a, int b);
extern f32 lbl_803E4770, lbl_803E4774, lbl_803E4778, lbl_803E477C;

int imanimspacecraft_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate) {
    ImAnimSpacecraftState *state;
    int i;
    int *tex;

    state = ((GameObject *)obj)->extra;
    tex = objFindTexture(obj, 1, 0);
    *tex = ((state->flags >> 1 & 1) ^ 1) << 8;
    if (!(state->flags & 2)) {
        if ((state->blinkTimer -= framesThisStep) < 0) {
            state->flags |= 2;
            state->blinkTimer = 0x78;
        }
    } else {
        state->flags &= ~2;
    }
    if (state->flags & 2) {
        *(f32 *)(lbl_803AC948 + 0xc) = lbl_803E4770;
        *(f32 *)(lbl_803AC948 + 0x10) = lbl_803E4774;
        *(f32 *)(lbl_803AC948 + 0x14) = lbl_803E4778;
        (*gPartfxInterface)->spawnObject(obj, 0x133, lbl_803AC948, 4, -1, NULL);
        *(f32 *)(lbl_803AC948 + 0xc) = lbl_803E477C;
        *(f32 *)(lbl_803AC948 + 0x10) = lbl_803E4774;
        *(f32 *)(lbl_803AC948 + 0x14) = lbl_803E4778;
        (*gPartfxInterface)->spawnObject(obj, 0x133, lbl_803AC948, 4, -1, NULL);
    }
    tex = objFindTexture(obj, 0, 0);
    *tex = 0x100;
    for (i = 0; i < animUpdate->eventCount; i++) {
        u32 ev = animUpdate->eventIds[i];
        switch (ev) {
        case 1:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 2:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 3:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 4:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 5:
            state->maskBits = (u8)(state->maskBits ^ 0x70);
            break;
        case 6:
            state->flags = (u8)(state->flags ^ 8);
            break;
        case 7:
            state->flags = (u8)(state->flags ^ 4);
            break;
        }
    }
    return 0;
}

extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;

void imspacethruster_update(int *obj) {
    ImSpaceThrusterState *state;
    int mode;
    s16 v;
    int *tex;

    state = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->anim.parent != NULL) {
        mode = ((s16 (*)(int, int))((void **)*(void **)*(int *)(*(int *)&((GameObject *)obj)->anim.parent + 0x68))[8])(*(int *)&((GameObject *)obj)->anim.parent, state->kind);
        switch (state->phase) {
        case 0:
            if (mode == 1) {
                ObjModel_SetBlendChannelTargets(DIMcannon_GetActiveModel(obj), 0, -1, 0, lbl_803E478C, 0x10);
                ((GameObject *)obj)->anim.alpha = 0xff;
                state->phase = 1;
            } else {
                int d = ((GameObject *)obj)->anim.alpha - framesThisStep * 8;
                if (d < 0) {
                    d = 0;
                }
                ((GameObject *)obj)->anim.alpha = d;
            }
            break;
        case 1:
            if (mode == 0) {
                ObjModel_SetBlendChannelTargets(DIMcannon_GetActiveModel(obj), 0, -1, 0, lbl_803E4790, 0x10);
                state->blendTimer = 0xb4;
                ((GameObject *)obj)->anim.alpha = 0xa4;
                state->phase = 2;
            }
            break;
        case 2:
            if (mode == 1) {
                state->phase = 1;
            } else {
                if ((state->blendTimer -= framesThisStep) < 0) {
                    state->phase = 0;
                }
            }
            break;
        }
        if (state->kind < 5) {
            f32 a = (f32)((GameObject *)obj)->anim.alpha / lbl_803E4794;
            if (a > lbl_803E4788) {
                a = lbl_803E4788;
            } else if (a < lbl_803E4798) {
                a = lbl_803E4798;
            }
            ((void (*)(int, f32, int))((void **)*(void **)*(int *)(*(int *)&((GameObject *)obj)->anim.parent + 0x68))[10])(*(int *)&((GameObject *)obj)->anim.parent, a, state->kind);
        }
        tex = objFindTexture(obj, 0, 0);
        v = -*(s16 *)((char *)tex + 0xa);
        v += 0x100;
        if (v > 0x800) {
            v -= 0x800;
        }
        *(s16 *)((char *)tex + 0xa) = -v;
        tex = objFindTexture(obj, 1, 0);
        v = -*(s16 *)((char *)tex + 0xa);
        v += 0xa0;
        if (v > 0x800) {
            v -= 0x800;
        }
        *(s16 *)((char *)tex + 0xa) = -v;
    }
}


void lavaball1bf_update(int *obj) {
    u8 *setup;
    Lavaball1bfState *state;
    int *spawned;
    f32 t;

    state = ((GameObject *)obj)->extra;
    setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
    state->gbState = GameBit_Get(((Lavaball1bfPlacement *)setup)->unk24);
    if (state->soloLatch != 0) {
        if (GameBit_Get(((Lavaball1bfPlacement *)setup)->unk1E) != 0) {
            state->gbState = 1;
            state->soloLatch = 0;
            state->fireTimer = lbl_803E4814;
        } else {
            state->gbState = 0;
        }
    }
    if (*(void **)&state->spawnedObj == NULL && Obj_IsLoadingLocked() != 0) {
        int s = Obj_AllocObjectSetup(0x24, 0x18d);
        *(u8 *)(s + 2) = 9;
        *(u8 *)(s + 4) = 2;
        *(u8 *)(s + 6) = 0xff;
        *(u8 *)(s + 5) = 4;
        *(u8 *)(s + 7) = 0x50;
        *(f32 *)(s + 8) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(s + 0xc) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(s + 0x10) = ((GameObject *)obj)->anim.localPosZ;
        *(s8 *)(s + 0x18) = (s8)setup[0x1c];
        *(s16 *)(s + 0x1a) = setup[0x1a];
        *(s16 *)(s + 0x1c) = setup[0x1b];
        *(int *)(s + 0x14) = ((ObjPlacement *)setup)->mapId;
        *(int *)&state->spawnedObj = ((int (*)(int, int, int, int, int))Obj_SetupObject)(s, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, 0);
    }
    spawned = state->spawnedObj;
    t = state->fireTimer - timeDelta;
    state->fireTimer = t;
    if (t <= lbl_803E4814 && ((int (*)(int *))((void **)*(void **)*(int *)((char *)spawned + 0x68))[9])(spawned) != 0) {
        if (state->gbState != 0) {
            int a;
            if (GameBit_Get(((Lavaball1bfPlacement *)setup)->unk1E) != 0 && state->gateB == 0) {
                a = setup[0x20];
                state->gateB = 1;
            } else {
                a = setup[0x1a];
            }
            ((void (*)(int *, int, int))((void **)*(void **)*(int *)((char *)spawned + 0x68))[8])(spawned, a, setup[0x1b]);
        }
        state->fireTimer = state->firePeriod + (f32)(int)randomGetRange(0, 0x3c);
    }
}

void lavaball1be_setScale(s16 *obj, int p2, int p3) {
    Lavaball1beState *state;
    u8 *setup;
    f32 vxz;
    f32 x;

    state = ((GameObject *)obj)->extra;
    setup = *(u8 **)&((GameObject *)obj)->anim.placementData;
    vxz = lbl_803E47D8 * (f32)p3;
    x = *(f32 *)(*(char **)&state->targetObj + 0xc);
    ((GameObject *)obj)->anim.worldPosX = x;
    ((GameObject *)obj)->anim.localPosX = x;
    x = *(f32 *)(*(char **)&state->targetObj + 0x10);
    ((GameObject *)obj)->anim.worldPosY = x;
    ((GameObject *)obj)->anim.localPosY = x;
    x = *(f32 *)(*(char **)&state->targetObj + 0x14);
    ((GameObject *)obj)->anim.worldPosZ = x;
    ((GameObject *)obj)->anim.localPosZ = x;
    x = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.previousWorldPosX = x;
    ((GameObject *)obj)->anim.previousLocalPosX = x;
    x = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.previousWorldPosY = x;
    ((GameObject *)obj)->anim.previousLocalPosY = x;
    x = ((GameObject *)obj)->anim.localPosZ;
    ((GameObject *)obj)->anim.previousWorldPosZ = x;
    ((GameObject *)obj)->anim.previousLocalPosZ = x;
    ((GameObject *)obj)->anim.rotX = (s16)((s32)((Lavaball1bePlacement *)setup)->unk18 << 8);
    ((GameObject *)obj)->anim.velocityX = vxz * -mathSinf(lbl_803E47DC * (f32)((GameObject *)obj)->anim.rotX / lbl_803E47E0);
    ((GameObject *)obj)->anim.velocityY = lbl_803E47D8 * (f32)p2;
    ((GameObject *)obj)->anim.velocityZ = vxz * -mathCosf(lbl_803E47DC * (f32)((GameObject *)obj)->anim.rotX / lbl_803E47E0);
    ((GameObject *)obj)->anim.flags &= ~0x4000;
    ObjHits_EnableObject(obj);
    state->flags &= ~0x10;
}
