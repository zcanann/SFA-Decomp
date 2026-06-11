#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim_internal.h"
#include "main/dll/DR/DRpushcart.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

typedef struct ShopitemState {
    u8 pad0[0x88 - 0x0];
    s16 unk88;
    u8 pad8A[0xEC - 0x8A];
} ShopitemState;


typedef struct ShopitemPlacement {
    u8 pad0[0x19 - 0x0];
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} ShopitemPlacement;


/* shopitem_getExtraSize == 0xec (spline-following pushcart item). */
typedef struct ShopItemState {
    u8 pad00[4];
    f32 controlX[4];  /* 0x04: B-spline control ring (address-passed, raw) */
    f32 controlY[4];  /* 0x14 */
    f32 controlZ[4];  /* 0x24 */
    u8 pad34[0xC];
    f32 splineT;      /* 0x40 */
    f32 splineSpeed;  /* 0x44 */
    u8 pad48[0x20];
    u8 segCounter;    /* 0x68 */
    u8 pad69[0x1F];
    s16 msgParam;     /* 0x88: ObjMsg payload (address-used, raw) */
    u8 pad8A[6];
    int vendorObj;    /* 0x90: nearest group-9 shop manager */
    s16 helpTextId;   /* 0x94 */
    u8 pad96;
    u8 flags97;       /* 0x97: PushcartState97 overlay */
    u8 pad98[0xEC - 0x98];
} ShopItemState;
STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

/* shopkeeper_getExtraSize == 0x9d8. */
typedef struct ShopkeeperState {
    u8 pad000[0x280];
    f32 animSpeed;    /* 0x280 */
    u8 pad284[0x35C - 0x284];
    u8 dll2EBlock[0x96D - 0x35C]; /* 0x35c: dll_2E look-controller block (address-used) */
    u8 unk96D;        /* 0x96d */
    u8 pad96E[0x980 - 0x96E];
    u8 eyeAnimBlock[0x9B0 - 0x980]; /* 0x980: characterDoEyeAnims block (address-used) */
    void *msgStack;   /* 0x9b0: Stack_Free'd on free */
    int vendorObj;    /* 0x9b4: nearest group-9 shop manager */
    f32 unk9B8;       /* 0x9b8 */
    u8 pad9BC[8];
    f32 textTimer;    /* 0x9c4: gameTextShow 0x433 countdown */
    s16 playerMoney;  /* 0x9c8 */
    u8 pad9CA[2];
    s16 price;        /* 0x9cc */
    s16 unk9CE;       /* 0x9ce */
    s16 priceShown;   /* 0x9d0 */
    u8 unk9D2;        /* 0x9d2 */
    u8 pad9D3;
    u8 flags9D4;      /* 0x9d4: 2 purchased-event, 4 facing, 0x10 leave, 0x20 tick */
    u8 amount;        /* 0x9d5 */
    u8 opacity;       /* 0x9d6: copied to obj alpha */
    u8 pad9D7;
} ShopkeeperState;
STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);


extern undefined4 FUN_80006824();
extern double FUN_80006a38();
extern undefined4 FUN_80006ac8();
extern undefined4 FUN_80006acc();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006b74();
extern int FUN_80006b7c();
extern undefined4 FUN_80006bb4();
extern uint FUN_80006c00();
extern undefined4 FUN_80006c88();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_800176d0();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_8001792c();
extern undefined4 FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800632e8();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_80081028();
extern undefined4 FUN_80081030();
extern undefined4 FUN_80081038();
extern undefined4 FUN_800810f4();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern void dll_2E_func06();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8011eb38();
extern undefined4 FUN_801f4f9c();
extern undefined4 FUN_801f4fa0();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern int FUN_80286838();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined2 FUN_80294d20();
extern undefined4 FUN_80294d28();
extern uint countLeadingZeros();

extern undefined4 DAT_803adcc8;
extern ScreenTransitionInterface **gScreenTransitionInterface;
extern undefined4* DAT_803dd70c;
extern MapEventInterface **gMapEventInterface;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803de8d8;
extern undefined4* lbl_803DCAB4;
#define gBoneParticleEffectInterface lbl_803DCAB4
extern f64 DOUBLE_803e6698;
extern f64 DOUBLE_803e66f0;
extern f32 lbl_803DC074;
extern f32 lbl_803E59D8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E6670;
extern f32 lbl_803E6674;
extern f32 lbl_803E6688;
extern f32 lbl_803E66B8;
extern f32 lbl_803E66BC;
extern f32 lbl_803E66C0;
extern f32 lbl_803E66C8;
extern f32 lbl_803E66CC;
extern f32 lbl_803E66D0;
extern f32 lbl_803E66D4;
extern f32 lbl_803E66D8;
extern f32 lbl_803E66DC;
extern f32 lbl_803E66E0;
extern f32 lbl_803E66E4;
extern f32 lbl_803E66E8;
extern f32 lbl_803E66F8;
extern void **gTitleMenuControlInterfaceCopy;

/*
 * --INFO--
 *
 * Function: FUN_801e76a0
 * EN v1.0 Address: 0x801E76A0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E7714
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
undefined4 FUN_801e76a0(int param_1)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  uVar1 = GameBit_Get(0xcef);
  if (uVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar1 = GameBit_Get(0xad3);
    if (uVar1 == 0) {
      GameBit_Set(0xad3,1);
      iVar3 = *(int *)(iVar3 + 0x9b4);
      (**(code **)(**(int **)&((GameObject *)iVar3)->anim.dll + 0x24))(iVar3,1,2);
    }
    uVar2 = 2;
  }
  return uVar2;
}


/*
 * --INFO--
 *
 * Function: FUN_801e7be4
 * EN v1.0 Address: 0x801E7BE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E7C90
 * EN v1.1 Size: 1452b
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
 * Function: FUN_801e7be8
 * EN v1.0 Address: 0x801E7BE8
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801E823C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
void fn_801E7DC8(int p1, int p2, int count)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern void hitDetectFn_800658a4(int, int *, int, f32, f32, f32);
  extern int Obj_AllocObjectSetup(int, int);
  extern void Obj_SetupObject(int, int, int, int, int);
  extern MapEventInterface **gMapEventInterface;
  int i;
  int local;
  int o;

  if (Obj_IsLoadingLocked() == 0) return;

  (*gMapEventInterface)->setAnimEvent((s32)((GameObject *)p1)->anim.mapEventSlot, 6, 1);

  hitDetectFn_800658a4(p1, &local, 0, ((GameObject *)p1)->anim.localPosX, ((GameObject *)p1)->anim.localPosY, ((GameObject *)p1)->anim.localPosZ);

  for (i = 0; i < count; i++) {
    o = Obj_AllocObjectSetup(36, 1151);
    *(f32 *)(o + 8) = ((GameObject *)p1)->anim.localPosX;
    *(f32 *)(o + 12) = ((GameObject *)p1)->anim.localPosY;
    *(f32 *)(o + 16) = ((GameObject *)p1)->anim.localPosZ;
    *(u8 *)(o + 24) = (u8)(s8)randomGetRange(-128, 127);
    *(s16 *)(o + 26) = (s16)(s32)(((GameObject *)p1)->anim.localPosY - *(f32 *)&local);
    *(u8 *)(o + 5) = 1;
    *(u8 *)(o + 7) = 255;
    *(u8 *)(o + 4) = 16;
    *(u8 *)(o + 6) = 6;
    *(int *)(o + 20) = ((ShopkeeperState *)p2)->vendorObj;
    Obj_SetupObject(o, 5, ((GameObject *)p1)->anim.mapEventSlot, -1, *(int *)&((GameObject *)p1)->anim.parent);
  }

  for (i = 0; i < count; i++) {
    o = Obj_AllocObjectSetup(36, 1151);
    *(f32 *)(o + 8) = ((GameObject *)p1)->anim.localPosX;
    *(f32 *)(o + 12) = ((GameObject *)p1)->anim.localPosY;
    *(f32 *)(o + 16) = ((GameObject *)p1)->anim.localPosZ;
    *(u8 *)(o + 24) = (u8)(s8)randomGetRange(-128, 127);
    *(s16 *)(o + 26) = (s16)(s32)(((GameObject *)p1)->anim.localPosY - *(f32 *)&local);
    *(u8 *)(o + 5) = 1;
    *(u8 *)(o + 7) = 255;
    *(u8 *)(o + 4) = 16;
    *(u8 *)(o + 6) = 6;
    *(u8 *)(o + 25) = 1;
    *(int *)(o + 20) = ((ShopkeeperState *)p2)->vendorObj;
    Obj_SetupObject(o, 5, ((GameObject *)p1)->anim.mapEventSlot, -1, *(int *)&((GameObject *)p1)->anim.parent);
  }
}

/*
 * --INFO--
 *
 * Function: FUN_801e7d3c
 * EN v1.0 Address: 0x801E7D3C
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x801E83B8
 * EN v1.1 Size: 508b
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
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E7FEC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E85B4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Stack_Free();

#pragma scheduling off
#pragma peephole off
void shopkeeper_free(int param_1)
{
  Stack_Free(*(undefined4 *)(*(int *)&((GameObject *)param_1)->extra + 0x9b0));
  return;
}

/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E8014
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E85DC
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void shopkeeper_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    int iVar1 = *(int *)&((GameObject *)param_1)->extra;
    float local_18[4];
    local_18[0] = lbl_803E59D8;
    if (*(s16 *)(iVar1 + 0x274) != 7 && visible != 0) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (param_1, param_2, param_3, param_4, param_5, lbl_803E59D8);
        dll_2E_func06(param_1, iVar1 + 0x35c, 0);
    }
    if ((*(u8 *)(iVar1 + 0x9d4) & 0x20) != 0) {
        (*(void (*)(int, int, float *, int, int))(*(int *)(*gBoneParticleEffectInterface + 0xc)))(param_1, 0x7ef, local_18, 0x50, 0);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801e80b0
 * EN v1.0 Address: 0x801E80B0
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801E8680
 * EN v1.1 Size: 324b
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
 * Function: FUN_801e8274
 * EN v1.0 Address: 0x801E8274
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E87C4
 * EN v1.1 Size: 344b
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
 * Function: FUN_801e8300
 * EN v1.0 Address: 0x801E8300
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801E89A0
 * EN v1.1 Size: 688b
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
 * Function: FUN_801e85b0
 * EN v1.0 Address: 0x801E85B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E8CE4
 * EN v1.1 Size: 452b
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
 * Function: FUN_801e85b8
 * EN v1.0 Address: 0x801E85B8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801E8EA8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
int fn_801E86F4(int obj, int p2, ObjSeqState *seq)
{
  extern void fn_801E8660(int obj);
  extern void fn_801F4D54(int obj, int sub);
  extern void fn_801F4ECC(int obj, int sub);
  extern f32 Curve_EvalBSpline(int p, f32 t, int m);
  extern int getAngle(f32 a, f32 b);
  extern EffectInterface **gPartfxInterface;
  extern f32 lbl_803E5A30;
  extern f32 lbl_803E5A60;
  extern f32 timeDelta;
  int sub = *(int *)&((GameObject *)obj)->extra;
  ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;

  seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_801E8660;
  seq->flags &= ~4;
  seq->unk70 &= ~4;

  if ((int)objAnim->banks[objAnim->bankIndex] != 0) {
    ObjAnim_AdvanceCurrentMove(lbl_803E5A60, timeDelta, obj, NULL);
  }

  switch (((GameObject *)obj)->anim.seqId) {
  case 1127: {
    f32 t = ((ShopItemState *)sub)->splineT;
    if (t > lbl_803E5A30) {
      u32 v;
      ((ShopItemState *)sub)->splineT = t - lbl_803E5A30;
      v = ((ShopItemState *)sub)->segCounter;
      if (v >= 4) {
        ((ShopItemState *)sub)->segCounter += 1;
      } else {
        fn_801F4D54(obj, sub);
      }
      fn_801F4ECC(obj, sub);
    }
  }
  {
    ((GameObject *)obj)->anim.localPosX = Curve_EvalBSpline(sub + 4, ((ShopItemState *)sub)->splineT, 0);
    ((GameObject *)obj)->anim.localPosY = Curve_EvalBSpline(sub + 0x14, ((ShopItemState *)sub)->splineT, 0);
    ((GameObject *)obj)->anim.localPosZ = Curve_EvalBSpline(sub + 0x24, ((ShopItemState *)sub)->splineT, 0);
    ((ShopItemState *)sub)->splineT = ((ShopItemState *)sub)->splineSpeed * timeDelta + ((ShopItemState *)sub)->splineT;
    ((GameObject *)obj)->anim.rotX = (s16)getAngle(
        ((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX,
        ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ);
    (*gPartfxInterface)->spawnObject((void *)obj, 415, NULL, 1, -1,
                                                        NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 416, NULL, 1, -1,
                                                        NULL);
  }
  break;
  }
  return 0;
}



/* Trivial 4b 0-arg blr leaves. */
void shopkeeper_hitDetect(void) {}
void shopkeeper_release(void) {}
void shopitem_hitDetect(void) {}
void shopitem_release(void) {}
void shopitem_initialise(void) {}
void spscarab_render(void) {}
void spscarab_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int shopkeeper_getExtraSize(void) { return 0x9d8; }
int shopkeeper_getObjectTypeId(void) { return 0x0; }
int shopitem_getExtraSize(void) { return 0xec; }
int shopitem_getObjectTypeId(void) { return 0x0; }
int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_getObjectTypeId(void) { return 0x0; }

extern void Sfx_RemoveLoopedObjectSound(int x, int y);
void spscarab_free(int x) { Sfx_RemoveLoopedObjectSound(x, 0x406); }

extern f32 lbl_803E5A30;
extern void fn_801E83B0(int obj, int, int, int, int);

void shopitem_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        if (((GameObject *)obj)->anim.seqId == 0x468) {
            fn_801E83B0(obj, 0, 0, 0, 0);
        } else {
            objRenderFn_8003b8f4(lbl_803E5A30);
        }
    }
}

void shopitem_free(int obj) {
    (*gExpgfxInterface)->freeSource(obj);
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x468:
        ObjGroup_RemoveObject(obj, 0x4F);
        break;
    }
}

extern void *lbl_803AD068[8];
extern void *lbl_803DDC58;
extern void DRlaserturret_startLinkedTarget(int);
extern void DRlaserturret_updateTracking(int);
extern void DRlaserturret_updateIdle(int);
extern void TREX_Lazerwall_updateTimedChallenge(int);
extern void TREX_Lazerwall_waitForStartBit(int);
extern void TREX_Lazerwall_popQueuedState(int);
extern void fn_801E66EC(int);
extern void fn_801E66E4(int);
extern void fn_801E66DC(int);

extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 a, int b, u32 c);
extern void gxSetPeControl_ZCompLoc_(u32 a);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);

void fn_801E832C(int obj) {
    if (*(u8 *)(obj + 0x37) == 0xFF) {
        GXSetBlendMode(0, 1, 0, 5);
    } else {
        GXSetBlendMode(1, 4, 1, 5);
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void shopkeeper_initialise(void) {
    lbl_803AD068[0] = (void *)DRlaserturret_startLinkedTarget;
    lbl_803AD068[1] = (void *)DRlaserturret_updateTracking;
    lbl_803AD068[2] = (void *)DRlaserturret_updateIdle;
    lbl_803AD068[3] = (void *)TREX_Lazerwall_updateTimedChallenge;
    lbl_803AD068[4] = (void *)TREX_Lazerwall_waitForStartBit;
    lbl_803AD068[5] = (void *)TREX_Lazerwall_popQueuedState;
    lbl_803AD068[6] = (void *)fn_801E66EC;
    lbl_803AD068[7] = (void *)fn_801E66E4;
    lbl_803DDC58 = (void *)fn_801E66DC;
}

extern void hudFn_8011f38c(int);
extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803E5A20;
extern f32 timeDelta;
extern f32 lbl_803E59DC;
extern void gameTextShow(int);
extern u32 ObjGroup_FindNearestObject(int kind, int obj, f32 *out);
extern int playerGetMoney(void *player);
extern void characterDoEyeAnims(int obj, int p2);
extern void dll_2E_func03(int, int);
extern f32 shopKeeperRotateFn_801e7c4c(s16 *obj, void *player, int mode);
extern int *gPlayerInterface;

typedef struct {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 bit20 : 1;
    u8 bit10 : 1;
    u8 bit08 : 1;
    u8 bit04 : 1;
    u8 bit02 : 1;
    u8 bit01 : 1;
} BitsAt9D4;

void shopkeeper_update(int obj) {
    void *player;
    int state;
    f32 dist;
    player = Obj_GetPlayerObject();
    state = *(int *)&((GameObject *)obj)->extra;
    dist = lbl_803E5A20;
    ((ShopkeeperState *)state)->flags9D4 &= ~0x20;
    if (((ShopkeeperState *)state)->textTimer > lbl_803E59DC) {
        gameTextShow(0x433);
        ((ShopkeeperState *)state)->textTimer = ((ShopkeeperState *)state)->textTimer - timeDelta;
        if (((ShopkeeperState *)state)->textTimer < lbl_803E59DC) {
            ((ShopkeeperState *)state)->textTimer = *(f32 *)&lbl_803E59DC;
        }
    }
    if ((((ShopkeeperState *)state)->flags9D4 & 0x04) != 0) {
        shopKeeperRotateFn_801e7c4c((s16 *)obj, player, 1);
    }
    ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    if (*(void **)&((ShopkeeperState *)state)->vendorObj == NULL) {
        ((ShopkeeperState *)state)->vendorObj = ObjGroup_FindNearestObject(9, obj, &dist);
    }
    ((ShopkeeperState *)state)->playerMoney = (s16)playerGetMoney(player);
    ((void (*)(int, int, f32, f32, void *, void *))(*(int *)((int)*gPlayerInterface + 8)))
        (obj, state, timeDelta, timeDelta, lbl_803AD068, &lbl_803DDC58);
    dll_2E_func03(obj, state + 0x35C);
    characterDoEyeAnims(obj, state + 0x980);
    ((GameObject *)obj)->anim.alpha = ((ShopkeeperState *)state)->opacity;
}

extern f32 lbl_803E59F0;
extern f32 lbl_803E5A28;
extern void *allocModelStruct_800139e8(int, int);
extern void dll_2E_func05(int, int, int, int, int);
extern int fn_801E76A0(int obj, int p2, ObjSeqState *seq, s8 advance);
extern void *Obj_GetActiveModel(int);
extern void ObjModel_SetPostRenderCallback(void *, void *);
extern void ObjGroup_AddObject(int, int);
extern void fn_801F4C28(int, int);
extern EffectInterface **gPartfxInterface;

void shopitem_init(int obj, int data) {
    ObjAnimComponent *objAnim;
    int state = *(int *)&((GameObject *)obj)->extra;

    objAnim = (ObjAnimComponent *)obj;
    ((GameObject *)obj)->objectFlags |= 0x2000;
    ((GameObject *)obj)->animEventCallback = (void *)fn_801E86F4;
    objAnim->bankIndex = (s8)*(s8 *)(data + 0x18);
    *(s16 *)obj = (s16)((*(u8 *)(data + 0x1A)) << 8);
    ((GameObject *)obj)->anim.rotY = (s16)((*(u8 *)(data + 0x1B)) << 8);
    if ((s32)objAnim->bankIndex >= (s32)objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x467:
        fn_801F4C28(obj, state);
        break;
    case 0x462:
        (*gPartfxInterface)->spawnObject((void *)obj, 0x3F1, NULL, 4,
                                                            -1, NULL);
        break;
    case 0x468:
        ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), (void *)fn_801E832C);
        ObjGroup_AddObject(obj, 0x4F);
        break;
    }
}

void shopkeeper_init(int obj) {
    int state = *(int *)&((GameObject *)obj)->extra;
    ((GameObject *)obj)->objectFlags |= 0x2000;
    ((GameObject *)obj)->animEventCallback = (void *)fn_801E76A0;
    ((GameObject *)obj)->anim.modelState->flags |= 0x810;
    ((ShopkeeperState *)state)->unk9B8 = lbl_803E59F0 * (f32)(s32)randomGetRange(0xF, 0x23);
    ((ShopkeeperState *)state)->msgStack = allocModelStruct_800139e8(4, 4);
    ((ShopkeeperState *)state)->opacity = 0xFF;
    ((ShopkeeperState *)state)->textTimer = lbl_803E5A28;
    dll_2E_func05(obj, state + 0x35C, -0x1C71, 0x3555, 2);
    ((ShopkeeperState *)state)->unk96D |= 0x12;
}

typedef struct {
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartState97;



void fn_801E8660(int obj) {
    int state = *(int *)&((GameObject *)obj)->extra;
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    PushcartState97 *b = (PushcartState97 *)(state + 0x97);
    if (b->flag_40 == 0) {
        int *vptr = (int *)((ShopItemState *)state)->vendorObj;
        int *cls = **(int ***)((char *)vptr + 0x68);
        if ((*(int (*)(int *, int))cls[0x2C / 4])(vptr, *(u8 *)(def + 0x19)) != 0) {
            b->flag_80 = 1;
        }
    }
    hudFn_8011f38c(0);
    {
        int *vptr2 = (int *)((ShopItemState *)state)->vendorObj;
        int *cls2 = **(int ***)((char *)vptr2 + 0x68);
        (*(void (*)(int *, int))cls2[0x40 / 4])(vptr2, -1);
    }
}

extern f32 lbl_803E5A60;
extern f32 lbl_803E5A64;
extern f32 lbl_803E5A68;
extern void ObjMsg_SendToObject(void *to, int msg, int obj, void *data);
extern void forceAButtonIcon(int icon);
extern void showHelpText(int textId);
extern void buttonDisable(int a, int b);
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern void objRenderFn_80041018(int obj);
extern f32 Curve_EvalBSpline(int p, f32 t, int m);

void shopitem_update(int obj)
{
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    void *player = Obj_GetPlayerObject();
    int state = *(int *)&((GameObject *)obj)->extra;
    f32 range = lbl_803E5A64;
    PushcartState97 *b = (PushcartState97 *)(state + 0x97);
    int money;
    int price;

    if (b->flag_40) {
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x8000);
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else if (b->flag_80) {
        ((ShopitemState *)state)->unk88 = -1;
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x7000A, obj, (void *)(state + 0x88));
        b->flag_80 = 0;
        b->flag_40 = 1;
    } else {
        if (*(u32 *)&((ShopItemState *)state)->vendorObj == 0) {
            int item;
            ((ShopItemState *)state)->vendorObj = ObjGroup_FindNearestObject(9, obj, &range);
            item = ((ShopItemState *)state)->vendorObj;
            if ((u32)item != 0) {
                if ((*(int (**)(int, int))((char *)**(int ***)(item + 0x68) + 0x28))(item, ((ShopitemPlacement *)def)->unk19) == 0
                    || (*(int (**)(int, int))((char *)**(int ***)(((ShopItemState *)state)->vendorObj + 0x68) + 0x2C))(((ShopItemState *)state)->vendorObj, ((ShopitemPlacement *)def)->unk19) != 0) {
                    b->flag_40 = 1;
                    ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x8000);
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                }
                ((ShopItemState *)state)->helpTextId = (s16)(*(int (**)(int, int))((char *)**(int ***)(((ShopItemState *)state)->vendorObj + 0x68) + 0x3C))(((ShopItemState *)state)->vendorObj, ((ShopitemPlacement *)def)->unk19);
            }
        } else {
            if (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) {
                forceAButtonIcon(0x12);
                showHelpText(((ShopItemState *)state)->helpTextId);
            }
            if (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) {
                money = playerGetMoney(player);
                price = (*(int (**)(int, int))((char *)**(int ***)(((ShopItemState *)state)->vendorObj + 0x68) + 0x38))(((ShopItemState *)state)->vendorObj, ((ShopitemPlacement *)def)->unk19);
                (*(int (**)(int, int))((char *)**(int ***)(((ShopItemState *)state)->vendorObj + 0x68) + 0x40))(((ShopItemState *)state)->vendorObj, ((ShopitemPlacement *)def)->unk19);
                switch (((GameObject *)obj)->anim.seqId) {
                case 0x467:
                    ((GameObject *)obj)->anim.localPosY = lbl_803E5A68 + *(f32 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0xC);
                    break;
                }
                if (money >= price) {
                    hudFn_8011f38c(3);
                    (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
                } else {
                    (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
                }
                buttonDisable(0, 0x100);
            }
            switch (((GameObject *)obj)->anim.seqId) {
            case 0x467: {
                f32 t = ((ShopItemState *)state)->splineT;
                if (t > lbl_803E5A30) {
                    u32 v;
                    ((ShopItemState *)state)->splineT = t - lbl_803E5A30;
                    v = ((ShopItemState *)state)->segCounter;
                    if (v >= 4) {
                        ((ShopItemState *)state)->segCounter = v + 1;
                    } else {
                        fn_801F4D54(obj, state);
                    }
                    fn_801F4ECC(obj, state);
                }
                ((GameObject *)obj)->anim.localPosX = Curve_EvalBSpline(state + 4, ((ShopItemState *)state)->splineT, 0);
                ((GameObject *)obj)->anim.localPosY = Curve_EvalBSpline(state + 0x14, ((ShopItemState *)state)->splineT, 0);
                ((GameObject *)obj)->anim.localPosZ = Curve_EvalBSpline(state + 0x24, ((ShopItemState *)state)->splineT, 0);
                ((ShopItemState *)state)->splineT = ((ShopItemState *)state)->splineSpeed * timeDelta + ((ShopItemState *)state)->splineT;
                ((GameObject *)obj)->anim.rotX = (s16)getAngle(
                    ((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX,
                    ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ);
                (*gPartfxInterface)->spawnObject((void *)obj, 0x19F,
                                                                    NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void *)obj, 0x1A0,
                                                                    NULL, 1, -1, NULL);
                break;
            }
            }
        }
        if (((GameObject *)obj)->anim.seqId != 0x464 && ((GameObject *)obj)->anim.seqId != 0x467) {
            ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5A60, timeDelta, NULL);
        }
        if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 8) == 0) {
            objRenderFn_80041018(obj);
        }
    }
}

extern void DRlaserturret_startTimedChallenge(int);
extern void DRlaserturret_handlePromptChoice(int);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void warpToMap(int mapId, int flag);
extern int getCurUiDll(void);
extern int *getDLL16(void);
extern void playerAddMoney(void *player, int amount);
extern void *objFindTexture(int obj, int target, int p3);
extern int dll_2E_func07(int obj, u8 *data, int p3, int p4, int p5);

int fn_801E76A0(int obj, int p2, ObjSeqState *seq, s8 advance)
{
    int state;
    int state2;
    void *player;
    int slot;
    int i;
    int digit;
    int hundreds;
    int *tex;
    f32 range;
    f32 speed;

    state = state2 = *(int *)&((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    range = lbl_803E59D8;
    ((ShopkeeperState *)state)->flags9D4 &= ~0x20;
    if (((ShopkeeperState *)state)->flags9D4 & 0x10) {
        if ((*gScreenTransitionInterface)->isFinished() != 0) {
            (*gScreenTransitionInterface)->step(0x1E, 1);
            (*gObjectTriggerInterface)->endSequence((s8)seq->slot);
        }
        return 0;
    }
    if (dll_2E_func07(obj, (u8 *)seq, state + 0x35C, 0, 0) != 0) {
        return 1;
    }
    seq->freeCallback = (ObjAnimSequenceFreeCallback)DRlaserturret_startTimedChallenge;
    seq->flags &= ~0x20;
    speed = lbl_803E59DC;
    ((ShopkeeperState *)state2)->animSpeed = speed;
    ((ShopkeeperState *)state)->flags9D4 |= 4;
    if (advance != 0) {
        ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, speed, timeDelta, NULL);
    }
    if (((GameObject *)obj)->seqIndex == -1) {
        if ((s8)seq->movementState != 0) {
            slot = (*(int (**)(int))((char *)**(int ***)(((ShopkeeperState *)state)->vendorObj + 0x68) + 0x44))(((ShopkeeperState *)state)->vendorObj);
            if (slot != -1) {
                ((ShopkeeperState *)state)->price = (s16)(*(int (**)(int, int))((char *)**(int ***)(((ShopkeeperState *)state)->vendorObj + 0x68) + 0x38))(((ShopkeeperState *)state)->vendorObj, slot);
                ((ShopkeeperState *)state)->unk9CE = (s16)(*(int (**)(int, int))((char *)**(int ***)(((ShopkeeperState *)state)->vendorObj + 0x68) + 0x30))(((ShopkeeperState *)state)->vendorObj, slot);
                ((ShopkeeperState *)state)->priceShown = ((ShopkeeperState *)state)->price;
                ((ShopkeeperState *)state)->unk9D2 = 0;
                digit = ((ShopkeeperState *)state)->price;
                tex = (int *)objFindTexture(obj, 8, 0);
                *tex = (digit % 10) * 0x100;
                tex = (int *)objFindTexture(obj, 7, 0);
                *tex = ((digit / 10) % 10) * 0x100;
                hundreds = digit / 100;
                if (hundreds > 9) {
                    hundreds = 9;
                }
                tex = (int *)objFindTexture(obj, 6, 0);
                *tex = hundreds << 8;
            }
            seq->movementState = 0;
            seq->conditionCallback = (ObjAnimSequenceConditionCallback)DRlaserturret_handlePromptChoice;
        }
        if ((*(int (**)(int))((char *)**(int ***)(((ShopkeeperState *)state)->vendorObj + 0x68) + 0x44))(((ShopkeeperState *)state)->vendorObj) != -1) {
            setAButtonIcon(0x12);
            setBButtonIcon(0xA);
        }
    }
    for (i = 0; i < seq->eventCount; i++) {
        switch (seq->eventIds[i]) {
        case 1:
            fn_801E7DC8(obj, state, ((ShopkeeperState *)state)->amount);
            ((ShopkeeperState *)state)->flags9D4 |= 2;
            break;
        case 2:
            (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state2, 3);
            (*(void (**)(int, int, f32 *, int, int))(*(int *)lbl_803DCAB4 + 0xC))(obj, 0x7EF, &range, 0x50, 0);
            ((ShopkeeperState *)state)->opacity = 0;
            break;
        case 3:
            (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state2, 2);
            ((ShopkeeperState *)state)->flags9D4 |= 0x20;
            ((ShopkeeperState *)state)->opacity = 0xFF;
            break;
        case 4:
            if (((GameObject *)player)->anim.seqId == 0) {
                warpToMap(0xF, 0);
            } else {
                warpToMap(0xE, 0);
            }
            break;
        case 5:
            if (getCurUiDll() == 0x10) {
                tex = getDLL16();
                (*(void (**)(int))(*tex + 0x10))(0);
            }
            break;
        case 6:
            if (getCurUiDll() == 0x10) {
                tex = getDLL16();
                (*(void (**)(int))(*tex + 0x10))(2);
            }
            break;
        case 7:
            if (getCurUiDll() == 0x10) {
                tex = getDLL16();
                (*(void (**)(int))(*tex + 0x10))(4);
            }
            break;
        case 9:
            playerAddMoney(player, ((ShopkeeperState *)state)->amount);
            break;
        case 10:
            playerAddMoney(player, -(int)((ShopkeeperState *)state)->amount);
            break;
        case 0xB:
            (*(void (**)(int, int, f32 *, int, int))(*(int *)lbl_803DCAB4 + 0xC))(obj, 0x7EF, &range, 0x50, 0);
            break;
        case 0xC:
            ((ShopkeeperState *)state)->amount = 1;
            digit = ((ShopkeeperState *)state)->amount;
            tex = (int *)objFindTexture(obj, 8, 0);
            *tex = (digit % 10) * 0x100;
            tex = (int *)objFindTexture(obj, 7, 0);
            *tex = ((digit / 10) % 10) * 0x100;
            digit = digit / 100;
            if (digit > 9) {
                digit = 9;
            }
            tex = (int *)objFindTexture(obj, 6, 0);
            *tex = digit << 8;
            break;
        }
    }
    ((GameObject *)obj)->anim.alpha = ((ShopkeeperState *)state)->opacity;
    return 0;
}

extern f32 sqrtf(f32 x);
extern f32 lbl_803E5A24;

f32 shopKeeperRotateFn_801e7c4c(s16 *obj, void *player, int mode)
{
    f32 dist;
    f32 dx;
    f32 dz;
    u16 angle;
    int diff;

    dx = ((GameObject *)player)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
    dz = ((GameObject *)player)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist != lbl_803E59DC) {
        dx /= dist;
        dz /= dist;
    }
    if (dist > lbl_803E5A24) {
        angle = (u16)getAngle(dx, dz);
        if (mode != 0) {
            *obj = (s16)angle;
        } else {
            diff = angle - (u16)*obj;
            if (diff > 0x8000) {
                diff -= 0xFFFF;
            }
            if (diff < -0x8000) {
                diff += 0xFFFF;
            }
            if (diff > 0x2000) {
                diff -= 0x2000;
            } else if (diff < -0x2000) {
                diff += 0x2000;
            } else {
                diff = 0;
            }
            *obj = (s16)(int)((f32)(diff >> 3) * timeDelta + (f32)*obj);
        }
    }
    return dist;
}

extern f32 lbl_803E5A34;
extern f32 lbl_803E5A38;
extern f32 lbl_803E5A3C;
extern f32 lbl_803E5A40;
extern f32 lbl_803E5A44;
extern f32 lbl_803E5A48;
extern f32 lbl_803E5A4C;
extern f32 lbl_803E5A50;
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 radius, int c, int d, int e, f32 scale, int g, int h);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void lightningRender(void);
extern int getHudHiddenFrameCount(void);
extern void mm_free_(int p);
extern int lightningCreate(f32 *start, void *end, f32 a, f32 b, int c, int d, int e);

typedef struct ShopSparkleSpawn {
    f32 x;
    f32 y;
    f32 z;
    int owner;
    u8 pad[0x28];
} ShopSparkleSpawn;

typedef struct PushcartStateE8 {
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartStateE8;

void fn_801E83B0(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    u8 spawned = 0;
    ShopSparkleSpawn v;
    PushcartStateE8 *b = (PushcartStateE8 *)(state + 0xE8);
    u8 i;
    int slot;
    f32 scale;

    if (b->flag_40) {
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A30, 1, 1, 0x14, lbl_803E5A34, 0, 0);
    } else {
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A30, 1, 1, 0x14, lbl_803E5A38, 0, 0);
    }
    *(u8 *)(ObjModel_GetRenderOp(*(int *)Obj_GetActiveModel(obj), 0) + 0x43) = 0x7F;
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5A30);
    for (i = 0; i < 10; i++) {
        slot = state + i * 4;
        if (*(int *)(slot + 0x98) != 0) {
            lightningRender();
            if (getHudHiddenFrameCount() == 0) {
                *(f32 *)(slot + 0xC0) += timeDelta;
                *(u16 *)(*(int *)(slot + 0x98) + 0x20) = (u16)(int)(lbl_803E5A3C + *(f32 *)(slot + 0xC0));
                if (*(u16 *)(*(int *)(slot + 0x98) + 0x20) > 0x14) {
                    mm_free_(*(int *)(slot + 0x98));
                    *(int *)(slot + 0x98) = 0;
                }
            }
        } else {
            if (spawned == 0 && getHudHiddenFrameCount() == 0) {
                v.owner = obj;
                v.x = ((GameObject *)obj)->anim.localPosX;
                v.y = ((GameObject *)obj)->anim.localPosY;
                v.z = ((GameObject *)obj)->anim.localPosZ;
                if (v.owner == obj) {
                    if (b->flag_40) {
                        scale = lbl_803E5A40;
                    } else {
                        scale = lbl_803E5A44;
                    }
                    v.x = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.x;
                    v.y = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.y;
                    v.z = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.z;
                }
                *(int *)(slot + 0x98) = lightningCreate((f32 *)(obj + 0xC), &v, lbl_803E5A48, lbl_803E5A4C, 0x14, 0x40, 0);
                *(f32 *)(slot + 0xC0) = lbl_803E5A50;
                spawned = 1;
            }
        }
    }
}
