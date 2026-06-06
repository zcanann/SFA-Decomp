#include "main/dll/texframeanimator.h"
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICDUST family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */
#include "main/game_object.h"
#include "main/dll/collectible_state.h"
#include "main/objanim_internal.h"

extern uint GameBit_Get(int eventId);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjLink_DetachChild();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801713ac();
extern undefined8 FUN_801723dc();
extern undefined8 FUN_801726ac();
extern undefined4 FUN_80172974();
extern undefined4 FUN_80172b40();
extern uint countLeadingZeros();

extern undefined4 DAT_803218a8;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e40d8;
extern undefined4 DAT_803e40dc;
extern f64 DOUBLE_803e40e0;
extern f32 lbl_803DC074;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern f32 lbl_803E40F0;
extern f32 lbl_803E40F4;
extern f32 lbl_803E412C;
extern f32 lbl_803E4130;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern void *gPathControlInterface;
extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 lbl_803E345C;
extern f32 lbl_803E3494;
extern f32 lbl_803E3498;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;

/*
 * --INFO--
 *
 * Function: collectible_init
 * EN v1.0 Address: 0x80172F14
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801730D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void collectible_init(int obj,int setup)
{
  ObjAnimComponent *objAnim;
  u8 *state;
  int setupObj;
  int setupModelIndex;
  u8 *data;
  u32 pathWord;
  u8 pathByte;

  objAnim = (ObjAnimComponent *)obj;
  state = ((GameObject *)obj)->extra;
  pathWord = lbl_803E3440;
  pathByte = lbl_803E3444;
  ObjGroup_AddObject(obj,4);
  ObjMsg_AllocQueue(obj,2);
  ((GameObject *)obj)->anim.rotX = (s16)((u8)*(u8 *)(setup + 0x1b) << 8);
  ((GameObject *)obj)->anim.rotY = (s16)((u8)*(u8 *)(setup + 0x22) << 8);
  ((GameObject *)obj)->anim.rotZ = (s16)((u8)*(u8 *)(setup + 0x23) << 8);
  setupObj = (int)objAnim->modelInstance;
  ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(setupObj + 4);
  ((GameObject *)obj)->animEventCallback = (void *)collectible_SeqFn;
  setupModelIndex = *(s8 *)(setup + 0x26);
  objAnim->bankIndex = (s8)setupModelIndex;
  if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
    objAnim->bankIndex = 0;
  }
  ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x2000;
  ((CollectibleState *)state)->unkC = *(u8 *)(setup + 0x19);
  ((CollectibleState *)state)->unkD = *(u8 *)(setup + 0x1a);
  ((CollectibleState *)state)->unkF = 0;
  *(s32 *)(state + 0x18) = -2;
  ((CollectibleState *)state)->unk1D = 0;
  ((CollectibleState *)state)->unk14 = *(s16 *)(setup + 0x24);
  *(s32 *)(state + 0x20) = *(s32 *)(setup + 0x14);
  ((CollectibleState *)state)->basePosX = ((GameObject *)obj)->anim.localPosX;
  ((CollectibleState *)state)->basePosY = ((GameObject *)obj)->anim.localPosY;
  ((CollectibleState *)state)->basePosZ = ((GameObject *)obj)->anim.localPosZ;
  ((CollectibleState *)state)->unk36 = *(u8 *)(setup + 0x27);
  ((CollectibleState *)state)->unk3E = 0;
  if (((CollectibleState *)state)->unk14 != -1) {
    ((CollectibleState *)state)->unk1E = (u8)((u32)__cntlzw(GameBit_Get(((CollectibleState *)state)->unk14)) >> 5);
  }
  ((CollectibleState *)state)->hideGameBit = *(s16 *)(setup + 0x1c);
  if (((CollectibleState *)state)->hideGameBit != -1) {
    *(u32 *)&((GameObject *)obj)->unkF4 = GameBit_Get(((CollectibleState *)state)->hideGameBit);
  } else {
    *(u32 *)&((GameObject *)obj)->unkF4 = 0;
  }
  if (((GameObject *)obj)->unkF4 == 0) {
    data = *(u8 **)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x18);
    if (data != 0) {
      ((CollectibleState *)state)->unk4 = (f32)*(s8 *)(data + 8);
    } else {
      ((CollectibleState *)state)->unk4 = lbl_803E3494;
    }
    data = *(u8 **)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x40);
    if (data != 0) {
      ((CollectibleState *)state)->unk4 = (f32)(s32)(*(u8 *)(data + 0xc) << 2);
    }
    if (((((ObjAnimComponent *)obj)->modelInstance->flags & 0x10000) != 0) &&
        (((CollectibleState *)state)->unk36 != 0)) {
      ((CollectibleState *)state)->unk38 = *(u8 *)(setup + 0x28);
      ((CollectibleState *)state)->unk39 = *(u8 *)(setup + 0x29);
      ((CollectibleState *)state)->unk3A = *(u8 *)(setup + 0x2a);
    }
    switch (((GameObject *)obj)->anim.seqId) {
      case 0xb:
        ((CollectibleState *)state)->unk40 = lbl_803E345C;
        ((CollectibleState *)state)->unk44 = lbl_803E3498;
        break;
      case 0x3cd:
        ((CollectibleState *)state)->unk40 = lbl_803E349C;
        ((CollectibleState *)state)->unk44 = lbl_803E3498;
        break;
      default:
        ((CollectibleState *)state)->unk40 = lbl_803E34A0;
        break;
    }
    (*(void (**)(u8 *,int,int,int))(*(int *)gPathControlInterface + 4))(state + 0x50,0,0x40006,1);
    (*(void (**)(u8 *,int,u8 *,u32 *,u8 *))(*(int *)gPathControlInterface + 0xc))
        (state + 0x50,1,lbl_80320C58,&pathWord,&pathByte);
    (*(void (**)(int,u8 *))(*(int *)gPathControlInterface + 0x20))(obj,state + 0x50);
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80173364
 * EN v1.0 Address: 0x80173364
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801733C0
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173364(short *param_1,int param_2)
{
}

extern void *gExpgfxInterface;

#pragma scheduling off
#pragma peephole off
void magicdust_free(int param_1)
{
  if (*(uint *)(param_1 + 0xc4) != 0) {
    ObjLink_DetachChild(*(int *)(param_1 + 0xc4), param_1);
  }
  (*(void (***)(int))gExpgfxInterface)[6](param_1);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801733c0
 * EN v1.0 Address: 0x801733C0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017372C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801733c0(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: collectible_release
 * EN v1.0 Address: 0x8017321C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80173378
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_release(void)
{
}

/*
 * --INFO--
 *
 * Function: collectible_initialise
 * EN v1.0 Address: 0x80173220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017337C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int magicdust_getExtraSize(void) { return 0x288; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E34B0;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void magicdust_render(void) { objRenderFn_8003b8f4(lbl_803E34B0); }
#pragma peephole reset
#pragma scheduling reset
