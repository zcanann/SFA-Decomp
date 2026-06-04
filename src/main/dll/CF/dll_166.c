#include "ghidra_import.h"
#include "main/dll/CF/dll_166.h"
#include "main/objanim.h"
#include "main/objhits.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void *Obj_GetPlayerObject(void);
extern void ObjHits_DisableObject(int obj);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *maxDistance);
extern void fn_802967E0(void *obj, int enabled);
extern int *gObjectTriggerInterface;
extern int *Resource_Acquire(int id, int flags);
extern void Music_Trigger(s32 triggerId, s32 mode);

extern undefined4 DAT_802c22b0;
extern undefined4 DAT_802c22b4;
extern undefined4 DAT_802c22b8;
extern undefined4 DAT_802c22bc;
extern int *lbl_803DDAE0;
extern int lbl_803DDAE4;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3C20;
extern f32 lbl_803E3C28;
extern f32 lbl_803E3C2C;

/*
 * --INFO--
 *
 * Function: treasurechest_update
 * EN v1.0 Address: 0x8018AA60
 * EN v1.0 Size: 632b
 * EN v1.1 Address: 0x8018AA94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_update(int obj)
{
  void *uVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int hitObject;
  int local_44;
  uint hitVolume;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float hitPosY;
  float local_14 [2];

  pbVar4 = *(byte **)(obj + 0xb8);
  iVar3 = *(int *)(obj + 0x4c);
  local_3c = lbl_803E3C28;
  if (((*pbVar4 >> 6 & 1) != 0) && ((char)*pbVar4 < '\0')) {
    *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
    ObjAnim_SetCurrentMove(obj,0,lbl_803E3C2C,0);
  }
  if (-1 < (char)*pbVar4) {
    if ((*(byte *)(obj + 0xaf) & 1) != 0) {
      *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
      uVar1 = Obj_GetPlayerObject();
      fn_802967E0(uVar1,1);
      iVar2 = ObjGroup_FindNearestObject(4,obj,&local_3c);
      if (iVar2 == 0) {
        (**(code **)(*gObjectTriggerInterface + 0x7c))((int)*(short *)(iVar3 + 0x1a),0,0);
        (**(code **)(*gObjectTriggerInterface + 0x48))(0,obj,0xffffffff);
      }
      else {
        (**(code **)(*gObjectTriggerInterface + 0x7c))((int)*(short *)(iVar2 + 0x46),0,0);
        (**(code **)(*gObjectTriggerInterface + 0x48))(1,obj,0xffffffff);
      }
      GameBit_Set((int)*(short *)(iVar3 + 0x1e),1);
      *pbVar4 = *pbVar4 & 0x7f | 0x80;
      ObjHits_DisableObject(obj);
    }
    *pbVar4 = *pbVar4 & 0xbf;
    local_38 = DAT_802c22b0;
    local_34 = DAT_802c22b4;
    local_30 = DAT_802c22b8;
    local_2c = DAT_802c22bc;
    local_44 = 0xffffffff;
    iVar3 = ObjHits_GetPriorityHitWithPosition(obj,&hitObject,&local_44,
                                               &hitVolume,&local_1c,&hitPosY,
                                               local_14);
    if ((iVar3 != 0) && (iVar3 != 0xe)) {
      local_1c = local_1c + playerMapOffsetX;
      local_14[0] = local_14[0] + playerMapOffsetZ;
      local_20 = lbl_803E3C20;
      local_24 = 0;
      local_26 = 0;
      local_28 = 0;
      if (lbl_803DDAE4 == 0) {
        (**(code **)(*lbl_803DDAE0 + 4))(0,1,&local_28,0x401,0xffffffff,&local_38);
        lbl_803DDAE4 = 0x3c;
      }
    }
    if (lbl_803DDAE4 != 0) {
      lbl_803DDAE4 = lbl_803DDAE4 + -1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: treasurechest_release
 * EN v1.0 Address: 0x8018ADB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AF9C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_release(void)
{
}

/*
 * --INFO--
 *
 * Function: treasurechest_initialise
 * EN v1.0 Address: 0x8018ADB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AFA0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: magiccavebottom_getExtraSize
 * EN v1.0 Address: 0x8018ADBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018AFA4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int magiccavebottom_getExtraSize(void)
{
  return 1;
}

#pragma scheduling off
void magiccavebottom_free(int obj) {
    (void)obj;
    GameBit_Set(0xefb, 0);
    Music_Trigger(0x2f, 0);
}
#pragma scheduling reset

extern int treasurechest_SeqFn(int obj, int unused, u8 *events);
#pragma scheduling off
#pragma peephole off
void treasurechest_init(int *obj) {
    register u8 *state = *(u8 **)((char *)obj + 0xb8);
    register int *cfg = *(int **)((char *)obj + 0x4c);
    register u32 b;

    *(int (**)(int, int, u8 *))((char *)obj + 0xbc) = treasurechest_SeqFn;
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)cfg + 0x18) << 8);

    if (*(s16 *)((char *)cfg + 0x1e) != -1) {
        b = (u32)(u8)GameBit_Get(*(s16 *)((char *)cfg + 0x1e));
        *state = (u8)((*state & ~0x80) | ((b & 1) << 7));
    } else {
        *state &= ~0x80;
    }
    if (((u32)*state >> 7) & 1) {
        *(s16 *)((char *)obj + 6) = (s16)(*(s16 *)((char *)obj + 6) | 0x4000);
        ObjHits_DisableObject((int)obj);
    }
    lbl_803DDAE0 = Resource_Acquire(90, 1);
    *state |= 0x40;
}
#pragma peephole reset
#pragma scheduling reset
