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

typedef struct ChestHitParams {
  u32 a;
  u32 b;
  u32 c;
  u32 d;
} ChestHitParams;

typedef struct ChestFlags {
  u8 open : 1;
  u8 trigger : 1;
} ChestFlags;

typedef struct ChestHitBlock {
  ChestHitParams params;
  u16 a;
  u16 b;
  u16 c;
  f32 scale;
  f32 x;
  f32 y;
  f32 z[2];
} ChestHitBlock;

extern ChestHitParams lbl_802C22B0;
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
#pragma peephole off
#pragma scheduling off
void treasurechest_update(int obj)
{
  ChestFlags *flags;
  int setup;
  uint iVar2;
  int iVar3;
  ChestHitBlock blk;
  float local_3c;
  uint hitVolume;
  int local_44;
  int hitObject;

  flags = *(ChestFlags **)(obj + 0xb8);
  setup = *(int *)(obj + 0x4c);
  local_3c = lbl_803E3C28;
  if (flags->trigger != 0 && flags->open != 0) {
    *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
    ObjAnim_SetCurrentMove(obj,0,lbl_803E3C2C,0);
  }
  if (flags->open == 0) {
    if ((*(byte *)(obj + 0xaf) & 1) != 0) {
      *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
      fn_802967E0(Obj_GetPlayerObject(),1);
      iVar2 = ObjGroup_FindNearestObject(4,obj,&local_3c);
      if (iVar2 != 0) {
        (*(void (**)(int,int,int))(*gObjectTriggerInterface + 0x7c))((int)*(short *)(iVar2 + 0x46),0,0);
        (*(void (**)(int,int,int))(*gObjectTriggerInterface + 0x48))(1,obj,0xffffffff);
      }
      else {
        (*(void (**)(int,int,int))(*gObjectTriggerInterface + 0x7c))((int)*(short *)(setup + 0x1a),0,0);
        (*(void (**)(int,int,int))(*gObjectTriggerInterface + 0x48))(0,obj,0xffffffff);
      }
      GameBit_Set((int)*(short *)(setup + 0x1e),1);
      flags->open = 1;
      ObjHits_DisableObject(obj);
    }
    flags->trigger = 0;
    blk.params = lbl_802C22B0;
    local_44 = 0xffffffff;
    iVar3 = ObjHits_GetPriorityHitWithPosition(obj,&hitObject,&local_44,
                                               &hitVolume,&blk.x,&blk.y,
                                               blk.z);
    if ((iVar3 != 0) && (iVar3 != 0xe)) {
      blk.x = blk.x + playerMapOffsetX;
      blk.z[0] = blk.z[0] + playerMapOffsetZ;
      blk.scale = lbl_803E3C20;
      blk.c = 0;
      blk.b = 0;
      blk.a = 0;
      if (lbl_803DDAE4 == 0) {
        (*(void (**)(int,int,u16 *,int,int,ChestHitParams *))(*lbl_803DDAE0 + 4))
            (0,1,&blk.a,0x401,0xffffffff,&blk.params);
        lbl_803DDAE4 = 0x3c;
      }
    }
    if (lbl_803DDAE4 != 0) {
      lbl_803DDAE4 = lbl_803DDAE4 + -1;
    }
  }
  return;
}
#pragma scheduling reset
#pragma peephole reset

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
    register ChestFlags *state = *(ChestFlags **)((char *)obj + 0xb8);
    register int *cfg = *(int **)((char *)obj + 0x4c);

    *(int (**)(int, int, u8 *))((char *)obj + 0xbc) = treasurechest_SeqFn;
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)cfg + 0x18) << 8);

    if (*(s16 *)((char *)cfg + 0x1e) != -1) {
        state->open = (u8)GameBit_Get(*(s16 *)((char *)cfg + 0x1e));
    } else {
        state->open = 0;
    }
    if (state->open != 0) {
        *(s16 *)((char *)obj + 6) = (s16)(*(s16 *)((char *)obj + 6) | 0x4000);
        ObjHits_DisableObject((int)obj);
    }
    lbl_803DDAE0 = Resource_Acquire(90, 1);
    state->trigger = 1;
}
#pragma peephole reset
#pragma scheduling reset
