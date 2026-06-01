#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"
#include "main/dll/SH/SHspore.h"
#include "main/objanim.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern void* FUN_80017624();
extern undefined4 FUN_80017680();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern int randomGetRange(int min, int max);
extern undefined4 FUN_80017a6c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjMsg_AllocQueue();
extern int ObjTrigger_IsSetById();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b444();
extern undefined4 FUN_800400b0();
extern void *Obj_GetPlayerObject(void);
extern f32 getXZDistance(f32 *a, f32 *b);
extern int fn_8003B500(void *obj, void *p2, f32 f1);
extern int fn_8003B228(void *obj, void *p2);
extern int characterDoEyeAnims(void *obj, void *p2);
extern void fn_8002B6D8(void *obj, int arg1, int arg2, int arg3, int arg4, int arg5);
extern int cMenuGetSelectedItem(void);
extern int getYButtonItem(s16 *outTrigger);
extern void *getTrickyObject(void);
extern int playerHasSpell(void *obj, int param);
extern void *ObjGroup_FindNearestObject(int group, void *obj, f32 *distanceOut);
extern int ObjTrigger_IsSet(void *obj);
extern int RandomTimer_UpdateRangeTrigger(f32 *state, f32 min, f32 max);
extern void Sfx_PlayFromObject(void *obj, int sfxId);
extern short FUN_8011e824();
extern int FUN_8012efc4();
extern uint FUN_80294cc4();

extern undefined4 DAT_803279d8;
extern undefined4 DAT_803dcc28;
extern undefined4 DAT_803dcc38;
extern undefined4 DAT_803dcc40;
extern undefined4 DAT_803dcc44;
extern undefined4 DAT_803dcc54;
extern void *gObjectTriggerInterface;
extern void *gMapEventInterface;
extern u8 lbl_803DBFC8;
extern u8 lbl_803DBFCC;
extern u8 lbl_803DBFD0;
extern u8 lbl_803DBFD4;
extern u8 lbl_803DBFD8;
extern u8 lbl_803DBFDC;
extern u8 lbl_803DBFE0;
extern u8 lbl_803DBFE4;
extern u8 lbl_803DBFE8;
extern u8 lbl_803DBFEC;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern f32 timeDelta;
extern f64 DOUBLE_803e6038;
extern s16 lbl_80326E18[];
extern f32 lbl_80326E24[];
extern f32 lbl_803E53F8;
extern f32 lbl_803E53FC;
extern f32 lbl_803E5400;
extern f32 lbl_803E5404;
extern f32 lbl_803E5408;
extern f32 lbl_803E6020;
extern f32 lbl_803E6024;
extern f32 lbl_803E6028;
extern f32 lbl_803E6088;
extern f32 lbl_803E608C;
extern f32 lbl_803E6094;
extern f32 lbl_803E6098;

/*
 * --INFO--
 *
 * Function: sh_queenearthwalker_getExtraSize
 * EN v1.0 Address: 0x801D4794
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_queenearthwalker_getExtraSize(void)
{
  return 0x40;
}

#pragma peephole off
#pragma scheduling off
void sh_queenearthwalker_update(void *obj)
{
  void *state;
  void *player;
  void *target;
  u8 action;
  s8 actionParam;
  u8 stateFlags;
  u8 eventIndex;
  s16 currentMove;
  s16 targetMove;

  state = *(void **)((u8 *)obj + 0xb8);
  *(u8 *)((u8 *)state + 0x2) &= ~0x20;
  actionParam = *(s8 *)((u8 *)obj + 0xac);
  action = (*(u8 (***)(s8))gMapEventInterface)[0x10](actionParam);

  if ((*(u8 *)((u8 *)state + 0x2) & 0x1) != 0) {
    switch (action) {
      case 0:
        queenFeedFn_801d44a4(obj, state);
        break;
      case 1:
        if (GameBit_Get(0x193) != 0) {
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFEC;
        } else {
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFD4;
        }
        player = Obj_GetPlayerObject();
        *(u8 *)((u8 *)state + 0x8) = 1;
        *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)player + 0xc);
        *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)player + 0x10);
        *(f32 *)((u8 *)state + 0x14) = *(f32 *)((u8 *)player + 0x14);
        fn_8003B500(obj, (u8 *)state + 0x8, lbl_803E53F8);
        break;
      case 2:
        openPortalFn_801d4364(obj, state);
        break;
      case 3:
        if (GameBit_Get(0x13f) != 0) {
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFEC;
        } else {
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFE0;
        }
        player = Obj_GetPlayerObject();
        *(u8 *)((u8 *)state + 0x8) = 1;
        *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)player + 0xc);
        *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)player + 0x10);
        *(f32 *)((u8 *)state + 0x14) = *(f32 *)((u8 *)player + 0x14);
        fn_8003B500(obj, (u8 *)state + 0x8, lbl_803E53F8);
        break;
      case 4:
        if (GameBit_Get(0x199) != 0) {
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFEC;
        } else {
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFE4;
        }
        player = Obj_GetPlayerObject();
        *(u8 *)((u8 *)state + 0x8) = 1;
        *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)player + 0xc);
        *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)player + 0x10);
        *(f32 *)((u8 *)state + 0x14) = *(f32 *)((u8 *)player + 0x14);
        fn_8003B500(obj, (u8 *)state + 0x8, lbl_803E53F8);
        break;
      case 5:
        player = Obj_GetPlayerObject();
        *(u8 *)((u8 *)state + 0x8) = 1;
        *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)player + 0xc);
        *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)player + 0x10);
        *(f32 *)((u8 *)state + 0x14) = *(f32 *)((u8 *)player + 0x14);
        fn_8003B500(obj, (u8 *)state + 0x8, lbl_803E53F8);
        break;
      case 6:
      case 7:
      case 8:
        break;
      default:
        break;
    }
  } else {
    switch (action) {
      case 1:
        target = ObjGroup_FindNearestObject(0xf, obj, NULL);
        (*(void (***)(void *, int))gObjectTriggerInterface)[0x15](target, 0x1324);
        (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](1, target, 0x10);
        *(u8 *)((u8 *)state + 0x2) |= 0xc;
        *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFC8;
        break;
      case 2:
        if (GameBit_Get(0xc2) == 6) {
          (*(void (***)(void *, int))gObjectTriggerInterface)[0x15](obj, 0x18f6);
          (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](6, obj, 1);
          *(u8 *)state = 3;
        } else {
          if (GameBit_Get(0xbf) != 0) {
            *(u8 *)state = 1;
          }
          *(u8 *)((u8 *)state + 0x2) |= 0xc;
          *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFCC;
        }
        break;
      case 3:
      case 4:
        (*(void (***)(void *, int))gObjectTriggerInterface)[0x15](obj, 0x18f6);
        (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](6, obj, 1);
        *(u8 *)state = 3;
        break;
      case 8:
        target = ObjGroup_FindNearestObject(0xf, obj, NULL);
        (*(void (***)(void *, int))gObjectTriggerInterface)[0x15](target, 0x6a4);
        (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](7, target, 8);
        *(u8 *)state = 4;
        *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFE8;
        break;
      default:
        break;
    }
    *(u8 *)((u8 *)state + 0x2) |= 0x1;
    return;
  }

  if ((*(u8 *)((u8 *)state + 0x2) & 0x8) != 0) {
    fn_8003B228(obj, (u8 *)state + 0x8);
  } else {
    characterDoEyeAnims(obj, (u8 *)state + 0x8);
  }

  currentMove = *(s16 *)((u8 *)obj + 0xa0);
  targetMove = lbl_80326E18[*(u8 *)state];
  if (currentMove != targetMove) {
    ObjAnim_SetCurrentMove((int)obj, targetMove, lbl_803E53F8, 0);
  }
  ObjAnim_AdvanceCurrentMove(lbl_80326E24[*(u8 *)state], timeDelta, (int)obj, NULL);

  stateFlags = *(u8 *)((u8 *)state + 0x2);
  if ((stateFlags & 0x10) == 0) {
    *(u8 *)((u8 *)state + 0x2) &= ~0x2;
    if (ObjTrigger_IsSet(obj) != 0 && *(u8 *)(*(int *)((u8 *)obj + 0x78) + 0x4) != 4) {
      eventIndex = (u8)randomGetRange(1, **(u8 **)((u8 *)state + 0x38));
      *(u8 *)((u8 *)state + 0x2) |= 0x2;
      (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](
          ((u8 *)*(u8 **)((u8 *)state + 0x38))[eventIndex], obj, -1);
    }
  }

  if (RandomTimer_UpdateRangeTrigger((f32 *)((u8 *)state + 0x3c), lbl_803E5404,
                                     lbl_803E5408) != 0) {
    Sfx_PlayFromObject(obj, 0x410);
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void queenFeedFn_801d44a4(void *obj, void *state)
{
  s16 triggerId;
  s32 total;
  void *tricky;
  void *player;

  switch (*(u8 *)state) {
    case 0:
      if (GameBit_Get(0xbf) != 0) {
        (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](1, obj, -1);
        *(u8 *)state = 1;
      }
      break;
    case 1:
      *(u8 *)((u8 *)obj + 0xaf) &= ~0x8;
      if (cMenuGetSelectedItem() == -1) {
        if (getYButtonItem(&triggerId) == 0 || triggerId != 0x66d) {
          tricky = getTrickyObject();
          if (tricky != NULL &&
              getXZDistance((f32 *)((u8 *)tricky + 0x18), (f32 *)((u8 *)obj + 0x18)) <
                  lbl_803E5400) {
            fn_8002B6D8(obj, 0, 0, 0, 0, 2);
          } else {
            *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
          }
          break;
        }
      }
      fn_8002B6D8(obj, 0, 0, 0, 0, 4);
      if (ObjTrigger_IsSetById(obj, 0x66d) != 0) {
        *(u8 *)((u8 *)state + 0x2) |= 0x10;
        total = GameBit_Get(0x66d);
        total += GameBit_Get(0xc2);
        GameBit_Set(0x66d, 0);
        GameBit_Set(0xc2, total);
        if (total != 6) {
          *(u8 *)((u8 *)state + 0x2) |= 0x2;
          if (randomGetRange(0, 1) != 0) {
            (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](3, obj, -1);
          } else {
            (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](4, obj, -1);
          }
        } else {
          (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](5, obj, -1);
          *(u8 *)state = 2;
        }
      }
      break;
    case 2:
      (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12](6, obj, -1);
      GameBit_Set(0x9e, 1);
      *(u8 *)state = 3;
      break;
    case 3:
      fn_8002B6D8(obj, 0, 0, 0, 0, 2);
      *(u8 *)((u8 *)state + 0x2) &= ~0x4;
      *(u8 *)((u8 *)state + 0x2) &= ~0x8;
      *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFD0;
      player = Obj_GetPlayerObject();
      *(u8 *)((u8 *)state + 0x8) = 1;
      *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)player + 0xc);
      *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)player + 0x10);
      *(f32 *)((u8 *)state + 0x14) = *(f32 *)((u8 *)player + 0x14);
      fn_8003B500(obj, (void *)((int)state + 0x8), lbl_803E53F8);
      break;
    default:
      break;
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void openPortalFn_801d4364(void *obj, void *state)
{
  void *player;

  player = Obj_GetPlayerObject();
  *(u8 *)((u8 *)obj + 0xaf) &= ~0x8;
  if (GameBit_Get(0xc48) != 0) {
    *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFEC;
  } else if (GameBit_Get(0x23c) != 0) {
    *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFDC;
  } else if (GameBit_Get(0x5bd) != 0) {
    *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
    if (playerHasSpell(player, 3) != 0 &&
        getXZDistance((f32 *)((u8 *)player + 0x18), (f32 *)((u8 *)obj + 0x18)) < lbl_803E53FC) {
      GameBit_Set(0x23b, 1);
    }
  } else if (GameBit_Get(0xa31) != 0) {
    *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFEC;
  } else {
    *(u8 **)((u8 *)state + 0x38) = &lbl_803DBFD8;
  }

  player = Obj_GetPlayerObject();
  *(u8 *)((u8 *)state + 0x8) = 1;
  *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)player + 0xc);
  *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)player + 0x10);
  *(f32 *)((u8 *)state + 0x14) = *(f32 *)((u8 *)player + 0x14);
  fn_8003B500(obj, (void *)((int)state + 0x8), lbl_803E53F8);
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void sh_queenearthwalker_init(void *obj, QueenEarthWalkerMapData *mapData)
{
  *(s16 *)obj = (s16)(mapData->yawByte << 8);
  *(int *)((u8 *)obj + 0xbc) = (int)sh_queenearthwalker_processAnimEvents;
  *(u16 *)((u8 *)obj + 0xb0) |= 0x4000;
}
#pragma peephole reset
#pragma scheduling reset
