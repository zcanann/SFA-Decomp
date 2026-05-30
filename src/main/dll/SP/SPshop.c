#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/SP/SPshop.h"

extern undefined4 FUN_800067c0();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d8;
extern int *gGameUIInterface;
extern int *gScreenTransitionInterface;
extern int *gObjectTriggerInterface;
extern s16 lbl_80327618[];
extern char sSPShopNumBloopsFormat[];
extern f32 lbl_803E54B0;
extern f32 lbl_803E54B4;
extern f32 timeDelta;
extern f64 lbl_803E54B8;

extern void *Obj_GetPlayerObject(void);
extern void fn_80137948(char *fmt, ...);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void SCGameBitLatch_Update(int state, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int setBit, int textId);

extern MapEventInterface **gMapEventInterface;

/*
 * --INFO--
 *
 * Function: SH_LevelControl_runBloopEvent
 * EN v1.0 Address: 0x801D8308
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x801D84C4
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SH_LevelControl_runBloopEvent(int obj, int state)
{
  int player;
  u8 i;
  u8 bloopsRemaining;

  if (((*gMapEventInterface)->getAnimEvent((s8)*(u8 *)(obj + 0xac), 0) == 0) &&
      (GameBit_Get(0x13f) == 0)) {
    *(u8 *)(state + 6) = 0;
    (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x64)))(*gGameUIInterface);
    for (i = 0; i < 0x12; i++) {
      GameBit_Set(lbl_80327618[i], 0);
    }
  }

  player = (int)Obj_GetPlayerObject();
  switch (*(u8 *)(state + 6)) {
  case 0:
    if (GameBit_Get(0x13f) != 0) {
      *(u8 *)(state + 6) = 7;
    } else {
      *(u8 *)(state + 6) = 1;
    }
    break;
  case 1:
    if (GameBit_Get(0x124) != 0) {
      (*gMapEventInterface)->triggerEvent(player + 0xc, *(s16 *)player, 1, 0);
      *(f32 *)(state + 8) = lbl_803E54B0;
      (*(void (*)(int, int))(*(int *)(*gGameUIInterface + 0x58)))(100000, 0x5db);
      *(u8 *)(state + 6) = 2;
    }
    break;
  case 2:
    bloopsRemaining = 0x12;
    for (i = 0; i < 0x12; i++) {
      if (GameBit_Get(lbl_80327618[i]) != 0) {
        bloopsRemaining--;
      }
    }
    fn_80137948(sSPShopNumBloopsFormat, bloopsRemaining);
    if (bloopsRemaining == 0) {
      (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x64)))(*gGameUIInterface);
      (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 8)))(0x14, 1);
      *(u8 *)(state + 6) = 3;
      Sfx_PlayFromObject(0, 0x7e);
    } else {
      *(f32 *)(state + 8) -= (f32)bloopsRemaining * timeDelta;
      if (*(f32 *)(state + 8) >= lbl_803E54B4) {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))((int)*(f32 *)(state + 8));
      } else if ((*gMapEventInterface)->getAnimEvent((s8)*(u8 *)(obj + 0xac), 0) == 0) {
        *(f32 *)(state + 8) = lbl_803E54B4;
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(1);
      } else {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x64)))(*gGameUIInterface);
        (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 8)))(0x14, 1);
        *(u8 *)(state + 6) = 5;
      }
    }
    break;
  case 3:
    if (((*(int (*)(int))(*(int *)(*gScreenTransitionInterface + 0x14)))(
             *gScreenTransitionInterface) != 0) &&
        ((*(u16 *)((int)Obj_GetPlayerObject() + 0xb0) & 0x1000) == 0)) {
      GameBit_Set(0x13f, 1);
      (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(3, obj, -1);
      *(u8 *)(state + 6) = 4;
    }
    break;
  case 4:
    *(u8 *)(state + 6) = 7;
    break;
  case 5:
    if (((*(int (*)(int))(*(int *)(*gScreenTransitionInterface + 0x14)))(
             *gScreenTransitionInterface) != 0) &&
        ((*(u16 *)((int)Obj_GetPlayerObject() + 0xb0) & 0x1000) == 0)) {
      (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(2, obj, -1);
      *(u8 *)(state + 6) = 6;
    }
    break;
  case 6:
    (*gMapEventInterface)->finishCurrentEvent(*gMapEventInterface);
    break;
  case 7:
    if (GameBit_Get(0xea6) == 0) {
      GameBit_Set(0xea6, 1);
      if (GameBit_Get(0x1a2) == 0) {
        GameBit_Set(0x9d5, 1);
      }
    }
    break;
  }

  if (*(u8 *)(state + 6) == 2) {
    if (*(s16 *)(state + 0x12) != 0xf2) {
      *(s16 *)(state + 0x12) = 0xf2;
      GameBit_Set(0xc0, 1);
      *(u32 *)state &= ~2;
    }
  } else if (*(s16 *)(state + 0x12) != 0xcc) {
    *(s16 *)(state + 0x12) = 0xcc;
    GameBit_Set(0xc0, 1);
    *(u32 *)state &= ~2;
  }

  if ((GameBit_Get(0xea8) == 0) && (GameBit_Get(0x91b) != 0)) {
    GameBit_Set(0xea8, 1);
    (*gMapEventInterface)->triggerEvent(0, 0, 1, 0);
  }
}

/*
 * --INFO--
 *
 * Function: FUN_801d8480
 * EN v1.0 Address: 0x801D8480
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801D8650
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8480(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int *param_6)
{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286838();
  uVar2 = (uint)param_5;
  uVar1 = GameBit_Get(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  GameBit_Set(uVar2,uVar1 >> 5);
  SCGameBitLatch_Update((int)((ulonglong)uVar3 >> 0x20), (int)uVar3, param_3, param_4,
                        param_5, (int)param_6);
  uVar1 = GameBit_Get(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  GameBit_Set(uVar2,uVar1 >> 5);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d8524
 * EN v1.0 Address: 0x801D8524
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D86E4
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8524(uint *param_1)
{
}
