#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/SC/SCcollectables.h"

#define SFXbaddie_haga_death 700
#define SFXnewtricky_01o 756

extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006bb4();
extern uint FUN_80006c00();
extern uint GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern uint getButtonsJustPressed(int controller);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined8 FUN_80043030();
extern undefined4 FUN_80044404();
extern int playerHasKrazoaSpirit();
extern void padGetAnalogInput(int controller, s8 *horizontal, s8 *vertical);
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294cd0();

extern undefined DAT_803adca8;
extern undefined4 DAT_803adcb6;
extern undefined4 DAT_803adcba;
extern undefined4 DAT_803adcc3;
extern int lbl_803DC050;
extern int lbl_803DDBF4;
extern undefined4 DAT_803dccb8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de874;
extern f64 DOUBLE_803e6128;
extern f32 lbl_803DC074;
extern f32 lbl_803E60F8;
extern f32 lbl_803E60FC;
extern f32 lbl_803E6100;
extern f32 lbl_803E6104;
extern f32 lbl_803E6108;
extern f32 lbl_803E610C;
extern f32 lbl_803E6110;
extern f32 lbl_803E6114;
extern f32 lbl_803E6118;
extern f32 lbl_803E611C;
extern f32 lbl_803E6120;
extern f32 lbl_803E6130;

/*
 * --INFO--
 *
 * Function: FUN_801d6d98
 * EN v1.0 Address: 0x801D6D98
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801D6F04
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d6d98(int param_1)
{
  float fVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar2 = FUN_80017a98();
  iVar4 = *(int *)(param_1 + 0xb8);
  local_2c = lbl_803E60F8;
  local_28 = lbl_803E60FC;
  local_24 = lbl_803E60F8;
  local_34 = 0xc0e;
  local_36 = 1;
  if ((*(byte *)(iVar4 + 0xd4) & 4) != 0) {
    fVar1 = *(float *)(iVar4 + 4);
    if (lbl_803E6100 <= fVar1) {
      if (lbl_803E6108 <= fVar1) {
        if (lbl_803E6118 <= fVar1) {
          if (lbl_803E6120 <= fVar1) {
            *(float *)(iVar4 + 4) = lbl_803E60F8;
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfb;
          }
        }
        else {
          uStack_1c = randomGetRange(0,0x1e0);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
              *(float *)(iVar4 + 4) * lbl_803E6104) {
            (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)(iVar4 + 0xd4) & 2) != 0) {
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfd;
            local_32 = 0x46;
            local_30 = lbl_803E611C;
            for (cVar3 = '\x0f'; cVar3 != '\0'; cVar3 = cVar3 + -1) {
              (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack_1c = randomGetRange(0,0x1e0);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
            *(float *)(iVar4 + 4) / lbl_803E610C) {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = lbl_803E6110 * ((*(float *)(iVar4 + 4) - lbl_803E6100) / lbl_803E6114);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) | 2;
      }
    }
    else {
      uStack_1c = randomGetRange(0,0x1e0);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
          *(float *)(iVar4 + 4) * lbl_803E6104) {
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *(float *)(iVar4 + 4) = *(float *)(iVar4 + 4) + lbl_803DC074;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7034
 * EN v1.0 Address: 0x801D7034
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801D71F4
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7034(void)
{
  short *psVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  undefined8 extraout_f1;
  float local_28;
  float local_24;
  float local_20 [8];
  
  psVar1 = (short *)FUN_8028683c();
  iVar4 = 0;
  DAT_803adcc3 = '\0';
  DAT_803adcba = '\0';
  FUN_8002fc3c(extraout_f1,(double)lbl_803DC074);
  if (DAT_803adcba != '\0') {
    *psVar1 = *psVar1 + DAT_803adcb6;
  }
  puVar3 = &DAT_803adca8;
  for (iVar2 = 0; iVar2 < DAT_803adcc3; iVar2 = iVar2 + 1) {
    switch(puVar3[0x13]) {
    case 1:
      iVar4 = 1;
      break;
    case 2:
      iVar4 = 2;
      break;
    case 3:
      iVar4 = 1;
      break;
    case 4:
      iVar4 = 2;
      break;
    case 9:
      FUN_80006824((uint)psVar1,SFXnewtricky_01o);
    }
    puVar3 = puVar3 + 1;
  }
  if ((iVar4 != 0) &&
     ((ObjPath_GetPointWorldPosition(psVar1,iVar4 + -1,&local_28,&local_24,local_20,0), psVar1[0x50] != 0x1b ||
      (lbl_803E6130 <= *(float *)(psVar1 + 0x4c))))) {
    FUN_80006820((double)local_28,(double)local_24,(double)local_20[0],(uint)psVar1,0x415);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7198
 * EN v1.0 Address: 0x801D7198
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801D7348
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801d7198(void)
{
  int iVar1;
  
  (**(code **)(*DAT_803dd72c + 0x74))();
  iVar1 = FUN_80017a98();
  FUN_80294cd0(iVar1,0xff);
  return 2;
}

/*
 * --INFO--
 *
 * Function: FUN_801d71dc
 * EN v1.0 Address: 0x801D71DC
 * EN v1.0 Size: 1172b
 * EN v1.1 Address: 0x801D7388
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801d71dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11)
{
  undefined4 uVar1;
  uint uVar2;
  undefined8 uVar3;
  char local_18;
  char local_17 [19];
  
  FUN_80017a98();
  uVar3 = FUN_80006bb4(0,local_17,&local_18);
  if (param_11 == 0x17) {
    uVar2 = playerHasKrazoaSpirit('\x01',0);
    if (('\0' < local_17[0]) && (uVar2 == 0)) {
      FUN_80006824(0,0x418);
      return 1;
    }
  }
  else if (param_11 < 0x17) {
    if (param_11 == 0x15) {
      if (('\0' < local_18) && (DAT_803dccb8 == 0)) {
        FUN_80006824(0,0x418);
        return 1;
      }
    }
    else if (param_11 < 0x15) {
      if ((0x13 < param_11) && (local_17[0] < '\0')) {
        FUN_80041ff8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x42);
        FUN_80042bec(uVar1,0);
        uVar1 = FUN_80044404(7);
        FUN_80042bec(uVar1,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,1);
        FUN_80006824(0,0x418);
        return 1;
      }
    }
    else if (('\0' < local_17[0]) && (uVar2 = playerHasKrazoaSpirit('\x01',0), uVar2 != 0)) {
      FUN_80041ff8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
      uVar1 = FUN_80044404(0x42);
      FUN_80042bec(uVar1,0);
      uVar1 = FUN_80044404(7);
      FUN_80042bec(uVar1,1);
      uVar2 = GameBit_Get(0xbfd);
      if (uVar2 == 0) {
        uVar2 = GameBit_Get(0xff);
        if (uVar2 == 0) {
          uVar2 = GameBit_Get(0xc6e);
          if (uVar2 == 0) {
            uVar2 = GameBit_Get(0xc85);
            if (uVar2 != 0) {
              (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
            }
          }
          else {
            (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
          }
        }
        else {
          (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
        }
      }
      else {
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
      }
      FUN_80006824(0,0x418);
      return 1;
    }
  }
  else if (param_11 == 0x19) {
    uVar2 = FUN_80006c00(0);
    if ((uVar2 & 0x200) != 0) {
      FUN_80042b9c(0,0,1);
      FUN_80044404(0x42);
      uVar3 = FUN_80043030(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80044404(0x17);
      FUN_80043030(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80006824(0,0x419);
      return 1;
    }
  }
  else if ((param_11 < 0x19) && (DAT_803de874 = 1, '\0' < local_18)) {
    FUN_80041ff8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,9);
    uVar1 = FUN_80044404(9);
    FUN_80042bec(uVar1,0);
    uVar1 = FUN_80044404(7);
    FUN_80042bec(uVar1,1);
    FUN_80006824(0,0x418);
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: warpstone_getExtraSize
 * EN v1.0 Address: 0x801D7468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int warpstone_getExtraSize(void)
{
  return 0xd8;
}

/*
 * --INFO--
 *
 * Function: warpstone_getObjectTypeId
 * EN v1.0 Address: 0x801D7470
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int warpstone_getObjectTypeId(void)
{
  return 0x48;
}

/* void f() { fn_X(N); } pattern. */
extern void loadUiDll(s32);
#pragma scheduling off
#pragma peephole off
void fn_801D70B4(void) { loadUiDll(0x1); }
#pragma peephole reset
#pragma scheduling reset

extern void ObjLink_DetachChild(int obj, int child);
extern void Obj_FreeObject(int obj);

#pragma scheduling off
#pragma peephole off
void warpstone_free(int obj, int mode)
{
    int *state = *(int **)((char *)obj + 0xb8);
    if (*(void **)state != NULL && mode == 0) {
        ObjLink_DetachChild(obj, state[0]);
        Obj_FreeObject(state[0]);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int ObjHits_GetPriorityHitWithPosition(int obj, int a, int b, int c, f32 *x, f32 *y, f32 *z);
extern void objLightFn_8009a1dc(int obj, f32 light, int *p, int x, int y);
extern int randFn_80080100(int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objAudioFn_800393f8(int obj, int *p, int a, int b, int c, int d);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E54A0;

#pragma scheduling off
#pragma peephole off
void warpstone_hitDetect(int obj)
{
    int *state = *(int **)((char *)obj + 0xb8);
    f32 pos[3];
    int p[3];

    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos[0], &pos[1], &pos[2]) != 0) {
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        objLightFn_8009a1dc(obj, lbl_803E54A0, p, 1, 0);
        if (randFn_80080100(3) != 0) {
            Sfx_PlayFromObject(obj, SFXbaddie_haga_death);
        } else {
            Sfx_PlayFromObject(obj, SFXbaddie_haga_death);
        }
        objAudioFn_800393f8(obj, state + 5, 171, -1280, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void objRenderFn_8003b8f4(f32);
extern int Obj_GetPlayerObject(void);
extern int fn_80296464(void);
extern int *Obj_GetActiveModel(int player);
extern void fn_80295B2C(int player, f32 x, f32 y, f32 z);
extern void playerRender(int player, int p2, int p3, int p4, int p5, int last);
extern f32 lbl_803E549C;

#pragma scheduling off
#pragma peephole off
void warpstone_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void *player;
    int *state = *(int **)((char *)obj + 0xb8);
    int *model;
    f32 z;
    f32 y;
    f32 x;
    s32 v = visible;
    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E549C);
        player = (void *)Obj_GetPlayerObject();
        if (player != NULL && fn_80296464() != 0) {
            model = Obj_GetActiveModel((int)player);
            *(u16 *)((char *)model + 24) = (u16)(*(u16 *)((char *)model + 24) & ~0x8);
            ObjPath_GetPointWorldPosition(obj, *(u8 *)((char *)state + 8), &x, &y, &z, 0);
            fn_80295B2C((int)player, x, y, z);
            playerRender((int)player, p2, p3, p4, p5, -1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int locked);
extern void mapUnload(int dirIdx, int flags);
extern MapEventInterface **gMapEventInterface;

#define WARPSTONE_MAP_EVENT_SET(mapId, value) \
    (*gMapEventInterface)->setMode((mapId), (value))
#define WARPSTONE_MAP_EVENT_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))

static void warpstone_setSwapstoneLoaded(void)
{
    loadMapAndParent(0x42);
    unlockLevel(0, 0, 1);
    lockLevel(mapGetDirIdx(0x42), 0);
    lockLevel(mapGetDirIdx(7), 1);
}

static void warpstone_setThorntailLoaded(void)
{
    loadMapAndParent(9);
    lockLevel(mapGetDirIdx(9), 0);
    lockLevel(mapGetDirIdx(7), 1);
}

static void warpstone_playAccept(void)
{
    Sfx_PlayFromObject(0, 0x418);
}

static void warpstone_setSwapstoneMapEvent(s32 value)
{
    WARPSTONE_MAP_EVENT_SET(0x42, value);
}

#pragma scheduling off
#pragma peephole off
int fn_801D6D98(undefined4 p1, undefined4 p2, int option)
{
    s8 horizontal;
    s8 vertical;

    Obj_GetPlayerObject();
    padGetAnalogInput(0, &horizontal, &vertical);

    switch (option) {
    case 0x14:
        if (horizontal < 0) {
            warpstone_setSwapstoneLoaded();
            warpstone_setSwapstoneMapEvent(1);
            warpstone_playAccept();
            return 1;
        }
        break;

    case 0x15:
        if (vertical > 0 && lbl_803DC050 == 0) {
            warpstone_playAccept();
            return 1;
        }
        break;

    case 0x16:
        if (horizontal > 0 && playerHasKrazoaSpirit(1, 0) != 0) {
            loadMapAndParent(0x42);
            lockLevel(mapGetDirIdx(0x42), 0);
            lockLevel(mapGetDirIdx(7), 1);
            if (GameBit_Get(0xbfd) != 0) {
                warpstone_setSwapstoneMapEvent(2);
            } else if (GameBit_Get(0xff) != 0) {
                warpstone_setSwapstoneMapEvent(2);
            } else if (GameBit_Get(0xc6e) != 0) {
                warpstone_setSwapstoneMapEvent(2);
            } else if (GameBit_Get(0xc85) != 0) {
                warpstone_setSwapstoneMapEvent(2);
            }
            warpstone_playAccept();
            return 1;
        }
        break;

    case 0x17: {
        int hasSpirit = playerHasKrazoaSpirit(1, 0);
        if (horizontal > 0 && hasSpirit == 0) {
            warpstone_playAccept();
            return 1;
        }
        break;
    }

    case 0x18:
        lbl_803DDBF4 = 1;
        if (vertical > 0) {
            warpstone_setThorntailLoaded();
            warpstone_playAccept();
            return 1;
        }
        break;

    case 0x19:
        if ((getButtonsJustPressed(0) & 0x200) != 0) {
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            mapUnload(mapGetDirIdx(0x17), 0x20000000);
            Sfx_PlayFromObject(0, 0x419);
            return 1;
        }
        break;
    }

    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int animatedObjGetSeqId(int obj);
extern int fn_80080360(int obj, int seqId);
extern int getCurUiDll(void);
extern void ObjAnim_AdvanceCurrentMove(int obj, f32 moveStepScale, f32 deltaTime, void *events);
extern int playerFn_801d6d58(void);
extern void AudioStream_CancelPrepared(void);
extern void seqClearTaskTexts(void);
extern void doNothing_8000CF54(int unused);
extern void CMenu_SetFadeCounter(s16 counter);
extern void warpToMap(int mapId, int spawnId);
extern void subtitleFn_8001b700(void);
extern int getDLL16(void);
extern void SHthorntail_updateDustEffects(int obj);
extern f32 timeDelta;

#pragma scheduling off
#pragma peephole off
int fn_801D70D8(int obj, undefined4 p2, int animObj)
{
    int commandOffset;
    int i;
    int child;
    u8 command;
    int state = *(int *)(obj + 0xb8);

    if (animatedObjGetSeqId(animObj) == 0x35f) {
        fn_80080360(animObj, 0x2648);
        if (getCurUiDll() != 0x10) {
            loadUiDll(0x10);
        }
    }

    child = *(int *)state;
    if (child != 0) {
        ObjAnim_AdvanceCurrentMove(child, *(f32 *)(obj + 0x98) - *(f32 *)(child + 0x98), timeDelta, NULL);
    }

    *(void **)(animObj + 0xec) = fn_801D6D98;
    *(void **)(animObj + 0xe8) = fn_801D70B4;

    if (*(s8 *)(animObj + 0x56) != 0) {
        *(u8 *)(state + 0xa) = *(u8 *)(state + 0xa) & ~3;
        if (playerFn_801d6d58() != 0) {
            *(u8 *)(state + 0xa) = *(u8 *)(state + 0xa) | 1;
        }
        if (GameBit_Get(0x2e8) != 0 || GameBit_Get(0x123) != 0) {
            *(u8 *)(state + 0xa) = *(u8 *)(state + 0xa) | 2;
        }
        *(u8 *)(animObj + 0x56) = 0;

        if (GameBit_Get(*(s16 *)(state + 0xe)) != 0 && animatedObjGetSeqId(animObj) == 0x35f) {
            AudioStream_CancelPrepared();
            seqClearTaskTexts();
            doNothing_8000CF54(0);
            *(u8 *)(animObj + 0x90) = *(u8 *)(animObj + 0x90) | 4;
        }
    }

    for (i = 0; i < *(u8 *)(animObj + 0x8b); i++) {
        commandOffset = i + 0x81;
        command = *(u8 *)(animObj + commandOffset);
        switch (command) {
        case 0x17:
            *(u8 *)(state + 0xd4) = *(u8 *)(state + 0xd4) | 4;
            Sfx_PlayFromObject(0, 0x420);
            break;

        case 3:
            *(u8 *)(state + 8) = 0;
            break;

        case 4:
            *(u8 *)(state + 8) = 1;
            break;

        case 6:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            warpToMap(0x7e, 1);
            break;

        case 7:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            GameBit_Set(0x884, 1);
            warpToMap(0x7e, 1);
            break;

        case 0xa:
            *(u8 *)(state + 9) = *(u8 *)(state + 9) ^ 1;
            break;

        case 9:
            WARPSTONE_MAP_EVENT_SET(0x17, 1);
            WARPSTONE_MAP_EVENT_SET(0xe, 2);
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            break;

        case 0xc:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            warpToMap(0x33, 0);
            break;

        case 0xd:
            subtitleFn_8001b700();
        case 0xe:
        case 0xf:
        case 0x10:
            if (getCurUiDll() == 0x10) {
                int dll16 = getDLL16();
                (*(void (**)(int))(*(int *)dll16 + 0x10))(command - 0xd);
            }
            GameBit_Set(*(s16 *)(state + 0xe), 1);
            GameBit_Set(0x887, 1);
            break;

        case 0x12:
            WARPSTONE_MAP_EVENT_ANIM(7, 0xa, 0);
            break;

        case 0x14:
            unlockLevel(0, 0, 1);
            break;

        case 0x15:
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            break;

        case 0x16:
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            break;
        }
    }

    SHthorntail_updateDustEffects(obj);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
