#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMsnowbike.h"

extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_GetPlayerObject(void);
extern void buttonDisable(int a, int b);
extern void padClearAnalogInputY(int a);
extern void padClearAnalogInputX(int a);
extern void gameTextShow(int a);
extern void fn_80088870(void *a, void *b, void *c, void *d);
extern void envFxActFn_800887f8(int a);
extern void skyFn_80088e54(int a, f32 b);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void mapUnloadFn_801d7c94(int param_1, uint *param_2);
extern void SH_LevelControl_setMusic(uint *param_1);
extern void SH_LevelControl_runBloopEvent(int param_1, uint *param_2);
extern void SH_LevelControl_doThornTailEvents(int param_1, uint *param_2);
extern void SH_LevelControl_doEarlyScenes(int param_1, uint *param_2);
extern void objRenderFn_8003b8f4(f32);

extern MapEventInterface **gMapEventInterface;
extern undefined4 *gObjectTriggerInterface;
extern f32 lbl_803E54B4;
extern f32 lbl_803E54C8;
extern f32 timeDelta;
extern u8 lbl_80327618[0x104];

/*
 * --INFO--
 *
 * Function: sh_levelcontrol_update
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 2452b
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void sh_levelcontrol_update(int param_1)
{
  uint *puVar5;
  uint iVar1;
  uint iVar3;
  uint uVar2;
  u8 cVar4;
  u8 *base = lbl_80327618;

  puVar5 = *(uint **)(param_1 + 0xb8);
  if (*(f32 *)((int)puVar5 + 0xc) > lbl_803E54B4) {
    gameTextShow(0x3f6);
    *(f32 *)((int)puVar5 + 0xc) = *(f32 *)((int)puVar5 + 0xc) - timeDelta;
    if (*(f32 *)((int)puVar5 + 0xc) < lbl_803E54B4) {
      *(f32 *)((int)puVar5 + 0xc) = lbl_803E54B4;
    }
  }
  SH_LevelControl_setMusic(puVar5);
  iVar1 = GameBit_Get(0x3aa);
  if (iVar1 != 0) {
    if (*(char *)(param_1 + 0xac) == 8) {
      cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1d);
      if (cVar4 == '\0') {
        (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1d, 1);
      }
    }
    else {
      cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1d);
      if (cVar4 != '\0') {
        (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1d, 0);
      }
    }
  }
  iVar1 = GameBit_Get(0x3b8);
  if (iVar1 != 0) {
    cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1c);
    if (cVar4 == '\0') {
      (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1c, 1);
    }
  }
  else {
    cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1c);
    if (cVar4 != '\0') {
      (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1c, 0);
    }
  }
  iVar1 = GameBit_Get(999);
  if ((iVar1 != 0) &&
     (cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1b),
     cVar4 == '\0')) {
    (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1b, 1);
  }
  iVar1 = GameBit_Get(0x11);
  if (iVar1 != 0) {
    cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1a);
    if (cVar4 == '\0') {
      (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1a, 1);
    }
  }
  else {
    cVar4 = (*gMapEventInterface)->getAnimEvent((int)*(char *)(param_1 + 0xac), 0x1a);
    if (cVar4 != '\0') {
      (*gMapEventInterface)->setAnimEvent((int)*(char *)(param_1 + 0xac), 0x1a, 0);
    }
  }
  switch (*(undefined *)((int)puVar5 + 5)) {
  case 1:
    SH_LevelControl_doEarlyScenes(param_1, puVar5);
    break;
  case 2:
    iVar1 = GameBit_Get(0xbf);
    if ((iVar1 != 0) && (uVar2 = GameBit_Get(0xc2), uVar2 < 6)) {
      if (*(short *)((int)puVar5 + 0x12) != 0xdb) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xdb;
        GameBit_Set(0xc0, 1);
        *puVar5 = *puVar5 & 0xfffffffd;
      }
    }
    else {
      iVar1 = GameBit_Get(0xc2);
      if ((iVar1 == 6) && (*(short *)((int)puVar5 + 0x12) != 0xcc)) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
        GameBit_Set(0xc0, 1);
        *puVar5 = *puVar5 & 0xfffffffd;
      }
    }
    iVar1 = GameBit_Get(0xc2);
    iVar3 = GameBit_Get(0x66d);
    if ((iVar3 + iVar1 == 6) && (iVar1 = GameBit_Get(0xe5b), iVar1 == 0)) {
      Sfx_PlayFromObject(param_1, 0x7e);
      GameBit_Set(0xe5b, 1);
    }
    break;
  case 3:
    SH_LevelControl_doThornTailEvents(param_1, puVar5);
    break;
  case 4:
    if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      GameBit_Set(0xc0, 1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    if (*(byte *)(puVar5 + 1) >= 2) {
      iVar1 = GameBit_Get(0xdff);
      if (iVar1 == 0) {
        padClearAnalogInputX(0);
        padClearAnalogInputY(0);
        buttonDisable(0, 0x100);
        buttonDisable(0, 0x200);
        buttonDisable(0, 0x1000);
        iVar1 = Obj_GetPlayerObject();
        if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
          (*(code *)(*gObjectTriggerInterface + 0x48))(7, param_1, 0xffffffff);
          GameBit_Set(0xdff, 1);
        }
      }
      else {
        iVar1 = GameBit_Get(0xede);
        if (iVar1 == 0) {
          GameBit_Set(0xede, 1);
          GameBit_Set(0x9d5, 1);
        }
      }
    }
    else {
      *(byte *)(puVar5 + 1) = *(byte *)(puVar5 + 1) + 1;
    }
    break;
  case 5:
    iVar1 = GameBit_Get(0x23c);
    if (iVar1 == 0) {
      if (*(short *)((int)puVar5 + 0x12) == 0xcc) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xffff;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      GameBit_Set(0xc0, 1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    iVar1 = GameBit_Get(0x90);
    if (((iVar1 != 0) && (iVar1 = GameBit_Get(0xeb3), iVar1 == 0)) &&
       (iVar1 = Obj_GetPlayerObject(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
      GameBit_Set(0xeb3, 1);
    }
    break;
  case 6:
    SH_LevelControl_runBloopEvent(param_1, puVar5);
    break;
  case 7:
    iVar1 = GameBit_Get(0x1a0);
    if (iVar1 == 0) {
      if (*(short *)((int)puVar5 + 0x12) == 0xcc) {
        *(undefined2 *)((int)puVar5 + 0x12) = 0xffff;
      }
    }
    else if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      GameBit_Set(0xc0, 1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    if (*(byte *)(puVar5 + 1) >= 2) {
      iVar1 = GameBit_Get(0x177);
      if (iVar1 == 0) {
        padClearAnalogInputX(0);
        padClearAnalogInputY(0);
        buttonDisable(0, 0x100);
        buttonDisable(0, 0x200);
        buttonDisable(0, 0x1000);
        iVar1 = Obj_GetPlayerObject();
        if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
          (*(code *)(*gObjectTriggerInterface + 0x48))(4, param_1, 0xffffffff);
          GameBit_Set(0x177, 1);
        }
      }
    }
    else {
      *(byte *)(puVar5 + 1) = *(byte *)(puVar5 + 1) + 1;
    }
    break;
  case 8:
    if (*(short *)((int)puVar5 + 0x12) != 0xcc) {
      *(undefined2 *)((int)puVar5 + 0x12) = 0xcc;
      GameBit_Set(0xc0, 1);
      *puVar5 = *puVar5 & 0xfffffffd;
    }
    iVar1 = GameBit_Get(0x19c);
    if ((iVar1 != 0) && (iVar1 = GameBit_Get(0xf3e), iVar1 == 0)) {
      GameBit_Set(0xf3e, 1);
      iVar1 = GameBit_Get(0xc64);
      if (iVar1 == 0) {
        GameBit_Set(0x9d5, 1);
      }
    }
  }
  iVar1 = GameBit_Get(0xd36);
  if (iVar1 == 0) {
    iVar1 = GameBit_Get(0xd35);
    if (iVar1 == 0) {
      if (*(int *)(param_1 + 0xf8) != 0) {
        *(undefined4 *)(param_1 + 0xf8) = 0;
        if (*(int *)(param_1 + 0xf4) == 2) {
          fn_80088870(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
          envFxActFn_800887f8(0x3f);
          getEnvfxActImmediately(0, 0, 0x244, 0);
          skyFn_80088e54(0, lbl_803E54B4);
        }
        else {
          fn_80088870(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
          envFxActFn_800887f8(0x1f);
          getEnvfxAct(0, 0, 0x244, 0);
        }
      }
    }
    else if (*(int *)(param_1 + 0xf8) != 1) {
      *(undefined4 *)(param_1 + 0xf8) = 1;
      if (*(int *)(param_1 + 0xf4) == 2) {
        envFxActFn_800887f8(0);
        getEnvfxActImmediately(0, 0, 0x1bf, 0);
        getEnvfxActImmediately(0, 0, 0x1be, 0);
        getEnvfxActImmediately(0, 0, 0x1c0, 0);
        getEnvfxActImmediately(0, 0, 0x244, 0);
      }
      else {
        envFxActFn_800887f8(0);
        getEnvfxAct(0, 0, 0x1bf, 0);
        getEnvfxAct(0, 0, 0x1be, 0);
        getEnvfxAct(0, 0, 0x1c0, 0);
        getEnvfxAct(0, 0, 0x244, 0);
      }
    }
  }
  else if (*(int *)(param_1 + 0xf8) != 2) {
    *(undefined4 *)(param_1 + 0xf8) = 2;
    envFxActFn_800887f8(0);
    if (*(int *)(param_1 + 0xf4) == 2) {
      getEnvfxActImmediately(0, 0, 0x1bf, 0);
      getEnvfxActImmediately(0, 0, 0x231, 0);
      getEnvfxActImmediately(0, 0, 0x232, 0);
      getEnvfxActImmediately(0, 0, 0x244, 0);
    }
    else {
      getEnvfxAct(0, 0, 0x1bf, 0);
      getEnvfxAct(0, 0, 0x231, 0);
      getEnvfxAct(0, 0, 0x232, 0);
      getEnvfxAct(0, 0, 0x244, 0);
    }
  }
  mapUnloadFn_801d7c94(param_1, puVar5);
  return;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void warpstonelift_free(void) {}
void warpstonelift_hitDetect(void) {}
void warpstonelift_release(void) {}
void warpstonelift_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int warpstonelift_getExtraSize(void) { return 0x1; }
int warpstonelift_getObjectTypeId(void) { return 0x0; }
int sh_staff_getExtraSize(void) { return 0x74; }

extern s32 lbl_803DC058[2];
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern void Music_Trigger(int track, int param);
extern int getSaveGameLoadStatus(void);
extern void timeOfDayFn_80055000(void);
extern void SH_LevelControl_SeqFn(void);
extern f32 lbl_803E54C0;
extern s16 lbl_80327618_ids[];

#pragma scheduling off
#pragma peephole off
void sh_levelcontrol_init(int obj) {
    int *state = *(int **)((char *)obj + 0xB8);
    int i;
    s16 *bitIds;
    u32 v;

    *(void (**)(void))((char *)obj + 0xBC) = SH_LevelControl_SeqFn;
    v = (u32)*(u16 *)((char *)obj + 0xB0) | 0x4000;
    *(u16 *)((char *)obj + 0xB0) = (u16)v;
    *(int *)((char *)obj + 0xF8) = 3;

    if (getSaveGameLoadStatus() != 0) {
        *(int *)((char *)obj + 0xF4) = 2;
    } else {
        *(int *)((char *)obj + 0xF4) = 1;
    }

    *(s16 *)((char *)state + 0x10) = -1;
    *(f32 *)((char *)state + 0xC) = lbl_803E54C0;

    if (GameBit_Get(0x611) != 0) {
        *(int *)state |= 0x40;
    }

    *(u8 *)((char *)state + 5) = (*(int (**)(int))((char *)*gMapEventInterface + 0x40))((int)*(s8 *)((char *)obj + 0xAC));

    *(s16 *)((char *)state + 0x12) = -1;
    Music_Trigger(34, 0);
    Music_Trigger(49, 0);
    Music_Trigger(178, 0);
    Music_Trigger(196, 0);
    Music_Trigger(166, 0);
    Music_Trigger(172, 0);
    Music_Trigger(168, 0);
    GameBit_Set(3213, 1);

    if (GameBit_Get(319) == 0) {
        bitIds = lbl_80327618_ids;
        for (i = 0; i < 18; i++) {
            GameBit_Set(*bitIds, 0);
            bitIds++;
        }
    }
    timeOfDayFn_80055000();
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void warpstonelift_init(int obj, s8 *def) {
    int *state = *(int **)((char *)obj + 0xB8);
    int i;
    *(s16 *)obj = (s16)((s32)def[0x18] << 8);
    *(int *)((char *)obj + 0xF4) = 0;
    for (i = 0; i < 2; i++) {
        if (GameBit_Get(lbl_803DC058[i]) != 0) {
            *(u8 *)state = (u8)(i + 1);
        }
    }
    switch (*(u8 *)state) {
    case 0:
    case 2:
        fn_8002B6D8(obj, 0, 0, 0, 0, 3);
        break;
    case 1:
        fn_8002B6D8(obj, 0, 0, 0, 0, 4);
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off
void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E54C8); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void sh_staff_free(int *obj, int p2) {
    int *state = *(int **)((char *)obj + 0xb8);
    char *p;
    int idx;

    if (p2 != 0) return;

    for (idx = 0; idx < 8; idx += 4) {
        int *child;
        p = (char *)state + idx * 5;
        child = *(int **)(p + 56);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 60);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 64);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 68);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 72);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        p += 20;
    }
}
#pragma peephole reset
#pragma scheduling reset
