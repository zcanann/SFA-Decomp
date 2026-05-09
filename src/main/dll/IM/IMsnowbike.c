#include "ghidra_import.h"
#include "main/dll/IM/IMsnowbike.h"

extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_GetPlayerObject(void);
extern void buttonDisable(int a, int b);
extern void fn_80014B58(int a);
extern void fn_80014B68(int a);
extern void gameTextShow(int a);
extern void fn_80088870(void *a, void *b, void *c, void *d);
extern void envFxActFn_800887f8(int a);
extern void fn_80088E54(int a, f32 b);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void fn_801D7C94(int param_1, uint *param_2);
extern void fn_801D80F4(uint *param_1);
extern void fn_801D8308(int param_1, uint *param_2);
extern void fn_801D87F8(int param_1, uint *param_2);
extern void fn_801D8B00(int param_1, uint *param_2);
extern void objRenderFn_8003b8f4(f32);

extern undefined4 *lbl_803DCAAC;
extern undefined4 *lbl_803DCA54;
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
  fn_801D80F4(puVar5);
  iVar1 = GameBit_Get(0x3aa);
  if (iVar1 != 0) {
    if (*(char *)(param_1 + 0xac) == 8) {
      cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1d);
      if (cVar4 == '\0') {
        (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1d, 1);
      }
    }
    else {
      cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1d);
      if (cVar4 != '\0') {
        (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1d, 0);
      }
    }
  }
  iVar1 = GameBit_Get(0x3b8);
  if (iVar1 != 0) {
    cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1c);
    if (cVar4 == '\0') {
      (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1c, 1);
    }
  }
  else {
    cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1c);
    if (cVar4 != '\0') {
      (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1c, 0);
    }
  }
  iVar1 = GameBit_Get(999);
  if ((iVar1 != 0) &&
     (cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1b),
     cVar4 == '\0')) {
    (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1b, 1);
  }
  iVar1 = GameBit_Get(0x11);
  if (iVar1 != 0) {
    cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1a);
    if (cVar4 == '\0') {
      (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1a, 1);
    }
  }
  else {
    cVar4 = (*(code *)(*lbl_803DCAAC + 0x4c))((int)*(char *)(param_1 + 0xac), 0x1a);
    if (cVar4 != '\0') {
      (*(code *)(*lbl_803DCAAC + 0x50))((int)*(char *)(param_1 + 0xac), 0x1a, 0);
    }
  }
  switch (*(undefined *)((int)puVar5 + 5)) {
  case 1:
    fn_801D8B00(param_1, puVar5);
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
    fn_801D87F8(param_1, puVar5);
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
        fn_80014B68(0);
        fn_80014B58(0);
        buttonDisable(0, 0x100);
        buttonDisable(0, 0x200);
        buttonDisable(0, 0x1000);
        iVar1 = Obj_GetPlayerObject();
        if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
          (*(code *)(*lbl_803DCA54 + 0x48))(7, param_1, 0xffffffff);
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
    fn_801D8308(param_1, puVar5);
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
        fn_80014B68(0);
        fn_80014B58(0);
        buttonDisable(0, 0x100);
        buttonDisable(0, 0x200);
        buttonDisable(0, 0x1000);
        iVar1 = Obj_GetPlayerObject();
        if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
          (*(code *)(*lbl_803DCA54 + 0x48))(4, param_1, 0xffffffff);
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
          fn_80088E54(0, lbl_803E54B4);
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
  fn_801D7C94(param_1, puVar5);
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
int warpstonelift_func08(void) { return 0x0; }
int sh_staff_getExtraSize(void) { return 0x74; }

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off
void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E54C8); }
#pragma peephole reset
