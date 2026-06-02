#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/TREX/TREX_trex.h"

#define SFXen_nlite1_c 0x34
#define SFXen_ripefruit11 0x35
#define SFXen_rockshat16 0x36
#define SFXmn_eggylaugh216 0x72
#define SFXbaddie_crater_call 0x2ca
#define SFXfend_rob_beep2 0x315
#define SFXfend_rob_beep3 0x316
#define SFXspirit_voice4 0x31d

extern undefined4 getLActions();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_8003964c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005335c();
extern undefined4 FUN_8005336c();
extern undefined4 FUN_8008110c();
extern undefined4 FUN_80081114();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined8 FUN_80294d28();
extern undefined4 FUN_80294d60();
extern int* gMapEventInterface;
extern void playerAddMoney(int player, int amount);
extern void playerAddHealth(int player, int amount);
extern int gameBitIncrement(int bit);
extern u8 lbl_80327FD0[];
extern void* fn_802966CC(int player);
extern void fn_80295CF4(int player, int mode);
extern void skyFn_80088c94(int skyId, int enable);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);

extern undefined4 DAT_80328c18;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dcd00;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e6558;
extern f64 DOUBLE_803e65a0;
extern f64 DOUBLE_803e65d8;
extern f64 DOUBLE_803e6600;
extern f64 DOUBLE_803e6628;
extern f64 DOUBLE_803e6638;
extern f64 DOUBLE_803e6650;
extern f32 lbl_803DC074;
extern f32 lbl_803DE8D0;
extern f32 lbl_803E654C;
extern f32 lbl_803E6550;
extern f32 lbl_803E6554;
extern f32 lbl_803E6560;
extern f32 lbl_803E6564;
extern f32 lbl_803E6568;
extern f32 lbl_803E6574;
extern f32 lbl_803E6578;
extern f32 lbl_803E6584;
extern f32 lbl_803E6588;
extern f32 lbl_803E658C;
extern f32 lbl_803E6590;
extern f32 lbl_803E6594;
extern f32 lbl_803E6598;
extern f32 lbl_803E659C;
extern f32 lbl_803E65A8;
extern f32 lbl_803E65AC;
extern f32 lbl_803E65B0;
extern f32 lbl_803E65B4;
extern f32 lbl_803E65C0;
extern f32 lbl_803E65C4;
extern f32 lbl_803E65C8;
extern f32 lbl_803E65CC;
extern f32 lbl_803E65D0;
extern f32 lbl_803E65D4;
extern f32 lbl_803E65E0;
extern f32 lbl_803E65E4;
extern f32 lbl_803E65E8;
extern f32 lbl_803E65F0;
extern f32 lbl_803E65F4;
extern f32 lbl_803E65F8;
extern f32 lbl_803E6608;
extern f32 lbl_803E660C;
extern f32 lbl_803E6614;
extern f32 lbl_803E6618;
extern f32 lbl_803E661C;
extern f32 lbl_803E6620;
extern f32 lbl_803E6624;
extern f32 lbl_803E6630;
extern f32 lbl_803E6634;
extern f32 lbl_803E6644;
extern f32 lbl_803E6648;
extern undefined4 uRam803de8d4;

/*
 * --INFO--
 *
 * Function: SB_FireBall_hitDetect
 * EN v1.0 Address: 0x801E42F8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E4330
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int *gPartfxInterface;

#pragma scheduling off
#pragma peephole off
void SB_FireBall_hitDetect(int *obj)
{
    int *params = *(int **)((char *)obj + 0x54);
    int i;
    if (*(void **)((char *)params + 0x50) == NULL) return;
    *(s16 *)((char *)params + 0x60) = (s16)(*(s16 *)((char *)params + 0x60) & ~1);
    for (i = 50; i != 0; i--) {
        ((void (*)(int *, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 167, 0, 1, -1, 0);
    }
    for (i = 10; i != 0; i--) {
        ((void (*)(int *, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 171, 0, 1, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801e4350
 * EN v1.0 Address: 0x801E4350
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E4384
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4350(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4378
 * EN v1.0 Address: 0x801E4378
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801E43B4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4378(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  short sVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  dVar5 = (double)*(float *)(iVar3 + 0x1c);
  dVar4 = (double)lbl_803E654C;
  if (dVar5 <= dVar4) {
    iVar2 = *(int *)(*(int *)(param_9 + 0x54) + 0x50);
    if ((((iVar2 != 0) && (sVar1 = *(short *)(iVar2 + 0x46), sVar1 != 0x119)) && (sVar1 != 0x113))
       && (dVar4 == dVar5)) {
      FUN_80006824(param_9,SFXspirit_voice4);
      *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & ~1;
      *(float *)(iVar3 + 0x1c) = lbl_803E6550;
      *(undefined *)(param_9 + 0x36) = 0x19;
      iVar3 = 0x32;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0xa7,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      iVar3 = 10;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0xab,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else {
    *(float *)(iVar3 + 0x1c) = (float)(dVar5 - (double)lbl_803DC074);
    if ((double)*(float *)(iVar3 + 0x1c) <= dVar4) {
      FUN_80017ac8(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e451c
 * EN v1.0 Address: 0x801E451C
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801E44EC
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e451c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  float fVar1;
  double dVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  if ((*(byte *)((int)pfVar3 + 0x1a) & 2) == 0) {
    FUN_8008110c((double)lbl_803E6554,param_9,4,0x185,5,0);
    FUN_8008110c((double)lbl_803E6554,param_9,4,0x185,5,0);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    *(byte *)((int)pfVar3 + 0x1a) = *(byte *)((int)pfVar3 + 0x1a) & 0xfd;
  }
  (**(code **)(*DAT_803dd708 + 8))(param_9,0xa9,0,1,0xffffffff,0);
  *(short *)(param_9 + 2) = *(short *)(param_9 + 2) + 4000;
  if ((*(byte *)((int)pfVar3 + 0x1a) & 1) == 0) {
    *pfVar3 = *(float *)(param_9 + 0x24);
    pfVar3[1] = *(float *)(param_9 + 0x28);
    pfVar3[2] = *(float *)(param_9 + 0x2c);
    *(byte *)((int)pfVar3 + 0x1a) = *(byte *)((int)pfVar3 + 0x1a) | 1;
    pfVar3[3] = *(float *)(param_9 + 0xc);
    pfVar3[4] = *(float *)(param_9 + 0x10);
    pfVar3[5] = *(float *)(param_9 + 0x14);
  }
  dVar2 = DOUBLE_803e6558;
  pfVar3[3] = (float)(DOUBLE_803e6558 * (double)(*pfVar3 * lbl_803DC074) + (double)pfVar3[3]);
  pfVar3[4] = (float)(dVar2 * (double)(pfVar3[1] * lbl_803DC074) + (double)pfVar3[4]);
  fVar1 = pfVar3[2] * lbl_803DC074;
  pfVar3[5] = (float)(dVar2 * (double)fVar1 + (double)pfVar3[5]);
  *(float *)(param_9 + 0xc) = pfVar3[3];
  *(float *)(param_9 + 0x10) = pfVar3[4];
  *(float *)(param_9 + 0x14) = pfVar3[5];
  *(uint *)(param_9 + 0xf4) = *(int *)(param_9 + 0xf4) - (uint)DAT_803dc070;
  if (*(int *)(param_9 + 0xf4) < 0) {
    FUN_80017ac8((double)fVar1,dVar2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  if (*(short *)(pfVar3 + 6) < 0x10) {
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & ~1;
  }
  else {
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  }
  *(ushort *)(pfVar3 + 6) = *(short *)(pfVar3 + 6) + (ushort)DAT_803dc070;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e481c
 * EN v1.0 Address: 0x801E481C
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x801E4790
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e481c(uint param_1)
{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x20) == 0) {
    piVar1 = FUN_80017624(param_1,'\x01');
    *(int **)(iVar2 + 0x20) = piVar1;
    if (*(int *)(iVar2 + 0x20) != 0) {
      FUN_800175b0(*(int *)(iVar2 + 0x20),2);
      FUN_8001759c(*(int *)(iVar2 + 0x20),200,0x3c,0,0);
      FUN_800175a0(*(int *)(iVar2 + 0x20),1);
      FUN_800175d0((double)lbl_803E6560,(double)lbl_803E6564,*(int *)(iVar2 + 0x20));
    }
  }
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~1;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * lbl_803E6568;
  *(byte *)(iVar2 + 0x1a) = *(byte *)(iVar2 + 0x1a) | 2;
  FUN_80006824(param_1,SFXen_ripefruit11);
  FUN_80006824(param_1,SFXbaddie_crater_call);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e48f4
 * EN v1.0 Address: 0x801E48F4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801E4888
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e48f4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4928
 * EN v1.0 Address: 0x801E4928
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E48B8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4928(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4950
 * EN v1.0 Address: 0x801E4950
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801E48E8
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4950(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (*(int *)(iVar1 + 0x50) != 0) {
    *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) & ~1;
    iVar1 = 0x32;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa7,0,1,0xffffffff,0);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    iVar1 = 10;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xab,0,1,0xffffffff,0);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4a14
 * EN v1.0 Address: 0x801E4A14
 * EN v1.0 Size: 580b
 * EN v1.1 Address: 0x801E49B0
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4a14(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  int *piVar1;
  undefined auStack_28 [8];
  float local_20;
  
  piVar1 = *(int **)(param_9 + 0x5c);
  if (*piVar1 == 0) {
    *piVar1 = *(int *)(param_9 + 0x7c);
  }
  if (*piVar1 != 0) {
    *param_9 = 0;
    param_9[2] = param_9[2] + (ushort)DAT_803dc070 * -800;
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else {
      if (*(char *)(piVar1 + 5) == '\0') {
        piVar1[2] = *(int *)(param_9 + 0x12);
        piVar1[3] = *(int *)(param_9 + 0x14);
        piVar1[4] = *(int *)(param_9 + 0x16);
        *(undefined *)(piVar1 + 5) = 1;
      }
      *(float *)(param_9 + 6) = (float)piVar1[2] * lbl_803DC074 + *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) = (float)piVar1[3] * lbl_803DC074 + *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) = (float)piVar1[4] * lbl_803DC074 + *(float *)(param_9 + 10);
      local_20 = lbl_803E6574;
      FUN_8008110c((double)lbl_803E6578,param_9,4,0x185,5,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0xa9,auStack_28,1,0xffffffff,0);
      if (*(short *)(piVar1 + 1) < 0x10) {
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & ~1;
      }
      else {
        *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 5;
        *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
        *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
        *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
      }
      *(ushort *)(piVar1 + 1) = *(short *)(piVar1 + 1) + (ushort)DAT_803dc070;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4c58
 * EN v1.0 Address: 0x801E4C58
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E4BAC
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4c58(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = *(uint *)(iVar2 + 0x18);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 0x18) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4cb0
 * EN v1.0 Address: 0x801E4CB0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E4C00
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4cb0(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4cd8
 * EN v1.0 Address: 0x801E4CD8
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801E4C30
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4cd8(uint param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50);
  if ((iVar1 != 0) && (*(float *)(iVar2 + 0x20) == lbl_803E6584)) {
    if (*(short *)(iVar1 + 0x46) == 0x8e) {
      FUN_80006824(param_1,SFXen_rockshat16);
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~1;
    *(float *)(iVar2 + 0x20) = lbl_803E6588;
    *(undefined *)(param_1 + 0x36) = 0;
    FUN_80081114(param_1,2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4d6c
 * EN v1.0 Address: 0x801E4D6C
 * EN v1.0 Size: 824b
 * EN v1.1 Address: 0x801E4CCC
 * EN v1.1 Size: 812b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4d6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  double dVar5;
  float local_28;
  float local_24;
  float local_20;
  undefined4 local_18;
  uint uStack_14;
  
  pfVar3 = *(float **)(param_9 + 0x5c);
  iVar2 = FUN_80017a98();
  fVar1 = lbl_803E6584;
  dVar5 = (double)pfVar3[8];
  dVar4 = (double)lbl_803E6584;
  if (dVar5 == dVar4) {
    *(undefined4 *)(param_9 + 0x40) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0x42) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x44) = *(undefined4 *)(param_9 + 10);
    uStack_14 = randomGetRange(0xffffff9c,100);
    *(float *)(param_9 + 4) =
         lbl_803E6590 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e65a0) +
         lbl_803E658C;
    if (*(char *)(pfVar3 + 7) == '\0') {
      *pfVar3 = *(float *)(param_9 + 0x12);
      pfVar3[1] = *(float *)(param_9 + 0x14);
      pfVar3[2] = *(float *)(param_9 + 0x16);
      *(undefined *)(pfVar3 + 7) = 1;
      pfVar3[3] = *(float *)(param_9 + 6);
      pfVar3[4] = *(float *)(param_9 + 8);
      pfVar3[5] = *(float *)(param_9 + 10);
    }
    fVar1 = lbl_803E6594;
    pfVar3[3] = lbl_803E6594 * *pfVar3 * lbl_803DC074 + pfVar3[3];
    pfVar3[4] = fVar1 * pfVar3[1] * lbl_803DC074 + pfVar3[4];
    pfVar3[5] = fVar1 * pfVar3[2] * lbl_803DC074 + pfVar3[5];
    *(float *)(param_9 + 6) = pfVar3[3];
    *(float *)(param_9 + 8) = pfVar3[4];
    *(float *)(param_9 + 10) = pfVar3[5];
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (((*(int *)(param_9 + 0x7a) < 0) ||
        ((iVar2 != 0 && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)))) &&
       (pfVar3[8] == lbl_803E6584)) {
      *(undefined *)(param_9 + 0x1b) = 0;
      pfVar3[8] = lbl_803E6588;
    }
    iVar2 = FUN_80017730();
    *param_9 = (short)iVar2;
    *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
    if ((*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') && (pfVar3[8] == lbl_803E6584)) {
      FUN_80081114(param_9,2);
      pfVar3[8] = lbl_803E6588;
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    local_28 = lbl_803E6598 * -*pfVar3;
    local_24 = lbl_803E6598 * -pfVar3[1];
    local_20 = lbl_803E6598 * -pfVar3[2];
    FUN_8008110c((double)lbl_803E659C,param_9,2,0x156,0xf,&local_28);
    FUN_8008110c((double)lbl_803E659C,param_9,2,0x156,0xf,&local_28);
    FUN_8008110c((double)lbl_803E659C,param_9,2,0x156,0xf,&local_28);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xa8,0,2,0xffffffff,0);
  }
  else {
    pfVar3[8] = (float)(dVar5 - (double)lbl_803DC074);
    if ((double)pfVar3[8] <= dVar4) {
      pfVar3[8] = fVar1;
      FUN_80017ac8(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e50a4
 * EN v1.0 Address: 0x801E50A4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801E4FF8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e50a4(int param_1)
{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~1;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) = *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) | 1;
  if (*(int *)(iVar2 + 0x18) == 0) {
    piVar1 = FUN_80017624(param_1,'\x01');
    *(int **)(iVar2 + 0x18) = piVar1;
    if (*(int *)(iVar2 + 0x18) != 0) {
      FUN_800175b0(*(int *)(iVar2 + 0x18),2);
      FUN_8001759c(*(int *)(iVar2 + 0x18),0,0x5a,0x96,0);
      FUN_800175a0(*(int *)(iVar2 + 0x18),1);
      FUN_800175d0((double)lbl_803E65A8,(double)lbl_803E65AC,*(int *)(iVar2 + 0x18));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e514c
 * EN v1.0 Address: 0x801E514C
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x801E50B0
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e514c(uint param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(param_3 + iVar3 + 0x81);
    if (cVar1 == '\x01') {
      *(undefined *)(iVar2 + 4) = 1;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar2 + 4) = 2;
    }
  }
  *(undefined2 *)(param_3 + 0x6e) = 0xfffc;
  if (*(short *)(param_1 + 0xb4) != -1) {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x4;
    iVar2 = FUN_8002fc3c((double)lbl_803E65B0,(double)lbl_803DC074);
    if (iVar2 != 0) {
      FUN_80006824(param_1,SFXfend_rob_beep2);
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e521c
 * EN v1.0 Address: 0x801E521C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801E5194
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e521c(int param_1)
{
  if (**(int **)(param_1 + 0xb8) != 0) {
    ObjLink_DetachChild(param_1,**(int **)(param_1 + 0xb8));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e524c
 * EN v1.0 Address: 0x801E524C
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x801E51CC
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e524c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int local_18;
  int local_14 [2];
  
  piVar4 = *(int **)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
  if (*piVar4 == 0) {
    iVar1 = FUN_80017b00(&local_18,local_14);
    for (local_18 = 0; local_18 < local_14[0]; local_18 = local_18 + 1) {
      iVar3 = *(int *)(iVar1 + local_18 * 4);
      if (*(short *)(iVar3 + 0x46) == 0x121) {
        *piVar4 = iVar3;
        ObjLink_AttachChild(param_9,*piVar4,1);
        local_18 = local_14[0];
      }
    }
  }
  if (((*(byte *)(param_9 + 0xaf) & 4) == 0) || (uVar2 = FUN_80017690(0x92a), uVar2 != 0)) {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_80006ba8(0,0x100);
      (**(code **)(*DAT_803dd6d4 + 0x84))(param_9,0);
      if (*(char *)((int)piVar4 + 5) == '\0') {
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))(1,param_9,0xffffffff);
        *(undefined *)((int)piVar4 + 5) = 1;
      }
      else {
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))(2,param_9,0xffffffff);
      }
    }
    if (*(int *)(param_9 + 0x30) != 0) {
      iVar3 = *(int *)(*(int *)(param_9 + 0x30) + 0xf4);
      iVar1 = FUN_8003964c(param_9,0);
      if (((iVar1 == 0) || (8 < iVar3)) || (*(short *)(param_9 + 0xa0) == 5)) {
        if (((iVar1 != 0) && (8 < iVar3)) && (*(short *)(param_9 + 0xa0) != 9)) {
          *(undefined2 *)(iVar1 + 4) = 0;
          FUN_800305f8((double)lbl_803E65B4,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,9,0,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else {
        *(undefined2 *)(iVar1 + 4) = *(undefined2 *)(*(int *)(param_9 + 0x30) + 4);
        FUN_800305f8((double)lbl_803E65B4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,5,0,param_12,param_13,param_14,param_15,param_16);
      }
    }
    iVar1 = FUN_8002fc3c((double)lbl_803E65B0,(double)lbl_803DC074);
    if (iVar1 != 0) {
      FUN_80006824(param_9,SFXfend_rob_beep2);
    }
  }
  else {
    FUN_80006ba8(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x84))(param_9,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
    FUN_80017698(0x92a,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e55c0
 * EN v1.0 Address: 0x801E55C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E5450
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e55c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e55c4
 * EN v1.0 Address: 0x801E55C4
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801E5564
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e55c4(uint param_1)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  if (0 < *(int *)(param_1 + 0xf4)) {
    *(int *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) + -1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  iVar1 = FUN_80017a98();
  FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
  if (*psVar3 < 1) {
    randomGetRange(0,10);
    uVar2 = FUN_80017690(0xa71);
    if (uVar2 == 0) {
      FUN_80006824(param_1,SFXfend_rob_beep3);
    }
    uVar2 = randomGetRange(400,600);
    *psVar3 = (short)uVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5684
 * EN v1.0 Address: 0x801E5684
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E5688
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5684(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e56ac
 * EN v1.0 Address: 0x801E56AC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801E56BC
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e56ac(int param_1)
{
  uint uVar1;
  
  if (((*(short *)(param_1 + 0x46) == 0x173) && (*(int *)(param_1 + 0xf4) == 0)) &&
     (uVar1 = FUN_80017690(0xa4b), uVar1 != 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5734
 * EN v1.0 Address: 0x801E5734
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801E579C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5734(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5790
 * EN v1.0 Address: 0x801E5790
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801E57F0
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5790(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  
  iVar1 = FUN_80286840();
  if (visible != 0) {
    FUN_8005336c(8);
    FUN_8003b818(iVar1);
    FUN_8005335c(8);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e57e0
 * EN v1.0 Address: 0x801E57E0
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801E586C
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e57e0(short *param_1)
{
  int iVar1;
  double dVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * lbl_803DC074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * lbl_803DC074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * lbl_803DC074 + *(float *)(param_1 + 10);
  local_2c = lbl_803E65C4;
  local_28 = lbl_803E65C4;
  local_24 = lbl_803E65C4;
  local_30 = lbl_803E65C0;
  if ((int)*(uint *)(param_1 + 0x7a) < 0x3d) {
    uStack_1c = *(uint *)(param_1 + 0x7a) ^ 0x80000000;
    local_20 = 0x43300000;
    local_30 = (f32)(s32)uStack_1c / lbl_803E65C8;
    local_18 = 0x43300000;
    iVar1 = (int)(lbl_803E65CC *
                 ((f32)(s32)uStack_1c / lbl_803E65C8
                 ));
    local_10 = (longlong)iVar1;
    *(char *)(param_1 + 0x1b) = (char)iVar1;
    uStack_14 = uStack_1c;
  }
  local_34 = 0;
  local_36 = 0;
  local_38 = 0;
  (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  dVar4 = (double)(*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42));
  dVar5 = (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
  dVar2 = (double)lbl_803E65D0;
  local_2c = (float)((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) / dVar2);
  local_28 = (float)(dVar4 / dVar2);
  local_24 = (float)(dVar5 / dVar2);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  local_2c = local_2c * lbl_803E65D4;
  local_28 = local_28 * lbl_803E65D4;
  local_24 = local_24 * lbl_803E65D4;
  uVar3 = (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  *param_1 = *param_1 + (ushort)DAT_803dc070 * 0x374;
  param_1[1] = param_1[1] + (ushort)DAT_803dc070 * 300;
  *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
  if (*(int *)(param_1 + 0x7a) < 0) {
    FUN_80017ac8(uVar3,dVar4,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e59ec
 * EN v1.0 Address: 0x801E59EC
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801E5A9C
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e59ec(uint param_1)
{
  float fVar1;
  uint uVar2;
  int *piVar3;
  
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  uVar2 = randomGetRange(0x14,0x28);
  fVar1 = lbl_803E65E0;
  *(float *)(param_1 + 0x24) =
       -(lbl_803E65E4 * (f32)(s32)(uVar2)
        + lbl_803E65E0);
  *(float *)(param_1 + 0x28) = lbl_803E65C4;
  *(float *)(param_1 + 0x2c) = lbl_803E65E8;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * fVar1;
  piVar3 = (int *)FUN_80006b14(0x75);
  (**(code **)(*piVar3 + 4))(param_1,DAT_803dcd00,0,0x10002,0xffffffff,0);
  DAT_803dcd00 = DAT_803dcd00 + 1;
  if (3 < DAT_803dcd00) {
    DAT_803dcd00 = 1;
  }
  FUN_80006b0c((undefined *)piVar3);
  FUN_80006824(param_1,SFXen_ripefruit11);
  FUN_80006824(param_1,SFXbaddie_crater_call);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5afc
 * EN v1.0 Address: 0x801E5AFC
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E5BB8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5afc(int param_1)
{
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_1,0xffff,0,0,0);
  if (*(uint *)(param_1 + 0xf8) != 0) {
    FUN_80017620(*(uint *)(param_1 + 0xf8));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5b80
 * EN v1.0 Address: 0x801E5B80
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801E5C34
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5b80(int param_1)
{
  FUN_8003b818(param_1);
  if (*(short *)(param_1 + 0x46) == 0x171) {
    FUN_8008110c((double)lbl_803E65F8,param_1,4,0x185,5,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5bd4
 * EN v1.0 Address: 0x801E5BD4
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x801E5C90
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5bd4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  int local_28;
  int local_24 [6];
  
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_24[2] = (int)DAT_803dc071;
    local_24[1] = 0x43300000;
    local_24[0] = (**(code **)(*DAT_803dd6d4 + 0x14))
                            ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) -
                                            DOUBLE_803e6600));
    if ((local_24[0] != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar4 = (int)*(char *)(*(int *)(param_9 + 0xb8) + 0x57);
      iVar5 = 0;
      uVar6 = extraout_f1;
      piVar1 = (int *)FUN_80017b00(local_24,&local_28);
      iVar3 = 0;
      for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar4) {
          iVar5 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar4 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar5 != 0)) && (*(short *)(iVar5 + 0xb4) != -1)) {
        *(undefined2 *)(iVar5 + 0xb4) = 0xffff;
        uVar6 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar4);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      FUN_80017ac8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5dd0
 * EN v1.0 Address: 0x801E5DD0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x801E5E04
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5dd0(int param_1,int param_2)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar3 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar3 + 0x6e) = 0xffff;
  *(float *)(iVar3 + 0x24) =
       lbl_803E65F4 /
       (lbl_803E65F4 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e6600));
  *(undefined4 *)(iVar3 + 0x28) = 0xffffffff;
  iVar2 = *(int *)(param_1 + 0xf4);
  if ((iVar2 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar3);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar2 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar2 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar3);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar3,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(short *)(param_1 + 0x46) == 0x171) {
    piVar1 = FUN_80017624(param_1,'\x01');
    if (piVar1 != (int *)0x0) {
      FUN_800175b0((int)piVar1,2);
      FUN_8001759c((int)piVar1,200,0x3c,0,0);
      FUN_800175d0((double)lbl_803E6608,(double)lbl_803E660C,(int)piVar1);
    }
    *(int **)(param_1 + 0xf8) = piVar1;
  }
  lbl_803DE8D0 = lbl_803E65F0;
  uRam803de8d4 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5f78
 * EN v1.0 Address: 0x801E5F78
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801E5FA4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5f78(int param_1)
{
  FUN_8000680c(param_1,0x40);
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5fc4
 * EN v1.0 Address: 0x801E5FC4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E5FEC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5fc4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5fec
 * EN v1.0 Address: 0x801E5FEC
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801E601C
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e5fec(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  undefined auStack_28 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  uVar1 = randomGetRange(0,1);
  if (uVar1 == 0) {
    *(undefined *)(param_3 + 0x90) = 8;
  }
  else {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  *(undefined *)(param_3 + 0x56) = 0;
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x20;
  iVar2 = FUN_80017a98();
  if ((iVar2 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    local_20 = lbl_803E6614;
    local_22 = 0xc0d;
    local_1c = local_1c - *(float *)(param_1 + 0x18);
    local_18 = local_18 - *(float *)(param_1 + 0x1c);
    local_14 = local_14 - *(float *)(param_1 + 0x20);
    for (iVar2 = 0; iVar2 < (int)(uint)DAT_803dc070; iVar2 = iVar2 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a8,auStack_28,6,0xffffffff,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e60cc
 * EN v1.0 Address: 0x801E60CC
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x801E6144
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e60cc(uint param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  bool bVar5;
  double dVar6;
  undefined auStack_38 [6];
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24 [2];
  uint uStack_1c;
  
  iVar4 = FUN_80017a98();
  dVar6 = (double)FUN_8001771c((float *)(iVar4 + 0x18),(float *)(param_1 + 0x18));
  bVar5 = FUN_800067f0(param_1,0x40);
  if (bVar5) {
    if ((double)lbl_803E6618 <= dVar6) {
      FUN_8000680c(param_1,0x40);
    }
  }
  else if (dVar6 < (double)lbl_803E6618) {
    FUN_80006824(param_1,SFXmn_eggylaugh216);
  }
  if (*(short *)(param_1 + 0x46) != 0x3e4) {
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xf8) = 1;
      uStack_1c = randomGetRange(0,0x5a);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_24[1] = 176.0;
      FUN_800305c4((double)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6628) /
                           lbl_803E6618),param_1);
    }
    FUN_8002fc3c((double)lbl_803E661C,(double)lbl_803DC074);
  }
  if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
    local_30 = lbl_803E6614;
    local_32 = 0xc0d;
    local_2c = lbl_803E6620;
    local_28 = lbl_803E6624;
    local_24[0] = lbl_803E6620;
    ObjPath_GetPointWorldPosition(param_1,0,&local_2c,&local_28,local_24,1);
    if (*(int *)(param_1 + 0x30) == 0) {
      fVar1 = *(float *)(param_1 + 0xc);
      fVar2 = *(float *)(param_1 + 0x10);
      fVar3 = *(float *)(param_1 + 0x14);
    }
    else {
      fVar1 = *(float *)(param_1 + 0x18);
      fVar2 = *(float *)(param_1 + 0x1c);
      fVar3 = *(float *)(param_1 + 0x20);
    }
    local_24[0] = local_24[0] - fVar3;
    local_28 = local_28 - fVar2;
    local_2c = local_2c - fVar1;
    for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7c7,auStack_38,2,0xffffffff,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e62b8
 * EN v1.0 Address: 0x801E62B8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E63C8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e62b8(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e62e0
 * EN v1.0 Address: 0x801E62E0
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801E63FC
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e62e0(int param_1)
{
  double dVar1;
  undefined8 local_18;
  
  if (*(short *)(param_1 + 0x46) == 0x187) {
    FUN_8002fc3c((double)lbl_803E6644,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e6650))
    ;
  }
  else if (*(short *)(param_1 + 0x46) == 0x803) {
    FUN_80017a98();
    dVar1 = DOUBLE_803e6638;
    if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
      *(float *)(param_1 + 0x24) =
           (float)((double)CONCAT44(0x43300000,
                                    (int)*(short *)(*(int *)(param_1 + 0x30) + 4) ^ 0x80000000) -
                  DOUBLE_803e6638) * lbl_803E6634;
      *(short *)(param_1 + 4) =
           (short)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_1 + 4) ^ 0x80000000) - dVar1)
                       + *(float *)(param_1 + 0x24));
    }
    else {
      *(float *)(param_1 + 0x24) = lbl_803E6630;
    }
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    FUN_8002fc3c((double)lbl_803E6648,(double)(float)(local_18 - DOUBLE_803e6650));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e63f4
 * EN v1.0 Address: 0x801E63F4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x801E6510
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e63f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  if (param_9[0x23] != 0x803) {
    *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
    FUN_800305f8((double)lbl_803E6630,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e64c4
 * EN v1.0 Address: 0x801E64C4
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801E6578
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e64c4(void)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  uVar2 = FUN_80017690((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1e));
  if (uVar2 != 0) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6510
 * EN v1.0 Address: 0x801E6510
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801E65EC
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6510(uint param_1)
{
  uint uVar1;
  
  uVar1 = FUN_80017690((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 != 0) {
    FUN_80006824(param_1,SFXen_nlite1_c);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6558
 * EN v1.0 Address: 0x801E6558
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x801E66B0
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6558(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_80017a98();
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar2 = (**(code **)(*DAT_803dd72c + 0x8c))();
  uVar4 = FUN_80294d28(iVar1,-param_10);
  switch(*(undefined *)(iVar3 + 1)) {
  case 0:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,2);
    break;
  case 1:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,8);
    break;
  case 2:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,4);
    break;
  case 3:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x1c);
    break;
  case 4:
    FUN_80017688(0x66c);
    break;
  case 5:
    FUN_80017688(0x86a);
    break;
  case 6:
    FUN_80017688(0xc1);
    break;
  case 7:
    FUN_80017688(0x13d);
    FUN_80017688(0x5d6);
    break;
  case 8:
    FUN_80017688(0x3f5);
    break;
  case 0x17:
    *(undefined *)(iVar2 + 10) = 10;
  }
  if ((int)*(short *)(&DAT_80328c18 + *(char *)(iVar3 + 1) * 0xc) != 0xffffffff) {
    FUN_80017698((int)*(short *)(&DAT_80328c18 + *(char *)(iVar3 + 1) * 0xc),1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void SB_FireBall_release(void) {}
void SB_FireBall_initialise(void) {}
void SB_CloudBall_release(void) {}
void SB_CloudBall_initialise(void) {}
void SB_KyteCage_render(void) {}
void SB_KyteCage_hitDetect(void) {}
void SB_KyteCage_release(void) {}
void SB_KyteCage_initialise(void) {}
void SB_CageKyte_free(void) {}
void SB_CageKyte_hitDetect(void) {}
void SB_CageKyte_release(void) {}
void SB_CageKyte_initialise(void) {}
void SB_SeqDoor_free(void) {}
void SB_SeqDoor_hitDetect(void) {}
void SB_SeqDoor_release(void) {}
void SB_SeqDoor_initialise(void) {}
void SB_MiniFire_hitDetect(void) {}
void SB_MiniFire_release(void) {}
void SB_MiniFire_initialise(void) {}
void ShipBattle_hitDetect(void) {}
void ShipBattle_release(void) {}
void ShipBattle_initialise(void) {}
void Flag_free(void) {}
void Flag_hitDetect(void) {}
void Flag_release(void) {}
void Flag_initialise(void) {}
void SB_ShipGunBroke_free(void) {}
void SB_ShipGunBroke_hitDetect(void) {}
void SB_ShipGunBroke_init(void) {}
void SB_ShipGunBroke_release(void) {}
void SB_ShipGunBroke_initialise(void) {}
void shop_hitDetect(void) {}
void shop_release(void) {}
void shop_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int SB_CloudBall_getExtraSize(void) { return 0x24; }
int SB_CloudBall_getObjectTypeId(void) { return 0x0; }
int SB_KyteCage_getExtraSize(void) { return 0x8; }
int SB_KyteCage_getObjectTypeId(void) { return 0x0; }
int SB_CageKyte_getExtraSize(void) { return 0x2; }
int SB_CageKyte_getObjectTypeId(void) { return 0x1; }
int SB_SeqDoor_getExtraSize(void) { return 0x0; }
int SB_SeqDoor_getObjectTypeId(void) { return 0x0; }
int SB_MiniFire_getExtraSize(void) { return 0x2; }
int SB_MiniFire_getObjectTypeId(void) { return 0x0; }
int ShipBattle_getExtraSize(void) { return 0x140; }
int ShipBattle_getObjectTypeId(void) { return 0xb; }
int Lamp_getExtraSize(void) { return 0x1; }
int Flag_getExtraSize(void) { return 0x0; }
int Flag_getObjectTypeId(void) { return 0x0; }
int SB_ShipGunBroke_getExtraSize(void) { return 0x1; }
int SB_ShipGunBroke_getObjectTypeId(void) { return 0x0; }
int shop_getExtraSize(void) { return 0x5; }
int shop_getObjectTypeId(void) { return 0x0; }
int fn_801E66DC(void) { return 0x0; }
int fn_801E66E4(void) { return 0x0; }

/* 16b chained patterns. */
s32 shop_getStateField1(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x1); }
s32 shop_setScale(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x0); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58E8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5920;
extern f32 lbl_803E5978;
extern f32 lbl_803E59A8;
extern f32 lbl_803E59C8;
extern int* gObjectTriggerInterface;
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern int* gExpgfxInterface;
extern int* gModgfxInterface;
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern int GameBit_Get(int);
extern void GameBit_Set(int slot, int val);
extern u8 framesThisStep;
extern void ObjAnim_SetCurrentMove(int* obj, int a, f32 t, int c);
extern int ObjAnim_AdvanceCurrentMove(int obj, f32 moveStepScale, f32 deltaTime, int events);
extern void ObjAnim_SetMoveProgress(f32 progress, int obj);
extern void *Obj_GetPlayerObject(void);
extern f32 Vec_distance(void *a, void *b);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int obj, int group);
extern void ModelLightStruct_free(int* p);
extern void skyFn_80088c94(int a, int b);
extern void Music_Trigger(int a, int b);
extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);
extern f32 lbl_803E5998;
extern f32 lbl_803E599C;
extern f32 lbl_803E59AC;
extern f32 lbl_803E59B0;
extern f32 lbl_803E5958;
extern f32 lbl_803E595C;
extern f64 lbl_803E5968;
extern f32 lbl_803E5970;
extern f32 lbl_803E5974;
extern f32 lbl_803E5960;
extern f32 lbl_803E5918;
extern f32 lbl_803E59D8;
extern f32 lbl_803E59DC;
extern f32 timeDelta;
extern u8 lbl_803DB411;
extern f32 lbl_803DDC50;
extern int* lbl_803DCAB4;
#define gBoneParticleEffectInterface lbl_803DCAB4
extern int Stack_IsEmpty(int stack);
extern int Stack_Pop(int stack, int *out);
int fn_801E5060(int p1, int p2, int p3);
void fn_801E5A2C(void);
#pragma peephole off
void SB_CloudBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E58E8); }
void SB_SeqDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5920); }
void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5978); }
void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E59A8); }
void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E59C8); }
#pragma peephole reset

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */
#pragma scheduling off
#pragma peephole off
void Flag_init(int* obj, int* def)
{
    if (*(s16*)((char*)obj + 0x46) != 0x803) {
        *(s16*)obj = (s16)((s32)*(s8*)((char*)def + 0x18) << 8);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E5998, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Flag_update(int obj)
{
    int linkedObj;

    if (*(s16 *)(obj + 0x46) == 0x187) {
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E59AC, (f32)(u32)framesThisStep, 0);
    } else if (*(s16 *)(obj + 0x46) == 0x803) {
        Obj_GetPlayerObject();
        linkedObj = *(int *)(obj + 0x30);
        if ((*(u16 *)(linkedObj + 0xb0) & 0x1000) != 0) {
            *(f32 *)(obj + 0x24) = lbl_803E5998;
        } else {
            *(f32 *)(obj + 0x24) = (f32)*(s16 *)(linkedObj + 4) * lbl_803E599C;
            *(s16 *)(obj + 4) = (s16)((f32)*(s16 *)(obj + 4) + *(f32 *)(obj + 0x24));
        }
    } else {
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E59B0, (f32)(u32)framesThisStep, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
int SB_KyteCage_SeqFn(int obj, int unused, int seqState)
{
    int i;
    int state;

    i = 0;
    state = *(int *)(obj + 0xb8);
    while (i < *(u8 *)(seqState + 0x8b)) {
        u8 seqCode;

        seqCode = *(u8 *)(seqState + (i + 0x81));
        if (seqCode == 1) {
            *(u8 *)(state + 4) = 1;
        } else if (seqCode == 2) {
            *(u8 *)(state + 4) = 2;
        }
        i++;
    }

    *(s16 *)(seqState + 0x6e) = -4;
    if (*(s16 *)(obj + 0xb4) != -1) {
        *(s16 *)(seqState + 0x6e) = (s16)(*(s16 *)(seqState + 0x6e) & ~4);
        if (ObjAnim_AdvanceCurrentMove(obj, lbl_803E5918, timeDelta, 0) != 0) {
            Sfx_PlayFromObject((int *)obj, SFXfend_rob_beep2);
        }
    }

    *(u8 *)(seqState + 0x56) = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */
#pragma scheduling off
#pragma peephole off
int SB_CageKyte_SeqFn(int* obj, int p2, void* state)
{
    int v = *(int*)((char*)obj + 0xf4);
    if (v > 0) {
        *(int*)((char*)obj + 0xf4) = v - 1;
    }
    *(u8*)((char*)obj + 0xaf) |= 0x8;
    *(s16*)((char*)state + 0x6e) = -2;
    *(u8*)((char*)state + 0x56) = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole off
#pragma scheduling off
int SB_SeqDoor_SeqFn(int p1, int p2, int p3)
{
    if (*(s16 *)((char *)p1 + 0x46) != 0x173) {
        *(s16 *)((char *)p3 + 0x6e) = -2;
    }
    *(u8 *)((char *)p3 + 0x56) = 0;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
extern f32 lbl_803E597C;
extern f32 lbl_803E5980;
extern f32 lbl_803E5984;
extern f32 lbl_803E5988;
extern f32 lbl_803E598C;
extern f64 lbl_803E5990;

#pragma scheduling off
#pragma peephole off
int Lamp_SeqFn(int obj, int unused, int state)
{
    u8 effectArgs[0x18];
    int i;

    if ((s32)randomGetRange(0, 1) != 0) {
        *(u8 *)(state + 0x90) = 4;
    } else {
        *(u8 *)(state + 0x90) = 8;
    }
    *(u8 *)(state + 0x56) = 0;
    *(s16 *)(state + 0x6e) = -1;
    *(s16 *)(state + 0x6e) = (s16)(*(s16 *)(state + 0x6e) & ~0x20);

    if (Obj_GetPlayerObject() == NULL) {
        return 0;
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
        *(f32 *)(effectArgs + 8) = lbl_803E597C;
        *(s16 *)(effectArgs + 6) = 0xc0d;
        *(f32 *)(effectArgs + 0xc) = *(f32 *)(effectArgs + 0xc) - *(f32 *)(obj + 0x18);
        *(f32 *)(effectArgs + 0x10) = *(f32 *)(effectArgs + 0x10) - *(f32 *)(obj + 0x1c);
        *(f32 *)(effectArgs + 0x14) = *(f32 *)(effectArgs + 0x14) - *(f32 *)(obj + 0x20);
        for (i = 0; i < framesThisStep; i++) {
            ((void (*)(int, int, void *, int, int, int))((void **)*gPartfxInterface)[2])(
                obj, 0x7a8, effectArgs, 6, -1, 0);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
int fn_801E66EC(int arg1, int arg2)
{
    int state;
    f32 local;
    int stk;
    int popOut;

    state = *(int *)(arg1 + 0xb8);
    local = lbl_803E59D8;

    if (*(s8 *)(arg2 + 0x27a) != 0) {
        if ((*(u16 *)(arg1 + 0xb0) & 0x800) != 0) {
            ((void (*)(int, int, f32 *, int, int))((void **)*gBoneParticleEffectInterface)[3])(
                arg1, 2031, &local, 80, 0);
        }
    }

    *(u8 *)(state + 0x9d6) = 0;
    *(f32 *)(arg2 + 0x280) = lbl_803E59DC;
    if (*(u8 *)(state + 0x9d6) == 0) {
        stk = *(int *)(state + 0x9b0);
        popOut = 0;
        if (Stack_IsEmpty(stk) == 0) {
            Stack_Pop(stk, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void Lamp_free(int* obj)
{
    Sfx_StopObjectChannel(obj, 64);
    ((void(*)(int*))((void**)*gExpgfxInterface)[6])(obj);
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Lamp_init(int* obj, int* def)
{
    int* state = *(int**)((char*)obj + 0xb8);
    if (*(s16*)((char*)obj + 0x46) == 996) {
        *(s16*)obj = (s16)((u32)*(u8*)((char*)def + 26) << 8);
    } else {
        *(s16*)obj = (s16)((s32)*(s8*)((char*)def + 24) << 8);
    }
    *(s16*)((char*)obj + 2) = 0;
    *(s16*)((char*)obj + 4) = 0;
    *(int*)((char*)obj + 248) = 0;
    *(s8*)state = 1;
    *(void**)((char*)obj + 0xbc) = (void*)fn_801E5A2C;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Lamp_update(int obj)
{
    u8 effectArgs[0x18];
    f32 distance;
    int i;

    distance = Vec_distance((void *)((int)Obj_GetPlayerObject() + 0x18), (void *)(obj + 0x18));
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) == 0) {
        if (distance < lbl_803E5980) {
            Sfx_PlayFromObject((int *)obj, SFXmn_eggylaugh216);
        }
    } else if (distance >= lbl_803E5980) {
        Sfx_StopObjectChannel((int *)obj, 0x40);
    }

    if (*(s16 *)(obj + 0x46) != 0x3e4) {
        if (*(int *)(obj + 0xf8) == 0) {
            *(int *)(obj + 0xf8) = 1;
            ObjAnim_SetMoveProgress((f32)(s32)randomGetRange(0, 90) / lbl_803E5980, obj);
        }
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E5984, timeDelta, 0);
    }

    if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
        *(f32 *)(effectArgs + 8) = lbl_803E597C;
        *(s16 *)(effectArgs + 6) = 0xc0d;
        *(f32 *)(effectArgs + 0xc) = lbl_803E5988;
        *(f32 *)(effectArgs + 0x10) = lbl_803E598C;
        *(f32 *)(effectArgs + 0x14) = lbl_803E5988;
        ObjPath_GetPointWorldPosition(obj, 0, (f32 *)(effectArgs + 0xc), (f32 *)(effectArgs + 0x10),
                                      (f32 *)(effectArgs + 0x14), 1);
        if (*(void **)(obj + 0x30) != NULL) {
            *(f32 *)(effectArgs + 0xc) = *(f32 *)(effectArgs + 0xc) - *(f32 *)(obj + 0x18);
            *(f32 *)(effectArgs + 0x10) = *(f32 *)(effectArgs + 0x10) - *(f32 *)(obj + 0x1c);
            *(f32 *)(effectArgs + 0x14) = *(f32 *)(effectArgs + 0x14) - *(f32 *)(obj + 0x20);
        } else {
            *(f32 *)(effectArgs + 0xc) = *(f32 *)(effectArgs + 0xc) - *(f32 *)(obj + 0xc);
            *(f32 *)(effectArgs + 0x10) = *(f32 *)(effectArgs + 0x10) - *(f32 *)(obj + 0x10);
            *(f32 *)(effectArgs + 0x14) = *(f32 *)(effectArgs + 0x14) - *(f32 *)(obj + 0x14);
        }
        for (i = 0; i < framesThisStep; i++) {
            ((void (*)(int, int, void *, int, int, int))((void **)*gPartfxInterface)[2])(
                obj, 0x7c7, effectArgs, 2, -1, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole off
#pragma scheduling off
void SB_CageKyte_init(int p)
{
    *(void **)((char *)p + 0xbc) = (void *)SB_CageKyte_SeqFn;
    *(u16 *)((char *)p + 0xb0) = (u16)((u32)*(u16 *)((char *)p + 0xb0) | 0x6000u);
}
#pragma scheduling reset
#pragma peephole reset
#pragma peephole off
void SB_CageKyte_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void SB_CageKyte_update(int obj)
{
    s16 *state;
    int player;

    state = *(s16 **)(obj + 0xb8);
    if (*(int *)(obj + 0xf4) > 0) {
        *(int *)(obj + 0xf4) = *(int *)(obj + 0xf4) - 1;
    }

    *(u8 *)(obj + 0xaf) = *(u8 *)(obj + 0xaf) | 8;
    *state -= framesThisStep;
    player = (int)Obj_GetPlayerObject();
    Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18));

    if (*state <= 0) {
        randomGetRange(0, 10);
        if ((u32)GameBit_Get(0xa71) == 0u) {
            Sfx_PlayFromObject((int *)obj, SFXfend_rob_beep3);
        }
        *state = (s16)randomGetRange(400, 600);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void SB_CloudBall_free(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    ((void(*)(int*))((void**)*gExpgfxInterface)[6])(obj);
    {
        int* child = *(int**)((char*)state + 24);
        if (child != NULL) {
            ModelLightStruct_free(child);
            *(int**)((char*)state + 24) = NULL;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E58E8;
extern f32 lbl_803E58EC;
extern f32 lbl_803E58F0;
extern void projectileParticleFxFn_80099660(int *obj, f32 scale, int type);

#pragma scheduling off
#pragma peephole off
void SB_CloudBall_hitDetect(int *obj)
{
    int *state = *(int **)((char *)obj + 0xb8);
    int *params = *(int **)((char *)obj + 0x54);
    int *target = *(int **)((char *)params + 0x50);

    if ((void *)target == NULL) return;
    if (*(f32 *)((char *)state + 0x20) != lbl_803E58EC) return;
    if (*(s16 *)((char *)target + 0x46) == 142) {
        Sfx_PlayFromObject(obj, SFXen_rockshat16);
    }
    params = *(int **)((char *)obj + 0x54);
    *(s16 *)((char *)params + 0x60) = (s16)(*(s16 *)((char *)params + 0x60) & ~1);
    *(f32 *)((char *)state + 0x20) = lbl_803E58F0;
    *(u8 *)((char *)obj + 0x36) = 0;
    projectileParticleFxFn_80099660(obj, lbl_803E58E8, 2);
}
#pragma peephole reset
#pragma scheduling reset
extern int objCreateLight(int *obj, int mode);
extern void modelLightStruct_setField50(int light, int v);
extern void modelLightStruct_setColorsA8AC(int light, int p, int r, int g, int p2);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void lightDistAttenFn_8001dc38(int light, f32 a, f32 b);
extern f32 lbl_803E5910;
extern f32 lbl_803E5914;

#pragma scheduling off
#pragma peephole off
void SB_CloudBall_init(int *obj)
{
    int *state = *(int **)((char *)obj + 0xb8);
    int *params = *(int **)((char *)obj + 0x54);

    *(s16 *)((char *)params + 0x60) = (s16)(*(s16 *)((char *)params + 0x60) & ~1);
    params = *(int **)((char *)obj + 0x54);
    *(u16 *)((char *)params + 0xb2) = (u16)(*(u16 *)((char *)params + 0xb2) | 1);
    if (((void **)state)[6] == NULL) {
        state[6] = objCreateLight(obj, 1);
        if (((void **)state)[6] != NULL) {
            modelLightStruct_setField50(state[6], 2);
            modelLightStruct_setColorsA8AC(state[6], 0, 90, 150, 0);
            lightSetFieldBC_8001db14(state[6], 1);
            lightDistAttenFn_8001dc38(state[6], lbl_803E5910, lbl_803E5914);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E58F4;
extern f32 lbl_803E58F8;
extern f32 lbl_803E58FC;
extern f32 lbl_803E5900;
extern f32 lbl_803E5904;
extern f64 lbl_803E5908;
extern f32 lbl_803E58E8_;  // dummy to avoid duplicate
extern void Obj_FreeObject(int obj);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E58DC;
extern f32 lbl_803E58E0;
extern void *Obj_GetPlayerObject(void);
#pragma scheduling off
#pragma peephole off
void SB_CloudBall_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *player = Obj_GetPlayerObject();
    f32 timer = *(f32 *)(state + 0x20);
    f32 zero = lbl_803E58EC;
    if (timer != zero) {
        *(f32 *)(state + 0x20) = timer - timeDelta;
        if (*(f32 *)(state + 0x20) <= zero) {
            *(f32 *)(state + 0x20) = zero;
            Obj_FreeObject(obj);
        }
    } else {
        f32 particleVelocity[3];
        f32 velocityScale;
        *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
        *(f32 *)(obj + 0x8) = lbl_803E58F8 * (f32)(int)randomGetRange(-0x64, 0x64) + lbl_803E58F4;
        if (*(s8 *)(state + 0x1c) == 0) {
            *(f32 *)state = *(f32 *)(obj + 0x24);
            *(f32 *)(state + 0x4) = *(f32 *)(obj + 0x28);
            *(f32 *)(state + 0x8) = *(f32 *)(obj + 0x2c);
            *(u8 *)(state + 0x1c) = 1;
            *(f32 *)(state + 0xc) = *(f32 *)(obj + 0xc);
            *(f32 *)(state + 0x10) = *(f32 *)(obj + 0x10);
            *(f32 *)(state + 0x14) = *(f32 *)(obj + 0x14);
        }
        velocityScale = lbl_803E58FC;
        *(f32 *)(state + 0xc) = velocityScale * (*(f32 *)state * timeDelta) + *(f32 *)(state + 0xc);
        *(f32 *)(state + 0x10) = velocityScale * (*(f32 *)(state + 0x4) * timeDelta) + *(f32 *)(state + 0x10);
        *(f32 *)(state + 0x14) = velocityScale * (*(f32 *)(state + 0x8) * timeDelta) + *(f32 *)(state + 0x14);
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x14);
        *(int *)(obj + 0xf4) = *(int *)(obj + 0xf4) - framesThisStep;
        if (*(int *)(obj + 0xf4) < 0 || (player != NULL && (*(u16 *)((char *)player + 0xb0) & 0x1000) != 0)) {
            if (*(f32 *)(state + 0x20) == lbl_803E58EC) {
                *(u8 *)(obj + 0x36) = 0;
                *(f32 *)(state + 0x20) = lbl_803E58F0;
            }
        }
        *(s16 *)obj = (s16)getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80),
                                     *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
        *(u8 *)(*(int *)(obj + 0x54) + 0x6e) = 5;
        *(u8 *)(*(int *)(obj + 0x54) + 0x6f) = 1;
        *(int *)(*(int *)(obj + 0x54) + 0x48) = 0x10;
        *(int *)(*(int *)(obj + 0x54) + 0x4c) = 0x10;
        *(s16 *)(*(int *)(obj + 0x54) + 0x60) = (s16)(*(s16 *)(*(int *)(obj + 0x54) + 0x60) | 1);
        if (*(s8 *)(*(int *)(obj + 0x54) + 0xad) != 0 && *(f32 *)(state + 0x20) == lbl_803E58EC) {
            projectileParticleFxFn_80099660((int *)obj, lbl_803E58E8, 2);
            *(f32 *)(state + 0x20) = lbl_803E58F0;
            *(u8 *)(obj + 0x36) = 0;
        }
        particleVelocity[0] = lbl_803E5900 * -*(f32 *)state;
        particleVelocity[1] = lbl_803E5900 * -*(f32 *)(state + 0x4);
        particleVelocity[2] = lbl_803E5900 * -*(f32 *)(state + 0x8);
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E5904, 2, 0x156, 0xf, particleVelocity);
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E5904, 2, 0x156, 0xf, particleVelocity);
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E5904, 2, 0x156, 0xf, particleVelocity);
        ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0xa8, 0, 2, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole off
#pragma scheduling off
void SB_FireBall_init(int p)
{
    int *state = *(int **)(p + 0xb8);
    *(int *)((char *)p + 0xf4) = 0x4b0;
    *(u8 *)((char *)state + 0x14) = 0;
}
#pragma scheduling reset
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void SB_FireBall_update(int obj)
{
    int state;
    f32 particleArgs[7];

    state = *(int *)(obj + 0xb8);
    if (*(void **)state == NULL) {
        *(void **)state = *(void **)(obj + 0xf8);
    }

    if (*(void **)state != NULL) {
        *(s16 *)obj = 0;
        *(s16 *)(obj + 4) = (s16)(*(s16 *)(obj + 4) + framesThisStep * SB_FIREBALL_SPIN_STEP);
        *(int *)(obj + 0xf4) -= framesThisStep;
        if (*(int *)(obj + 0xf4) < 0) {
            Obj_FreeObject(obj);
            return;
        }

        if (*(s8 *)(state + 0x14) == 0) {
            *(f32 *)(state + 0x08) = *(f32 *)(obj + 0x24);
            *(f32 *)(state + 0x0c) = *(f32 *)(obj + 0x28);
            *(f32 *)(state + 0x10) = *(f32 *)(obj + 0x2c);
            *(u8 *)(state + 0x14) = 1;
        }

        *(f32 *)(obj + 0x0c) += *(f32 *)(state + 0x08) * timeDelta;
        *(f32 *)(obj + 0x10) += *(f32 *)(state + 0x0c) * timeDelta;
        *(f32 *)(obj + 0x14) += *(f32 *)(state + 0x10) * timeDelta;

        particleArgs[2] = lbl_803E58DC;
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E58E0, SB_FIREBALL_SETUP_SIZE,
                                     SB_FIREBALL_SETUP_MODEL_ID, SB_FIREBALL_SETUP_PARAM, NULL);
        ((void (*)(int, int, f32 *, int, int, int))((void **)*gPartfxInterface)[2])(
            obj, SB_FIREBALL_TRAIL_PARTICLE_ID, particleArgs, 1, -1, 0);

        if (*(s16 *)(state + 4) > SB_FIREBALL_HITBOX_ENABLE_DELAY) {
            *(u8 *)(*(int *)(obj + 0x54) + 0x6e) = SB_FIREBALL_HITBOX_TYPE;
            *(u8 *)(*(int *)(obj + 0x54) + 0x6f) = SB_FIREBALL_HITBOX_PRIORITY;
            *(int *)(*(int *)(obj + 0x54) + 0x48) = SB_FIREBALL_HITBOX_SIZE;
            *(int *)(*(int *)(obj + 0x54) + 0x4c) = SB_FIREBALL_HITBOX_SIZE;
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) =
                (s16)(*(s16 *)(*(int *)(obj + 0x54) + 0x60) | SB_FIREBALL_SOLID_HITBOX_FLAG);
        } else {
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) =
                (s16)(*(s16 *)(*(int *)(obj + 0x54) + 0x60) & ~SB_FIREBALL_SOLID_HITBOX_FLAG);
        }

        *(s16 *)(state + 4) += framesThisStep;
    }
}
#pragma peephole reset
#pragma scheduling reset
/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */
#pragma scheduling off
#pragma peephole off
void SB_KyteCage_free(int* obj)
{
    void *child = **(void***)((char*)obj + 0xb8);
    if (child != NULL) {
        ObjLink_DetachChild(obj, child);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern int SB_KyteCage_SeqFn(int obj, int unused, int seqState);

#pragma scheduling off
#pragma peephole off
void SB_KyteCage_init(int *obj, int *params)
{
    int *state = *(int **)((char *)obj + 0xb8);
    *(int (**)(int, int, int))((char *)obj + 0xbc) = SB_KyteCage_SeqFn;
    *(s16 *)obj = (s16)((s8) * (s8 *)((char *)params + 0x18) << 8);
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
    *(u8 *)((char *)state + 0x4) = 0;
    if ((u32)GameBit_Get(117) == 0u) {
        getLActions(obj, obj, 88, 0, 0, 0);
        getLActions(obj, obj, 109, 0, 0, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern int *ObjList_GetObjects(int *out_head, int *out_count);
extern void buttonDisable(int controller, int mask);
extern int *objModelGetVecFn_800395d8(int obj, int idx);
extern int ObjAnim_AdvanceCurrentMove(int obj, f32 b, f32 dt, int a);
extern f32 lbl_803E5918;
extern f32 lbl_803E591C;
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
void SB_KyteCage_update(int obj)
{
    extern uint GameBit_Get(int);
    int state = *(int *)(obj + 0xb8);
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~0x8);
    if (*(void **)state == NULL) {
        int *head;
        int count;
        int i;
        head = ObjList_GetObjects(&i, &count);
        for (i = 0; i < count; i++) {
            int child = head[i];
            if (*(s16 *)(child + 0x46) == 0x121) {
                *(int *)state = child;
                ObjLink_AttachChild(obj, *(int *)state, 1);
                i = count;
            }
        }
    }
    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
        if (GameBit_Get(0x92a) == 0) {
            buttonDisable(0, 0x100);
            ((void (*)(int, int))((void **)*gObjectTriggerInterface)[0x84/4])(obj, 0);
            ((void (*)(int, int, int))((void **)*gObjectTriggerInterface)[0x48/4])(3, obj, -1);
            GameBit_Set(0x92a, 1);
            return;
        }
    }
    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
        buttonDisable(0, 0x100);
        ((void (*)(int, int))((void **)*gObjectTriggerInterface)[0x84/4])(obj, 0);
        if (*(u8 *)(state + 5) != 0) {
            ((void (*)(int, int, int))((void **)*gObjectTriggerInterface)[0x48/4])(2, obj, -1);
        } else {
            ((void (*)(int, int, int))((void **)*gObjectTriggerInterface)[0x48/4])(1, obj, -1);
            *(u8 *)(state + 5) = 1;
        }
    }
    if (*(void **)(obj + 0x30) != NULL) {
        int kind = *(int *)(*(int *)(obj + 0x30) + 0xf4);
        int *mvec = objModelGetVecFn_800395d8(obj, 0);
        if (mvec != 0 && kind < 9 && *(s16 *)(obj + 0xa0) != 5) {
            *(s16 *)((char *)mvec + 4) = *(s16 *)(*(int *)(obj + 0x30) + 4);
            ObjAnim_SetCurrentMove((int *)obj, 5, lbl_803E591C, 0);
        } else if (mvec != 0 && kind >= 9 && *(s16 *)(obj + 0xa0) != 9) {
            *(s16 *)((char *)mvec + 4) = 0;
            ObjAnim_SetCurrentMove((int *)obj, 9, lbl_803E591C, 0);
        }
    }
    if (ObjAnim_AdvanceCurrentMove(obj, lbl_803E5918, timeDelta, 0) != 0) {
        Sfx_PlayFromObject((int *)obj, SFXfend_rob_beep2);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void SB_MiniFire_free(int* obj)
{
    ((void(*)(int*))((void**)*gExpgfxInterface)[6])(obj);
    ((void(*)(int*))((void**)*gModgfxInterface)[6])(obj);
}
#pragma peephole reset
#pragma scheduling reset
extern int Resource_Acquire(int id, int mode);
extern void Resource_Release(int resource);
extern int lbl_803DC098;
extern f32 lbl_803E592C;
extern f32 lbl_803E5948;
extern f32 lbl_803E594C;
extern f32 lbl_803E5950;

#pragma scheduling off
#pragma peephole off
void SB_MiniFire_init(int obj)
{
    int resource;

    *(int *)(obj + 0xf4) = 180;
    *(f32 *)(obj + 0x24) = -(lbl_803E594C * (f32)(s32)randomGetRange(20, 40)) + lbl_803E5948;
    *(f32 *)(obj + 0x28) = lbl_803E592C;
    *(f32 *)(obj + 0x2c) = lbl_803E5950;
    *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * lbl_803E5948;

    resource = Resource_Acquire(117, 1);
    (*(void (**)(int, int, int, int, int, int))(*(int *)resource + 4))(
        obj, lbl_803DC098, 0, 0x10002, -1, 0);
    lbl_803DC098++;
    if (lbl_803DC098 > 3) {
        lbl_803DC098 = 1;
    }
    Resource_Release(resource);
    Sfx_PlayFromObject((int *)obj, SFXen_ripefruit11);
    Sfx_PlayFromObject((int *)obj, SFXbaddie_crater_call);
}
#pragma peephole reset
#pragma scheduling reset
extern void fn_80053ED0(int);
extern void fn_80053EBC(int);
extern f32 lbl_803E5928;

#pragma scheduling off
#pragma peephole off
void SB_MiniFire_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) {
        fn_80053ED0(8);
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5928);
        fn_80053EBC(8);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern f64 lbl_803E5940;
extern f32 lbl_803E5930;
extern f32 lbl_803E5934;
extern f32 lbl_803E5938;
extern f32 lbl_803E593C;
extern f32 timeDelta;
extern u8 framesThisStep;
extern void Obj_FreeObject(int obj);
#pragma scheduling off
#pragma peephole off
void SB_MiniFire_update(int obj)
{
    f32 buf[8];
    f32 dx;
    f32 dy;
    f32 dz;
    int dt;
    *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0x24) * timeDelta + *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x2c) * timeDelta + *(f32 *)(obj + 0x14);
    buf[3] = lbl_803E592C;
    buf[4] = lbl_803E592C;
    buf[5] = lbl_803E592C;
    buf[2] = lbl_803E5928;
    if (*(int *)(obj + 0xf4) <= 0x3c) {
        buf[2] = (f32)*(int *)(obj + 0xf4) / lbl_803E5930;
        *(u8 *)(obj + 0x36) = (u8)(int)(lbl_803E5934 * ((f32)*(int *)(obj + 0xf4) / lbl_803E5930));
    }
    *(s16 *)((char *)buf + 4) = 0;
    *(s16 *)((char *)buf + 2) = 0;
    *(s16 *)((char *)buf + 0) = 0;
    ((void (*)(int, int, void *, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0xa0, buf, 1, -1, 0);
    dy = *(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84);
    dz = *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88);
    dx = *(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80);
    buf[3] = dx / lbl_803E5938;
    buf[4] = dy / lbl_803E5938;
    buf[5] = dz / lbl_803E5938;
    ((void (*)(int, int, void *, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0xa0, buf, 1, -1, 0);
    buf[3] = buf[3] * lbl_803E593C;
    buf[4] = buf[4] * lbl_803E593C;
    buf[5] = buf[5] * lbl_803E593C;
    ((void (*)(int, int, void *, int, int, int))((void **)*gPartfxInterface)[2])(obj, 0xa0, buf, 1, -1, 0);
    *(s16 *)obj = *(s16 *)obj + framesThisStep * 0x374;
    *(s16 *)(obj + 2) = *(s16 *)(obj + 2) + framesThisStep * 0x12c;
    *(int *)(obj + 0xf4) = *(int *)(obj + 0xf4) - framesThisStep;
    if (*(int *)(obj + 0xf4) < 0) {
        Obj_FreeObject(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void SB_SeqDoor_init(int* obj, int* def)
{
    *(void**)((char*)obj + 0xbc) = (void*)fn_801E5060;
    *(s16*)obj = (s16)((s32)*(s8*)((char*)def + 24) << 8);
    {
        s8 b = *(s8*)((char*)def + 25);
        *(s8*)((char*)obj + 0xad) = (s8)(((u32)-b | (u32)b) >> 31);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void SB_SeqDoor_update(int *obj)
{
    if (*(s16 *)((char *)obj + 0x46) == 371) {
        if (*(int *)((char *)obj + 0xf4) == 0) {
            if ((u32)GameBit_Get(2635) != 0u) {
                ((void (*)(int, int *, int))((void **)*gObjectTriggerInterface)[18])(0, obj, -1);
                *(int *)((char *)obj + 0xf4) = 1;
            }
        }
    }
    *(u8 *)((char *)obj + 0xaf) |= 0x10;
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E59C0;

#pragma scheduling off
#pragma peephole off
void SB_ShipGunBroke_render(int* obj, int p2, int p3, int p4, int p5)
{
    int* p = *(int**)((char*)obj + 76);
    if ((u32)GameBit_Get(*(s16*)((char*)p + 30)) != 0u) {
        ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E59C0);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void SB_ShipGunBroke_update(int* obj)
{
    int* p = *(int**)((char*)obj + 76);
    if ((u32)GameBit_Get(*(s16*)((char*)p + 30)) != 0u) {
        Sfx_PlayFromObject(obj, SFXen_nlite1_c);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern int* gTitleMenuControlInterfaceCopy;

#pragma scheduling off
#pragma peephole off
void ShipBattle_free(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    ((void(*)(int*))((void**)*gObjectTriggerInterface)[9])(state);
    ((void(*)(int*, int, int, int, int))((void**)*gTitleMenuControlInterface)[2])(obj, 0xffff, 0, 0, 0);
    {
        int light = *(int*)((char*)obj + 248);
        if (light != 0) {
            ModelLightStruct_free((int*)light);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void ShipBattle_init(int obj, int def)
{
    int state;
    int light;
    int chainIndex;

    state = *(int *)(obj + 0xb8);
    *(s16 *)(state + 0x6a) = *(s16 *)(def + 0x1a);
    *(s16 *)(state + 0x6e) = -1;
    *(f32 *)(state + 0x24) =
        lbl_803E595C / (lbl_803E595C + (f32)*(u8 *)(def + 0x24));
    *(int *)(state + 0x28) = -1;

    chainIndex = *(int *)(obj + 0xf4);
    if (chainIndex == 0) {
        if (*(s16 *)(def + 0x18) != 1) {
            (*(void (**)(int, int))(*(int *)gObjectTriggerInterface + 0x1c))(state, def);
            *(int *)(obj + 0xf4) = *(s16 *)(def + 0x18) + 1;
            goto light_setup;
        }
    }

    if (chainIndex != 0) {
        if (*(s16 *)(def + 0x18) != chainIndex - 1) {
            (*(void (**)(int))(*(int *)gObjectTriggerInterface + 0x24))(state);
            if (*(s16 *)(def + 0x18) != -1) {
                (*(void (**)(int, int))(*(int *)gObjectTriggerInterface + 0x1c))(state, def);
            }
            *(int *)(obj + 0xf4) = *(s16 *)(def + 0x18) + 1;
        }
    }

light_setup:
    if (*(s16 *)(obj + 0x46) == 0x171) {
        light = objCreateLight((int *)obj, 1);
        if (light != 0) {
            modelLightStruct_setField50(light, 2);
            modelLightStruct_setColorsA8AC(light, 200, 60, 0, 0);
            lightDistAttenFn_8001dc38(light, lbl_803E5970, lbl_803E5974);
        }
        *(int *)(obj + 0xf8) = light;
    }

    lbl_803DDC50 = lbl_803E5958;
    *(u8 *)((char *)&lbl_803DDC50 + 4) = 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void ShipBattle_render(int* obj)
{
    objRenderFn_8003b8f4(lbl_803E595C);
    if (*(s16*)((char*)obj + 0x46) == 369) {
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E5960, 4, 389, 5, NULL);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void ShipBattle_update(int obj)
{
    int *objects;
    int objectCount;
    int triggerResult;
    int current;
    int linkedObject;
    int sameGroupCount;
    int groupId;

    if (*(void **)(obj + 0x4c) == NULL || *(s16 *)(*(int *)(obj + 0x4c) + 0x18) == -1) {
        return;
    }

    triggerResult = (*(int (**)(int, f32))(*(int *)gObjectTriggerInterface + 0x14))(
        obj, (f32)lbl_803DB411);
    if (triggerResult == 0 || *(s16 *)(obj + 0xb4) != -2) {
        return;
    }

    groupId = *(s8 *)(*(int *)(obj + 0xb8) + 0x57);
    linkedObject = 0;
    objects = ObjList_GetObjects(&triggerResult, &objectCount);
    sameGroupCount = 0;
    triggerResult = 0;
    while (triggerResult < objectCount) {
        current = objects[triggerResult];
        if (*(s16 *)(current + 0xb4) == groupId) {
            linkedObject = current;
        }
        if (*(s16 *)(current + 0xb4) == -2 && *(s16 *)(current + 0x44) == 0x10 &&
            groupId == *(s8 *)(*(int *)(current + 0xb8) + 0x57)) {
            sameGroupCount++;
        }
        triggerResult++;
    }

    if (sameGroupCount <= 1 && linkedObject != 0 && *(s16 *)(linkedObject + 0xb4) != -1) {
        *(s16 *)(linkedObject + 0xb4) = -1;
        (*(void (**)(int))(*(int *)gObjectTriggerInterface + 0x4c))(groupId);
    }
    *(s16 *)(obj + 0xb4) = -1;
    Obj_FreeObject(obj);
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void shop_buyItem(int obj, int price)
{
    int player;
    int state;
    int mapEventState;
    u8 *items;
    s16 boughtBit;

    player = (int)Obj_GetPlayerObject();
    state = *(int *)(obj + 0xb8);
    mapEventState = ((int (*)(void))(*(u32 *)(*gMapEventInterface + 0x8c)))();
    playerAddMoney(player, -price);

    switch (*(s8 *)(state + 1)) {
        case 0:
            playerAddHealth(player, 2);
            break;
        case 0x17:
            *(u8 *)(mapEventState + 0xa) = 10;
            break;
        case 1:
            playerAddHealth(player, 8);
            break;
        case 2:
            playerAddHealth(player, 4);
            break;
        case 3:
            playerAddHealth(player, 0x1c);
            break;
        case 4:
            gameBitIncrement(0x66c);
            break;
        case 5:
            gameBitIncrement(0x86a);
            break;
        case 6:
            gameBitIncrement(0xc1);
            break;
        case 7:
            gameBitIncrement(0x13d);
            gameBitIncrement(0x5d6);
            break;
        case 8:
            gameBitIncrement(0x3f5);
            break;
    }

    items = lbl_80327FD0;
    boughtBit = *(s16 *)(items + *(s8 *)(state + 1) * 0xc + 8);
    if (boughtBit != -1) {
        GameBit_Set(boughtBit, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void shop_free(int* obj)
{
    skyFn_80088c94(7, 0);
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(144, 0);
    GameBit_Set(3838, 0);
}
#pragma peephole reset
#pragma scheduling reset
extern int* gObjectTriggerInterface;

#pragma scheduling off
#pragma peephole off
void shop_func0B(int* obj, int v, int p3)
{
    s8* state = *(s8**)((char*)obj + 0xb8);
    state[0] = (s8)v;
    if (v != 0) {
        ((void(*)(int, int*, int))((void**)*gObjectTriggerInterface)[18])(p3, obj, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset
/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */
#pragma scheduling off
#pragma peephole off
void shop_func15(int* obj, int v)
{
    s8* b = *(s8**)((char*)obj + 0xb8);
    b[2] = 0;
    b[3] = 0;
    b[4] = (s8)v;
}
/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */
void shop_func16(int* obj, int p2, int p3)
{
    s8* b = *(s8**)((char*)obj + 0xb8);
    b[2] = (s8)(b[2] + p3);
    b[3] = (s8)(b[3] + p2);
}
/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */
void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4)
{
    s8* b = *(s8**)((char*)obj + 0xb8);
    *out_b2 = b[2];
    *out_b3 = b[3];
    *out_b4 = b[4];
}
#pragma peephole reset
#pragma scheduling reset
/* shop_getItem* helpers — table lookup */
extern u8 lbl_80327FD0[];
#pragma peephole off
#pragma scheduling off
int shop_getItemPrice(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return lbl_80327FD0[idx * 0xc];
    }
    return 0;
}
s16 shop_getItemTextId(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return *(s16 *)&lbl_80327FD0[idx * 0xc + 0xa];
    }
    return 0;
}
u8 shop_getItemField4(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return lbl_80327FD0[idx * 0xc + 0x4];
    }
    return 0;
}
u8 shop_getItemMinPrice(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return lbl_80327FD0[idx * 0xc + 0x5];
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void shop_init(int obj, int objDef)
{
    int i;
    u8 *item;

    *(s8 *)(*(int *)(obj + 0xb8) + 1) = -1;
    ObjGroup_AddObject(obj, 9);
    i = 0;
    item = lbl_80327FD0;
    while (i < 0x3c) {
        item[5] = item[randomGetRange(0, 2) + 1];
        item += 0xc;
        i++;
    }
    Music_Trigger(0x90, 1);
    *(int *)(obj + 0xf8) = 0;
    GameBit_Set(0xefe, 1);
}
#pragma peephole reset
#pragma scheduling reset
/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */
extern void* Obj_GetPlayerObject(void);
extern int GameBit_Get(int);
#pragma scheduling off
#pragma peephole off
int shop_isItemAvailable(int p, int idx)
{
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = *(s16 *)(lbl_80327FD0 + idx * 0xc + 0x6);
    if (slot == -1 || (u32)GameBit_Get(slot) != 0u) {
        result = 1;
    }
    return result;
}
/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
int shop_isItemBought(int p, int idx)
{
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = *(s16 *)(lbl_80327FD0 + idx * 0xc + 0x8);
    if (slot != -1 && (u32)GameBit_Get(slot) != 0u) {
        result = 1;
    }
    return result;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void shop_setStateField1(int* obj, int v)
{
    s8* state = *(s8**)((char*)obj + 0xb8);
    state[1] = (s8)v;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void shop_update(int obj)
{
    int player;

    player = (int)Obj_GetPlayerObject();
    if (fn_802966CC(player) != NULL && (u32)GameBit_Get(0x18b) == 0u) {
        fn_80295CF4(player, 0);
    }

    if (*(int *)(obj + 0xf4) == 0) {
        ((MapEventInterface *)*(int *)gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 0, 1);
        ((MapEventInterface *)*(int *)gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 5, 1);
        ((MapEventInterface *)*(int *)gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 6, 1);
        GameBit_Set(0x617, 1);
        skyFn_80088c94(7, 1);
        *(int *)(obj + 0xf4) = 1;
    }

    if ((u32)GameBit_Get(0xd21) != 0u && *(int *)(obj + 0xf8) == 0) {
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, 0x1c8, 0);
        getEnvfxAct(obj, obj, 0x1cb, 0);
        *(int *)(obj + 0xf8) = 1;
        return;
    }

    if ((u32)GameBit_Get(0xd21) == 0u && *(int *)(obj + 0xf8) != 0) {
        *(int *)(obj + 0xf8) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
