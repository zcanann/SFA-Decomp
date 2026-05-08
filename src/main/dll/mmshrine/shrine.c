#include "ghidra_import.h"
#include "main/dll/mmshrine/shrine.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017b00();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8011eb10();
extern void fn_801C4B10(void);
extern undefined4 FUN_801c4b14();
extern undefined4 FUN_801c4f4c();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern uint FUN_80294cd0();
extern int fn_8001F4C8(int param_1,int param_2);
extern void GameBit_Set(int eventId,int value);
extern void Obj_FreeObject(void);

extern undefined4 DAT_803dc071;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern int *lbl_803DCA54;
extern int *lbl_803DCA74;
extern f64 DOUBLE_803e5bd0;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803DC074;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BE8;

/*
 * --INFO--
 *
 * Function: mmsh_shrine_init
 * EN v1.0 Address: 0x801C52D8
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801C533C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_shrine_init(undefined2 *param_1,int param_2)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = 0;
  *(void (**)(void))(param_1 + 0x5e) = fn_801C4B10;
  *(undefined2 *)(piVar2 + 7) = 10;
  *(undefined *)(piVar2 + 9) = 0;
  if (0 < *(short *)(param_2 + 0x1a)) {
    *(short *)(piVar2 + 7) = *(short *)(param_2 + 0x1a) >> 8;
  }
  GameBit_Set(299,0);
  GameBit_Set(0x12d,0);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar2 == 0) {
    iVar1 = fn_8001F4C8(0,1);
    *piVar2 = iVar1;
  }
  GameBit_Set(0xf07,1);
  GameBit_Set(0xefa,1);
  return;
}

/*
 * --INFO--
 *
 * Function: mmsh_scales_free
 * EN v1.0 Address: 0x801C53B0
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x801C5418
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_scales_free(int param_1,int param_2)
{
  (**(code **)(*lbl_803DCA54 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*lbl_803DCA74 + 8))(param_1,0xffff,0,0,0);
  if ((*(int *)(param_1 + 200) != 0) && (param_2 == 0)) {
    Obj_FreeObject();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c5448
 * EN v1.0 Address: 0x801C5448
 * EN v1.0 Size: 1236b
 * EN v1.1 Address: 0x801C54D4
 * EN v1.1 Size: 952b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5448(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar3 = FUN_80017a98();
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar7 = FUN_80080f28(7,'\x01');
    uVar7 = FUN_80006728(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3
                         ,0x20d,0,in_r7,in_r8,in_r9,in_r10);
    uVar7 = FUN_80006728(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3
                         ,0x20e,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80006728(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3,0x222,0
                 ,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
  }
  iVar4 = FUN_80044404(0x20);
  FUN_80042b9c(iVar4,1,0);
  FUN_801c4b14(param_9);
  FUN_801d8308(iVar6 + 0x18,8,-1,-1,0xae6,(int *)0xa);
  FUN_801d8480(iVar6 + 0x18,4,-1,-1,0xcbb,(int *)0x8);
  FUN_801d8308(iVar6 + 0x18,0x10,-1,-1,0xcbb,(int *)0xc4);
  bVar1 = *(byte *)(iVar6 + 0x24);
  if (bVar1 == 3) {
    (**(code **)(*DAT_803dd6d4 + 0x4c))((int)(short)param_9[0x5a]);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
    *(undefined *)(iVar6 + 0x24) = 4;
    FUN_80017698(0xae6,0);
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if ((*(uint *)(iVar6 + 0x18) & 1) != 0) {
        param_9[3] = param_9[3] | 0x4000;
        *param_9 = 0;
        *(undefined *)(iVar6 + 0x24) = 2;
        *(uint *)(iVar6 + 0x18) = *(uint *)(iVar6 + 0x18) & 0xfffffffe;
        FUN_80017698(0xae6,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      }
    }
    else if (bVar1 == 0) {
      fVar2 = *(float *)(iVar6 + 0x14) - lbl_803DC074;
      *(float *)(iVar6 + 0x14) = fVar2;
      if (fVar2 <= lbl_803E5BD8) {
        FUN_80006824((uint)param_9,0x343);
        uVar5 = FUN_80017760(500,1000);
        *(float *)(iVar6 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e5bd0);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        *(undefined *)(iVar6 + 0x24) = 1;
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x4c,0,0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_800067c0((int *)0xd8,1);
      }
    }
    else {
      uVar5 = FUN_80294cd0(iVar3,4);
      if (uVar5 == 0) {
        FUN_80006770(3);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      *(undefined *)(iVar6 + 0x24) = 5;
      FUN_80017698(0xae6,0);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(iVar6 + 0x24) = 0;
    *(uint *)(iVar6 + 0x18) = *(uint *)(iVar6 + 0x18) & 0xfffffffe;
    param_9[3] = param_9[3] & 0xbfff;
    FUN_80017698(299,0);
    FUN_80017698(0xae4,0);
    FUN_80017698(0xae5,0);
    FUN_80017698(0xae6,0);
  }
  else if (bVar1 < 5) {
    *(undefined *)(iVar6 + 0x24) = 5;
    FUN_80017698(0xae6,0);
    FUN_80017698(0xae4,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c591c
 * EN v1.0 Address: 0x801C591C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C588C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c591c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c5920
 * EN v1.0 Address: 0x801C5920
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801C5964
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5920(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  undefined8 uVar1;
  
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_9 + 0xb8));
  uVar1 = (**(code **)(*DAT_803dd6f4 + 8))(param_9,0xffff,0,0,0);
  if ((*(int *)(param_9 + 200) != 0) && (param_10 == 0)) {
    FUN_80017ac8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c5a34
 * EN v1.0 Address: 0x801C5A34
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C59F4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5a34(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c5a5c
 * EN v1.0 Address: 0x801C5A5C
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x801C5A28
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5a5c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
                                            DOUBLE_803e5c08));
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


/* Trivial 4b 0-arg blr leaves. */
void mmsh_shrine_release(void) {}
void mmsh_shrine_initialise(void) {}
void mmsh_scales_hitDetect(void) {}
void mmsh_scales_release(void) {}
void mmsh_scales_initialise(void) {}
void mmsh_waterspike_free(void) {}
void mmsh_waterspike_hitDetect(void) {}
void mmsh_waterspike_release(void) {}
void mmsh_waterspike_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int mmsh_scales_getExtraSize(void) { return 0x140; }
int mmsh_scales_func08(void) { return 0xb; }
int mmsh_waterspike_getExtraSize(void) { return 0x0; }
int mmsh_waterspike_func08(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E4F68;
extern void fn_8003B8F4(f32);
#pragma peephole off
void mmsh_scales_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E4F68); }
#pragma peephole reset
