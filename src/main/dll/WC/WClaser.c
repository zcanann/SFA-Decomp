#include "ghidra_import.h"
#include "main/dll/WC/WClaser.h"

extern undefined4 FUN_800066e0();
extern undefined4 FUN_80006b0c();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80061a80();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294d74();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd58;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd710;
extern undefined4* DAT_803dd714;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de8f0;
extern undefined4 DAT_803de8f4;
extern f32 lbl_803E6984;
extern f32 lbl_803E6988;
extern f32 lbl_803E698C;

/*
 * --INFO--
 *
 * Function: FUN_801f02f0
 * EN v1.0 Address: 0x801F02F0
 * EN v1.0 Size: 900b
 * EN v1.1 Address: 0x801F05B4
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801f02f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11)
{
  uint uVar1;
  char cVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  
  DAT_803dcd58 = (uint)DAT_803dc070;
  *(undefined2 *)(param_11 + 0x6e) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 1:
      *(undefined4 *)(param_9 + 0xf4) = 10;
      break;
    case 2:
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x77,0,0,0,in_r9,in_r10);
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x78,0,0,0,in_r9,in_r10);
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x80,0,0,0,in_r9,in_r10);
      break;
    case 3:
      param_1 = (**(code **)(*DAT_803dd714 + 0x14))(0,0x1e,0x50);
      break;
    case 4:
      *(undefined4 *)(param_9 + 0xf4) = 0xc;
      break;
    case 5:
      *(undefined4 *)(param_9 + 0xf4) = 0xd;
      break;
    case 6:
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),1,0);
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),2,0);
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),4,0);
      param_1 = FUN_80017698(0xd1,0);
      break;
    case 7:
      DAT_803de8f0 = 1;
      break;
    case 8:
      DAT_803de8f0 = 0;
      break;
    case 9:
      *(undefined4 *)(param_9 + 0xf4) = 0xb;
    }
  }
  uVar1 = FUN_80017690(0x429);
  if ((uVar1 != 0) &&
     (cVar2 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_9 + 0x34),2), cVar2 != '\0'))
  {
    (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),1,0);
    (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),2,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0674
 * EN v1.0 Address: 0x801F0674
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F0804
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0674(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f0678
 * EN v1.0 Address: 0x801F0678
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801F0864
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0678(void)
{
  int iVar1;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_8028683c();
  uVar2 = FUN_80017690(0x78);
  if (((uVar2 == 0) && (in_r8 != '\0')) &&
     ((*(short *)(iVar1 + 0x46) != 0x188 || (*(int *)(*(int *)(iVar1 + 0x30) + 0xf4) < 7)))) {
    FUN_8003b818(iVar1);
    if (DAT_803de8f0 != '\0') {
      (**(code **)(*DAT_803dd710 + 4))(1);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0718
 * EN v1.0 Address: 0x801F0718
 * EN v1.0 Size: 788b
 * EN v1.1 Address: 0x801F0928
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0718(short *param_1)
{
  uint uVar1;
  short *psVar2;
  char cVar3;
  undefined4 *puVar4;
  
  uVar1 = FUN_80017690(0x78);
  if (uVar1 == 0) {
    if (param_1[0x23] == 0x188) {
      *(undefined *)(param_1 + 0x1b) = 0x80;
    }
    else {
      psVar2 = (short *)FUN_80017a98();
      puVar4 = *(undefined4 **)(param_1 + 0x5c);
      uVar1 = FUN_80017690(0x429);
      if (uVar1 == 0) {
        uVar1 = FUN_80017690(0xd0);
        if ((uVar1 == 0) &&
           (cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_1 + 0x1a),2),
           cVar3 == '\0')) {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),1,1);
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),2,1);
        }
      }
      else {
        cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_1 + 0x1a),2);
        if (cVar3 != '\0') {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),1,0);
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),2,0);
        }
      }
      uVar1 = FUN_80017690(0xd0);
      if (uVar1 == 0) {
        if ((*(char *)(puVar4 + 3) == '\0') && (uVar1 = FUN_80017690(0x429), uVar1 == 0)) {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),1,1);
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),2,1);
          *(undefined *)(puVar4 + 3) = 1;
        }
      }
      else {
        cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_1 + 0x1a),4);
        if (cVar3 == '\0') {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),4,1);
        }
        if (*(char *)(puVar4 + 3) != '\0') {
          *(undefined *)(puVar4 + 3) = 0;
        }
      }
      uVar1 = FUN_80017690(0xa4);
      if (uVar1 == 0) {
        *(float *)(psVar2 + 6) = lbl_803E6984;
        *(float *)(psVar2 + 8) = lbl_803E6988;
        *(float *)(psVar2 + 10) = lbl_803E698C;
        FUN_80061a80(psVar2,param_1,0);
        FUN_80294d74((int)psVar2);
        param_1[0x7c] = 0;
        param_1[0x7d] = 1;
      }
      else {
        param_1[0x7a] = 0;
        param_1[0x7b] = 10;
        if (*(int *)(param_1 + 0x7c) == 1) {
          *(undefined4 *)(param_1 + 6) = *puVar4;
          *(undefined4 *)(param_1 + 8) = puVar4[1];
          *(undefined4 *)(param_1 + 10) = puVar4[2];
          *param_1 = *(short *)((int)puVar4 + 0xe);
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
          param_1[0x7c] = 0;
          param_1[0x7d] = 2;
        }
      }
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801F06D0(void) {}
void fn_801F06D4(void) {}
void fn_801F0734(void) {}
void fn_801F0768(void) {}
void fn_801F08F8(void) {}
void fn_801F08FC(void) {}
void fn_801F0950(void) {}
void fn_801F0998(void) {}
void fn_801F0ADC(void) {}
void fn_801F0AE0(void) {}
void fn_801F0B48(void) {}
void fn_801F0B4C(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801F0724(void) { return 0x1; }
int fn_801F072C(void) { return 0x0; }
int fn_801F0940(void) { return 0xc; }
int fn_801F0948(void) { return 0x0; }
int fn_801F0AE4(void) { return 0x50; }
int fn_801F0AEC(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E5CF8;
extern void fn_8003B8F4(f32);
#pragma peephole off
void fn_801F0738(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5CF8); }
#pragma peephole reset
