#include "ghidra_import.h"
#include "main/dll/DR/DRpulley.h"

extern int FUN_8005b54c();
extern uint countLeadingZeros();

extern undefined4 DAT_803dcd24;
extern undefined4* DAT_803dd6ec;
extern undefined4* DAT_803dd728;
extern f32 lbl_803E6780;
extern f32 lbl_803E6790;
extern f32 lbl_803E67B8;
extern f32 lbl_803E680C;
extern f32 lbl_803E6824;
extern f32 lbl_803E6840;
extern f32 lbl_803E6848;
extern f32 lbl_803E6850;
extern f32 lbl_803E687C;
extern f32 lbl_803E688C;
extern f32 lbl_803E6894;
extern f32 lbl_803E6898;
extern f32 lbl_803E68A8;
extern f32 lbl_803E68AC;
extern f32 lbl_803E68D0;
extern f32 lbl_803E68D4;
extern f32 lbl_803E68D8;
extern f32 lbl_803E68DC;

/*
 * --INFO--
 *
 * Function: FUN_801ecec4
 * EN v1.0 Address: 0x801ECEC4
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801ECF60
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecec4(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x4b0) = lbl_803E68D4;
  *(float *)(param_2 + 0x530) = lbl_803E68D0;
  *(float *)(param_2 + 0x534) = lbl_803E688C;
  *(float *)(param_2 + 0x538) = lbl_803E680C;
  *(float *)(param_2 + 0x53c) = lbl_803E68AC;
  *(float *)(param_2 + 0x548) = lbl_803E6894;
  *(float *)(param_2 + 0x54c) = lbl_803E687C;
  *(float *)(param_2 + 0x540) = lbl_803E67B8;
  *(float *)(param_2 + 0x544) = lbl_803E6790;
  fVar1 = lbl_803E68D8;
  *(float *)(param_2 + 0x57c) = lbl_803E68D8;
  *(float *)(param_2 + 0x580) = fVar1;
  *(float *)(param_2 + 0x554) = lbl_803E68DC;
  *(float *)(param_2 + 0x550) = lbl_803E68A8;
  *(float *)(param_2 + 0x570) = lbl_803E6850;
  fVar1 = lbl_803E6840;
  *(float *)(param_2 + 0x558) = lbl_803E6840;
  *(float *)(param_2 + 0x578) = lbl_803E6824;
  *(float *)(param_2 + 0x574) = lbl_803E6848;
  *(float *)(param_2 + 0x56c) = lbl_803E6898;
  *(float *)(param_2 + 0x4ac) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecf58
 * EN v1.0 Address: 0x801ECF58
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801ECFF4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecf58(int param_1)
{
  (**(code **)(*DAT_803dd6ec + 0x34))(*(int *)(param_1 + 0xb8) + 0x28);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecf94
 * EN v1.0 Address: 0x801ECF94
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801ED02C
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801ecf94(int param_1)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = (**(code **)(*DAT_803dd6ec + 0x34))(*(int *)(param_1 + 0xb8) + 0x28);
  if ((iVar1 == 3) && (DAT_803dcd24 == -1)) {
    uVar2 = 1;
  }
  else {
    uVar2 = countLeadingZeros((DAT_803dcd24 + -1) - iVar1);
    uVar2 = uVar2 >> 5;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed004
 * EN v1.0 Address: 0x801ED004
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x801ED09C
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed004(short *param_1)
{
  float fVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0x5c);
  iVar2 = FUN_8005b54c(*(int *)((uint)*(byte *)(psVar3 + 0x21a) * 0xc + -0x7fcd6e30 +
                               (uint)*(byte *)((int)psVar3 + 0x435) * 4),(int *)0x0,(int *)0x0,
                       (int *)0x0,(uint *)0x0);
  if (iVar2 != 0) {
    if (*(char *)(psVar3 + 0x21a) != '\0') {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
      *param_1 = (ushort)*(byte *)(iVar2 + 0x29) << 8;
    }
    (**(code **)(*DAT_803dd6ec + 0x10))(param_1,psVar3 + 0x14,0);
    *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(param_1 + 10);
    *psVar3 = *param_1;
    fVar1 = lbl_803E6780;
    *(float *)(psVar3 + 0x24a) = lbl_803E6780;
    *(float *)(psVar3 + 0x24c) = fVar1;
    *(float *)(psVar3 + 0x24e) = fVar1;
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,psVar3 + 0xbc);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
    *(undefined *)((int)psVar3 + 0x3d3) = 1;
  }
  return;
}
