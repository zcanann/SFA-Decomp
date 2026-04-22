#include "ghidra_import.h"
#include "main/dll/DR/DRpulley.h"

extern int FUN_8005b60c();
extern uint countLeadingZeros();

extern undefined4 DAT_803dcd24;
extern undefined4* DAT_803dd6ec;
extern undefined4* DAT_803dd728;
extern f32 FLOAT_803e6780;
extern f32 FLOAT_803e6790;
extern f32 FLOAT_803e67b8;
extern f32 FLOAT_803e680c;
extern f32 FLOAT_803e6824;
extern f32 FLOAT_803e6840;
extern f32 FLOAT_803e6848;
extern f32 FLOAT_803e6850;
extern f32 FLOAT_803e687c;
extern f32 FLOAT_803e688c;
extern f32 FLOAT_803e6894;
extern f32 FLOAT_803e6898;
extern f32 FLOAT_803e68a8;
extern f32 FLOAT_803e68ac;
extern f32 FLOAT_803e68d0;
extern f32 FLOAT_803e68d4;
extern f32 FLOAT_803e68d8;
extern f32 FLOAT_803e68dc;

/*
 * --INFO--
 *
 * Function: FUN_801ecf60
 * EN v1.0 Address: 0x801ECF60
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecf60(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x4b0) = FLOAT_803e68d4;
  *(float *)(param_2 + 0x530) = FLOAT_803e68d0;
  *(float *)(param_2 + 0x534) = FLOAT_803e688c;
  *(float *)(param_2 + 0x538) = FLOAT_803e680c;
  *(float *)(param_2 + 0x53c) = FLOAT_803e68ac;
  *(float *)(param_2 + 0x548) = FLOAT_803e6894;
  *(float *)(param_2 + 0x54c) = FLOAT_803e687c;
  *(float *)(param_2 + 0x540) = FLOAT_803e67b8;
  *(float *)(param_2 + 0x544) = FLOAT_803e6790;
  fVar1 = FLOAT_803e68d8;
  *(float *)(param_2 + 0x57c) = FLOAT_803e68d8;
  *(float *)(param_2 + 0x580) = fVar1;
  *(float *)(param_2 + 0x554) = FLOAT_803e68dc;
  *(float *)(param_2 + 0x550) = FLOAT_803e68a8;
  *(float *)(param_2 + 0x570) = FLOAT_803e6850;
  fVar1 = FLOAT_803e6840;
  *(float *)(param_2 + 0x558) = FLOAT_803e6840;
  *(float *)(param_2 + 0x578) = FLOAT_803e6824;
  *(float *)(param_2 + 0x574) = FLOAT_803e6848;
  *(float *)(param_2 + 0x56c) = FLOAT_803e6898;
  *(float *)(param_2 + 0x4ac) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecff4
 * EN v1.0 Address: 0x801ECFF4
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecff4(int param_1)
{
  (**(code **)(*DAT_803dd6ec + 0x34))(*(int *)(param_1 + 0xb8) + 0x28);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed02c
 * EN v1.0 Address: 0x801ED02C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801ed02c(int param_1)
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
 * Function: FUN_801ed09c
 * EN v1.0 Address: 0x801ED09C
 * EN v1.0 Size: 352b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed09c(short *param_1)
{
  float fVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0x5c);
  iVar2 = FUN_8005b60c(*(int *)((uint)*(byte *)(psVar3 + 0x21a) * 0xc + -0x7fcd6e30 +
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
    fVar1 = FLOAT_803e6780;
    *(float *)(psVar3 + 0x24a) = FLOAT_803e6780;
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
