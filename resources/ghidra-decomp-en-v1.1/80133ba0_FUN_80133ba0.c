// Function: FUN_80133ba0
// Entry: 80133ba0
// Size: 284 bytes

/* WARNING: Removing unreachable block (ram,0x80133ca0) */
/* WARNING: Removing unreachable block (ram,0x80133c98) */
/* WARNING: Removing unreachable block (ram,0x80133c90) */
/* WARNING: Removing unreachable block (ram,0x80133c88) */
/* WARNING: Removing unreachable block (ram,0x80133c80) */
/* WARNING: Removing unreachable block (ram,0x80133bd0) */
/* WARNING: Removing unreachable block (ram,0x80133bc8) */
/* WARNING: Removing unreachable block (ram,0x80133bc0) */
/* WARNING: Removing unreachable block (ram,0x80133bb8) */
/* WARNING: Removing unreachable block (ram,0x80133bb0) */

void FUN_80133ba0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  byte bVar4;
  undefined8 extraout_f1;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  dVar5 = (double)FLOAT_803e2f14;
  dVar6 = (double)FLOAT_803e2f18;
  dVar7 = (double)FLOAT_803e2e98;
  dVar8 = (double)FLOAT_803e2f1c;
  dVar9 = (double)FLOAT_803e2f20;
  for (bVar4 = 0; bVar4 < 2; bVar4 = bVar4 + 1) {
    puVar2 = FUN_8002becc(0x20,bVar4 + 0x7da);
    uVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    iVar1 = (uint)bVar4 * 4;
    *(undefined4 *)(&DAT_803dc830 + iVar1) = uVar3;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0xc) = (float)dVar5;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x10) = (float)dVar6;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0xc) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x10) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x14) = (float)dVar8;
    **(undefined2 **)(&DAT_803dc830 + iVar1) = 2000;
    *(undefined2 *)(*(int *)(&DAT_803dc830 + iVar1) + 2) = 0;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 8) = (float)dVar9;
    param_1 = extraout_f1;
  }
  return;
}

