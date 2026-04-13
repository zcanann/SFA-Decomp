// Function: FUN_8023b06c
// Entry: 8023b06c
// Size: 148 bytes

/* WARNING: Removing unreachable block (ram,0x8023b0e0) */
/* WARNING: Removing unreachable block (ram,0x8023b07c) */

undefined4 FUN_8023b06c(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  longlong lVar6;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar3 + 0x68) = FLOAT_803e816c;
  dVar5 = (double)*(float *)(iVar3 + 0x68);
  piVar1 = (int *)FUN_8002b660(param_1);
  iVar3 = *piVar1;
  lVar6 = (longlong)(int)((double)FLOAT_803e814c * dVar5);
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xf8); iVar4 = iVar4 + 1) {
    iVar2 = FUN_800284e8(iVar3,iVar4);
    *(char *)(iVar2 + 0x43) = (char)lVar6;
  }
  return 0;
}

