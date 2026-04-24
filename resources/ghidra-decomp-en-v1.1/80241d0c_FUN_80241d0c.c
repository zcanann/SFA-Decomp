// Function: FUN_80241d0c
// Entry: 80241d0c
// Size: 112 bytes

void FUN_80241d0c(int param_1,uint param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
  iVar1 = 0;
  DAT_803dea90 = param_1;
  DAT_803dea94 = param_3;
  for (iVar2 = 0; iVar2 < DAT_803dea94; iVar2 = iVar2 + 1) {
    puVar3 = (undefined4 *)(DAT_803dea90 + iVar1);
    *puVar3 = 0xffffffff;
    iVar1 = iVar1 + 0xc;
    puVar3[2] = 0;
    puVar3[1] = 0;
  }
  DAT_803dea9c = param_2 & 0xffffffe0;
  DAT_803dd198 = 0xffffffff;
  DAT_803dea98 = DAT_803dea90 + param_3 * 0xc + 0x1fU & 0xffffffe0;
  return;
}

