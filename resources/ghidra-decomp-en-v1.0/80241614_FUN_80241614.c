// Function: FUN_80241614
// Entry: 80241614
// Size: 112 bytes

void FUN_80241614(int param_1,uint param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
  iVar1 = 0;
  DAT_803dde10 = param_1;
  DAT_803dde14 = param_3;
  for (iVar2 = 0; iVar2 < DAT_803dde14; iVar2 = iVar2 + 1) {
    puVar3 = (undefined4 *)(DAT_803dde10 + iVar1);
    *puVar3 = 0xffffffff;
    iVar1 = iVar1 + 0xc;
    puVar3[2] = 0;
    puVar3[1] = 0;
  }
  DAT_803dc530 = 0xffffffff;
  DAT_803dde18 = DAT_803dde10 + param_3 * 0xc + 0x1fU & 0xffffffe0;
  DAT_803dde1c = param_2 & 0xffffffe0;
  return;
}

