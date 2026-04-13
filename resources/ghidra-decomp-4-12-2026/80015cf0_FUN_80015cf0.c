// Function: FUN_80015cf0
// Entry: 80015cf0
// Size: 184 bytes

/* WARNING: Removing unreachable block (ram,0x80015d24) */

int FUN_80015cf0(byte *param_1,int *param_2)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  bVar1 = *param_1;
  uVar2 = (uint)(byte)(&DAT_802c7618)[bVar1];
  iVar3 = 0;
  if (uVar2 == 3) {
LAB_80015d50:
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    iVar3 = (iVar3 + (uint)bVar1) * 0x40;
LAB_80015d60:
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    iVar3 = (iVar3 + (uint)bVar1) * 0x40;
LAB_80015d70:
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    iVar3 = (iVar3 + (uint)bVar1) * 0x40;
  }
  else {
    if (2 < uVar2) {
      if (uVar2 == 5) {
        param_1 = param_1 + 1;
        iVar3 = (uint)bVar1 << 6;
      }
      else if (4 < uVar2) goto LAB_80015d88;
      bVar1 = *param_1;
      param_1 = param_1 + 1;
      iVar3 = (iVar3 + (uint)bVar1) * 0x40;
      goto LAB_80015d50;
    }
    if (uVar2 == 1) goto LAB_80015d70;
    if (uVar2 != 0) goto LAB_80015d60;
  }
  iVar3 = iVar3 + (uint)*param_1;
LAB_80015d88:
  *param_2 = uVar2 + 1;
  return iVar3 - *(int *)(&DAT_802c7718 + uVar2 * 4);
}

