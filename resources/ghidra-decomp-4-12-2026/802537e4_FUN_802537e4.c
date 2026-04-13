// Function: FUN_802537e4
// Entry: 802537e4
// Size: 228 bytes

void FUN_802537e4(uint param_1)

{
  ushort uVar1;
  int iVar2;
  undefined2 *puVar3;
  
  puVar3 = &DAT_8032ef68;
  if (0xb < param_1) {
    param_1 = 0xb;
  }
  FUN_80243e74();
  DAT_803ded10 = param_1;
  iVar2 = FUN_8024e064();
  if (iVar2 == 2) {
LAB_8025384c:
    puVar3 = &DAT_8032ef68;
  }
  else {
    if (iVar2 < 2) {
      if (iVar2 == 0) goto LAB_8025384c;
      if (-1 < iVar2) {
        puVar3 = (undefined2 *)0x8032ef98;
        goto LAB_80253870;
      }
    }
    else if (iVar2 == 5) goto LAB_8025384c;
    FUN_8007d858();
    param_1 = 0;
  }
LAB_80253870:
  uVar1 = DAT_cc00206c;
  if ((uVar1 & 1) == 0) {
    iVar2 = 1;
  }
  else {
    iVar2 = 2;
  }
  FUN_80252d48(iVar2 * (uint)(ushort)puVar3[param_1 * 2],(uint)*(byte *)(puVar3 + param_1 * 2 + 1));
  FUN_80243e9c();
  return;
}

