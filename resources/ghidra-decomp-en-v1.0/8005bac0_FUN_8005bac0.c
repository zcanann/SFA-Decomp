// Function: FUN_8005bac0
// Entry: 8005bac0
// Size: 456 bytes

void FUN_8005bac0(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint *puVar8;
  
  iVar2 = FUN_802860d8();
  iVar3 = FUN_8002e0fc(0,0);
  puVar8 = &DAT_803868dc;
  for (iVar7 = 1; iVar7 < DAT_803dceae; iVar7 = iVar7 + 1) {
    iVar6 = *(int *)(iVar3 + (*puVar8 & 0x3ff) * 4);
    uVar4 = *(uint *)(*(int *)(iVar6 + 0x50) + 0x44);
    if (((uVar4 & 0x800) == 0) && ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x5f) & 0x10) == 0)) {
      if ((uVar4 & 0x800000) == 0) {
        (**(code **)(*DAT_803dca7c + 0x1c))(0,0,0,1,iVar6);
      }
      FUN_8003b958(0,0,0,0,iVar6,1);
      iVar5 = *(int *)(iVar6 + 100);
      if ((iVar5 == 0) || (*(int *)(iVar5 + 0xc) == 0)) {
        if ((*(short *)(*(int *)(iVar6 + 0x50) + 0x48) == 3) &&
           (((*(ushort *)(iVar6 + 6) & 0x4000) == 0 && ((*(uint *)(iVar5 + 0x30) & 4) != 0)))) {
          FUN_8005d150(iVar6,0x13,0);
          (&DAT_8037e0cc)[DAT_803dce30 * 4] = 3;
          DAT_803dce30 = DAT_803dce30 + 1;
        }
      }
      else {
        FUN_8005d150(iVar6,0x13,0);
        (&DAT_8037e0cc)[DAT_803dce30 * 4] = 2;
        DAT_803dce30 = DAT_803dce30 + 1;
      }
    }
    else if ((*(char *)(iVar2 + (*puVar8 & 0x3ff)) != '\0') && (DAT_803dcdf0 < 0x14)) {
      piVar1 = &DAT_803821d4 + DAT_803dcdf0;
      DAT_803dcdf0 = DAT_803dcdf0 + 1;
      *piVar1 = iVar6;
    }
    puVar8 = puVar8 + 1;
  }
  FUN_80286124();
  return;
}

