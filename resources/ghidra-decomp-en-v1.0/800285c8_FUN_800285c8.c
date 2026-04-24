// Function: FUN_800285c8
// Entry: 800285c8
// Size: 156 bytes

void FUN_800285c8(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860d8();
  piVar1 = (int *)((ulonglong)uVar6 >> 0x20);
  iVar2 = *piVar1;
  if ((*(ushort *)(piVar1 + 6) & 0x40) == 0) {
    *(ushort *)(piVar1 + 6) = *(ushort *)(piVar1 + 6) | 0x40;
    iVar5 = 0;
    iVar4 = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(*piVar1 + 0xf8); iVar3 = iVar3 + 1) {
      FUN_8005344c(*(int *)(iVar2 + 0x38) + iVar4,piVar1[0xd] + iVar5,(int)uVar6,
                   *(undefined2 *)(iVar2 + 0xe2));
      iVar5 = iVar5 + 0xc;
      iVar4 = iVar4 + 0x44;
    }
  }
  FUN_80286124();
  return;
}

