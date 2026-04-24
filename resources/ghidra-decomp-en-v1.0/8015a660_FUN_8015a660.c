// Function: FUN_8015a660
// Entry: 8015a660
// Size: 284 bytes

void FUN_8015a660(void)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int in_r6;
  int in_r8;
  undefined *puVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  puVar4 = (&PTR_DAT_8031fd4c)[(uint)*(ushort *)(iVar3 + 0x338) * 2];
  if (in_r6 != 0x11) {
    if (in_r6 == 0x10) {
      *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 0x20;
    }
    else {
      if (*(ushort *)(iVar3 + 0x2a0) < 4) {
        FUN_8014d08c((double)FLOAT_803e2cb8,uVar1,iVar3,5,0,0);
      }
      else {
        FUN_8014d08c((double)FLOAT_803e2cb8,uVar1,iVar3,6,0,0);
      }
      iVar2 = FUN_800221a0(0,3);
      *(undefined *)(iVar3 + 0x33a) = puVar4[iVar2];
      *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 8;
      if ((int)(uint)*(ushort *)(iVar3 + 0x2b0) < in_r8) {
        *(undefined2 *)(iVar3 + 0x2b0) = 0;
      }
      else {
        *(ushort *)(iVar3 + 0x2b0) = *(ushort *)(iVar3 + 0x2b0) - (short)in_r8;
      }
      if (*(short *)(iVar3 + 0x2b0) == 0) {
        FUN_8000bb18(uVar1,0x49e);
      }
      if (in_r6 != 0x1a) {
        FUN_8000bb18(uVar1,0x22);
      }
    }
  }
  FUN_80286128();
  return;
}

