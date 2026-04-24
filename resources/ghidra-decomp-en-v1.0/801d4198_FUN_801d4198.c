// Function: FUN_801d4198
// Entry: 801d4198
// Size: 460 bytes

/* WARNING: Removing unreachable block (ram,0x801d421c) */

undefined4 FUN_801d4198(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 2) & 0x20) == 0) {
    FUN_8000b7bc(param_1,0x7f);
    *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) & 0xef;
    *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 0x20;
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 2) {
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 2;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 8;
      }
      else {
        *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) & 0xf7;
      }
    }
    else if (bVar1 < 4) {
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) & 0xfd;
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 8;
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 0x40;
    }
  }
  if ((*(byte *)(iVar3 + 2) & 2) != 0) {
    if ((*(byte *)(iVar3 + 2) & 4) == 0) {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfff7;
      iVar2 = FUN_8002b9ec();
      *(undefined *)(iVar3 + 8) = 1;
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b500((double)FLOAT_803e53f8,param_1,iVar3 + 8);
    }
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    if ((*(byte *)(iVar3 + 2) & 8) == 0) {
      FUN_8003b310(param_1,iVar3 + 8);
    }
    else {
      FUN_8003b228(param_1,iVar3 + 8);
    }
  }
  return 0;
}

