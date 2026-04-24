// Function: FUN_801c2c68
// Entry: 801c2c68
// Size: 348 bytes

void FUN_801c2c68(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_802860d8();
  piVar5 = *(int **)(iVar2 + 0xb8);
  uVar3 = FUN_8002b9ec();
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80296518(uVar3,1,1);
        FUN_800200e8(0xbfd,1);
        FUN_800200e8(0x956,1);
        (**(code **)(*DAT_803dcaac + 0x44))(0xb,2);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)(piVar5 + 7) = *(byte *)(piVar5 + 7) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_8001db6c((double)FLOAT_803e4e88,*piVar5,0);
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_8001db6c((double)FLOAT_803e4e88,*piVar5,0);
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286124(0);
  return;
}

