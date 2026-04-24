// Function: FUN_801c8ebc
// Entry: 801c8ebc
// Size: 388 bytes

void FUN_801c8ebc(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  
  iVar2 = FUN_802860d8();
  piVar6 = *(int **)(iVar2 + 0xb8);
  uVar3 = FUN_8002b9ec();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80296518(uVar3,2,1);
        FUN_800200e8(0x15f,1);
        FUN_800200e8(0xc6e,1);
        (**(code **)(*DAT_803dcaac + 0x44))(0xb,3);
        FUN_8004350c(0,0,1);
        uVar4 = FUN_800481b0(10);
        FUN_80043560(uVar4,0);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)((int)piVar6 + 0x15) = *(byte *)((int)piVar6 + 0x15) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar6 != 0) {
          FUN_8001db6c((double)FLOAT_803e50d8,*piVar6,0);
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar6 != 0) {
          FUN_8001db6c((double)FLOAT_803e50d8,*piVar6,0);
        }
      }
    }
    *(undefined *)(param_3 + iVar5 + 0x81) = 0;
  }
  FUN_80286124(0);
  return;
}

