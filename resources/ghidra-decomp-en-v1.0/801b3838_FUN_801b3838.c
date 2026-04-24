// Function: FUN_801b3838
// Entry: 801b3838
// Size: 400 bytes

void FUN_801b3838(int param_1)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 unaff_r29;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1a));
  if (iVar2 != 0) {
    if (*(char *)(iVar6 + 0x1e) != -1) {
      sVar1 = *(short *)(iVar6 + 0x1a);
      if (sVar1 == 0x1e3) {
        uVar3 = FUN_8001ffb4(0x182);
        uVar4 = FUN_8001ffb4(0x183);
        uVar3 = uVar3 & 0xff | (uVar4 & 0x7f) << 1;
        uVar4 = FUN_8001ffb4(0x184);
        uVar4 = uVar3 | (uVar4 & 0x3f) << 2;
        if (uVar4 == 7) {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar5 = 2;
        }
        else {
          FUN_800200e8((int)*(short *)(iVar6 + 0x1a),0);
          unaff_r29 = 0x1d;
          if (((uVar4 & 4) != 0) && (unaff_r29 = 0x1f, (uVar3 & 2) != 0)) {
            unaff_r29 = 0x3f;
          }
          uVar5 = 1;
        }
      }
      else if ((sVar1 < 0x1e3) && (sVar1 == 0x17a)) {
        iVar2 = FUN_8001ffb4(0x181);
        if (iVar2 == 0) {
          FUN_800200e8((int)*(short *)(iVar6 + 0x1a),0);
          unaff_r29 = 0x1f;
          uVar5 = 1;
        }
        else {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar5 = 0;
        }
      }
      else {
        uVar5 = 0;
      }
      (**(code **)(*DAT_803dca54 + 0x48))(uVar5,param_1,unaff_r29);
    }
    if ((*(byte *)(iVar6 + 0x1d) & 2) == 0) {
      FUN_800200e8((int)*(short *)(iVar6 + 0x18),1);
    }
  }
  return;
}

