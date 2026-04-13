// Function: FUN_801b3dec
// Entry: 801b3dec
// Size: 400 bytes

void FUN_801b3dec(int param_1)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 unaff_r29;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x1a));
  if (uVar2 != 0) {
    if (*(char *)(iVar5 + 0x1e) != -1) {
      sVar1 = *(short *)(iVar5 + 0x1a);
      if (sVar1 == 0x1e3) {
        uVar2 = FUN_80020078(0x182);
        uVar3 = FUN_80020078(0x183);
        uVar2 = uVar2 & 0xff | (uVar3 & 0x7f) << 1;
        uVar3 = FUN_80020078(0x184);
        uVar3 = uVar2 | (uVar3 & 0x3f) << 2;
        if (uVar3 == 7) {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar4 = 2;
        }
        else {
          FUN_800201ac((int)*(short *)(iVar5 + 0x1a),0);
          unaff_r29 = 0x1d;
          if (((uVar3 & 4) != 0) && (unaff_r29 = 0x1f, (uVar2 & 2) != 0)) {
            unaff_r29 = 0x3f;
          }
          uVar4 = 1;
        }
      }
      else if ((sVar1 < 0x1e3) && (sVar1 == 0x17a)) {
        uVar2 = FUN_80020078(0x181);
        if (uVar2 == 0) {
          FUN_800201ac((int)*(short *)(iVar5 + 0x1a),0);
          unaff_r29 = 0x1f;
          uVar4 = 1;
        }
        else {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar4 = 0;
        }
      }
      else {
        uVar4 = 0;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(uVar4,param_1,unaff_r29);
    }
    if ((*(byte *)(iVar5 + 0x1d) & 2) == 0) {
      FUN_800201ac((int)*(short *)(iVar5 + 0x18),1);
    }
  }
  return;
}

