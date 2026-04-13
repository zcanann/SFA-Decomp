// Function: FUN_8017f548
// Entry: 8017f548
// Size: 792 bytes

void FUN_8017f548(undefined2 *param_1)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  byte *pbVar5;
  int iVar6;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e44ec;
  iVar6 = *(int *)(param_1 + 0x26);
  pbVar5 = *(byte **)(param_1 + 0x5c);
  if (*(int *)(pbVar5 + 4) == 0) {
    uVar2 = FUN_80036f50((uint)*(byte *)(iVar6 + 0x21),param_1,local_18);
    *(undefined4 *)(pbVar5 + 4) = uVar2;
    if (*(int *)(pbVar5 + 4) == 0) {
      return;
    }
    if ((int)*(short *)(iVar6 + 0x1a) == 0xffffffff) {
      pbVar5[1] = 0;
    }
    else {
      uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x1a));
      pbVar5[1] = (byte)uVar3;
    }
    if ((pbVar5[1] == 0) || (*(short *)(iVar6 + 0x1e) == -1)) {
      *pbVar5 = 2;
    }
    else {
      *pbVar5 = 1;
    }
  }
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0xc);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0x10);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0x14);
  *param_1 = **(undefined2 **)(pbVar5 + 4);
  param_1[2] = *(undefined2 *)(*(int *)(pbVar5 + 4) + 4);
  param_1[1] = *(undefined2 *)(*(int *)(pbVar5 + 4) + 2);
  bVar1 = *pbVar5;
  if (bVar1 == 3) {
    uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x18));
    if (uVar3 != 0) {
      *pbVar5 = 2;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar6 + 0x1e));
      (**(code **)(*DAT_803dd6d4 + 0x48))
                (*(undefined *)(iVar6 + 0x22),param_1,*(undefined *)(iVar6 + 0x20));
      *pbVar5 = 4;
    }
    else if (bVar1 != 0) {
      if ((pbVar5[1] == 0) || ((*(byte *)(iVar6 + 0x23) & 1) != 0)) {
        if (((int)*(short *)(iVar6 + 0x18) == 0xffffffff) ||
           (uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x18)), uVar3 != 0)) {
          if (((*(byte *)((int)param_1 + 0xaf) & 1) == 0) ||
             ((*(short *)(iVar6 + 0x1c) != -1 &&
              (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x20))(), iVar4 == 0)))) {
            *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) | 0x20;
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
          }
          else {
            if ((*(byte *)(iVar6 + 0x23) & 2) != 0) {
              FUN_800201ac((int)*(short *)(iVar6 + 0x18),0);
            }
            if ((int)*(short *)(iVar6 + 0x1a) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar6 + 0x1a),1);
            }
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
            pbVar5[1] = 1;
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(iVar6 + 0x22),param_1,0xffffffff);
          }
        }
        else {
          *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
          *pbVar5 = 3;
        }
      }
      else {
        *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        *pbVar5 = 4;
      }
    }
  }
  return;
}

