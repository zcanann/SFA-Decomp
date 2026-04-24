// Function: FUN_8017eff0
// Entry: 8017eff0
// Size: 792 bytes

void FUN_8017eff0(undefined2 *param_1)

{
  undefined4 uVar1;
  byte bVar3;
  int iVar2;
  byte *pbVar4;
  int iVar5;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e3854;
  iVar5 = *(int *)(param_1 + 0x26);
  pbVar4 = *(byte **)(param_1 + 0x5c);
  if (*(int *)(pbVar4 + 4) == 0) {
    uVar1 = FUN_80036e58(*(undefined *)(iVar5 + 0x21),param_1,local_18);
    *(undefined4 *)(pbVar4 + 4) = uVar1;
    if (*(int *)(pbVar4 + 4) == 0) {
      return;
    }
    if (*(short *)(iVar5 + 0x1a) == -1) {
      pbVar4[1] = 0;
    }
    else {
      bVar3 = FUN_8001ffb4();
      pbVar4[1] = bVar3;
    }
    if ((pbVar4[1] == 0) || (*(short *)(iVar5 + 0x1e) == -1)) {
      *pbVar4 = 2;
    }
    else {
      *pbVar4 = 1;
    }
  }
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(pbVar4 + 4) + 0xc);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(pbVar4 + 4) + 0x10);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(pbVar4 + 4) + 0x14);
  *param_1 = **(undefined2 **)(pbVar4 + 4);
  param_1[2] = *(undefined2 *)(*(int *)(pbVar4 + 4) + 4);
  param_1[1] = *(undefined2 *)(*(int *)(pbVar4 + 4) + 2);
  bVar3 = *pbVar4;
  if (bVar3 == 3) {
    iVar5 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x18));
    if (iVar5 != 0) {
      *pbVar4 = 2;
    }
  }
  else if (bVar3 < 3) {
    if (bVar3 == 1) {
      *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) & 0xdf;
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      (**(code **)(*DAT_803dca54 + 0x54))(param_1,(int)*(short *)(iVar5 + 0x1e));
      (**(code **)(*DAT_803dca54 + 0x48))
                (*(undefined *)(iVar5 + 0x22),param_1,*(undefined *)(iVar5 + 0x20));
      *pbVar4 = 4;
    }
    else if (bVar3 != 0) {
      if ((pbVar4[1] == 0) || ((*(byte *)(iVar5 + 0x23) & 1) != 0)) {
        if ((*(short *)(iVar5 + 0x18) == -1) || (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
          if (((*(byte *)((int)param_1 + 0xaf) & 1) == 0) ||
             ((*(short *)(iVar5 + 0x1c) != -1 &&
              (iVar2 = (**(code **)(*DAT_803dca68 + 0x20))(), iVar2 == 0)))) {
            *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) | 0x20;
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
          }
          else {
            if ((*(byte *)(iVar5 + 0x23) & 2) != 0) {
              FUN_800200e8((int)*(short *)(iVar5 + 0x18),0);
            }
            if (*(short *)(iVar5 + 0x1a) != -1) {
              FUN_800200e8((int)*(short *)(iVar5 + 0x1a),1);
            }
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
            pbVar4[1] = 1;
            (**(code **)(*DAT_803dca54 + 0x48))(*(undefined *)(iVar5 + 0x22),param_1,0xffffffff);
          }
        }
        else {
          *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) & 0xdf;
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
          *pbVar4 = 3;
        }
      }
      else {
        *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) & 0xdf;
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        *pbVar4 = 4;
      }
    }
  }
  return;
}

