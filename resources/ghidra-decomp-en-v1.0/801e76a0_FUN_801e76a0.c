// Function: FUN_801e76a0
// Entry: 801e76a0
// Size: 1452 bytes

void FUN_801e76a0(undefined4 param_1,undefined4 param_2,int param_3,char param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined2 uVar9;
  int *piVar8;
  int iVar10;
  uint uVar11;
  double dVar12;
  float local_28 [10];
  
  iVar4 = FUN_802860d4();
  iVar1 = *(int *)(iVar4 + 0xb8);
  iVar5 = FUN_8002b9ec();
  local_28[0] = FLOAT_803e59d8;
  *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) & 0xdf;
  if ((*(byte *)(iVar1 + 0x9d4) & 0x10) == 0) {
    iVar7 = FUN_80114bb0(iVar4,param_3,iVar1 + 0x35c,0,0);
    if (iVar7 == 0) {
      *(code **)(param_3 + 0xe8) = FUN_801e75ec;
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffdf;
      dVar12 = (double)FLOAT_803e59dc;
      *(float *)(iVar1 + 0x280) = FLOAT_803e59dc;
      *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) | 4;
      if (param_4 != '\0') {
        FUN_8002fa48(dVar12,(double)FLOAT_803db414,iVar4,0);
      }
      if (*(short *)(iVar4 + 0xb4) == -1) {
        if (*(char *)(param_3 + 0x56) != '\0') {
          iVar7 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x44))();
          if (iVar7 != -1) {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x38))
                              (*(int *)(iVar1 + 0x9b4),iVar7);
            *(undefined2 *)(iVar1 + 0x9cc) = uVar9;
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x30))
                              (*(int *)(iVar1 + 0x9b4),iVar7);
            *(undefined2 *)(iVar1 + 0x9ce) = uVar9;
            *(undefined2 *)(iVar1 + 0x9d0) = *(undefined2 *)(iVar1 + 0x9cc);
            *(undefined *)(iVar1 + 0x9d2) = 0;
            iVar10 = (int)*(short *)(iVar1 + 0x9cc);
            piVar8 = (int *)FUN_800394ac(iVar4,8,0);
            iVar7 = iVar10 >> 0x1f;
            iVar2 = iVar10 / 10 + iVar7;
            *piVar8 = (iVar10 + (iVar2 - (iVar2 >> 0x1f)) * -10) * 0x100;
            piVar8 = (int *)FUN_800394ac(iVar4,7,0);
            iVar2 = iVar10 / 10 + iVar7;
            iVar2 = iVar2 - (iVar2 >> 0x1f);
            iVar3 = iVar2 / 10 + (iVar2 >> 0x1f);
            *piVar8 = (iVar2 + (iVar3 - (iVar3 >> 0x1f)) * -10) * 0x100;
            iVar7 = iVar10 / 100 + iVar7;
            iVar7 = iVar7 - (iVar7 >> 0x1f);
            if (9 < iVar7) {
              iVar7 = 9;
            }
            piVar8 = (int *)FUN_800394ac(iVar4,6,0);
            *piVar8 = iVar7 << 8;
          }
          *(undefined *)(param_3 + 0x56) = 0;
          *(code **)(param_3 + 0xec) = FUN_801e71a4;
        }
        iVar7 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x44))();
        if (iVar7 != -1) {
          FUN_8011f3ec(0x12);
          FUN_8011f3c8(10);
        }
      }
      for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar7 = iVar7 + 1) {
        switch(*(undefined *)(param_3 + iVar7 + 0x81)) {
        case 1:
          FUN_801e7dc8(iVar4,iVar1,*(undefined *)(iVar1 + 0x9d5));
          *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) | 2;
          break;
        case 2:
          (**(code **)(*DAT_803dca8c + 0x14))(iVar4,iVar1,3);
          (**(code **)(*DAT_803dcab4 + 0xc))(iVar4,0x7ef,local_28,0x50,0);
          *(undefined *)(iVar1 + 0x9d6) = 0;
          break;
        case 3:
          (**(code **)(*DAT_803dca8c + 0x14))(iVar4,iVar1,2);
          *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) | 0x20;
          *(undefined *)(iVar1 + 0x9d6) = 0xff;
          break;
        case 4:
          if (*(short *)(iVar5 + 0x46) == 0) {
            FUN_800552e8(0xf,0);
          }
          else {
            FUN_800552e8(0xe,0);
          }
          break;
        case 5:
          iVar2 = FUN_80014940();
          if (iVar2 == 0x10) {
            piVar8 = (int *)FUN_80014938();
            (**(code **)(*piVar8 + 0x10))(0);
          }
          break;
        case 6:
          iVar2 = FUN_80014940();
          if (iVar2 == 0x10) {
            piVar8 = (int *)FUN_80014938();
            (**(code **)(*piVar8 + 0x10))(2);
          }
          break;
        case 7:
          iVar2 = FUN_80014940();
          if (iVar2 == 0x10) {
            piVar8 = (int *)FUN_80014938();
            (**(code **)(*piVar8 + 0x10))(4);
          }
          break;
        case 9:
          FUN_802968ac(iVar5,*(undefined *)(iVar1 + 0x9d5));
          break;
        case 10:
          FUN_802968ac(iVar5,-(uint)*(byte *)(iVar1 + 0x9d5));
          break;
        case 0xb:
          (**(code **)(*DAT_803dcab4 + 0xc))(iVar4,0x7ef,local_28,0x50,0);
          break;
        case 0xc:
          *(undefined *)(iVar1 + 0x9d5) = 1;
          uVar11 = (uint)*(byte *)(iVar1 + 0x9d5);
          piVar8 = (int *)FUN_800394ac(iVar4,8,0);
          *piVar8 = (uVar11 % 10) * 0x100;
          piVar8 = (int *)FUN_800394ac(iVar4,7,0);
          *piVar8 = ((uVar11 / 10) % 10) * 0x100;
          uVar11 = uVar11 / 100;
          if (9 < uVar11) {
            uVar11 = 9;
          }
          piVar8 = (int *)FUN_800394ac(iVar4,6,0);
          *piVar8 = uVar11 << 8;
        }
      }
      *(undefined *)(iVar4 + 0x36) = *(undefined *)(iVar1 + 0x9d6);
      uVar6 = 0;
    }
    else {
      uVar6 = 1;
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dca4c + 0x14))();
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dca4c + 0xc))(0x1e,1);
      (**(code **)(*DAT_803dca54 + 0x4c))((int)*(char *)(param_3 + 0x57));
    }
    uVar6 = 0;
  }
  FUN_80286120(uVar6);
  return;
}

