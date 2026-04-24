// Function: FUN_801e8968
// Entry: 801e8968
// Size: 1044 bytes

void FUN_801e8968(void)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined2 uVar5;
  int iVar4;
  int iVar6;
  int iVar7;
  double dVar8;
  float local_28 [10];
  
  puVar1 = (undefined2 *)FUN_802860dc();
  iVar7 = *(int *)(puVar1 + 0x26);
  uVar2 = FUN_8002b9ec();
  iVar6 = *(int *)(puVar1 + 0x5c);
  local_28[0] = FLOAT_803e5a64;
  if ((*(byte *)(iVar6 + 0x97) >> 6 & 1) == 0) {
    if ((char)*(byte *)(iVar6 + 0x97) < '\0') {
      *(undefined2 *)(iVar6 + 0x88) = 0xffff;
      uVar2 = FUN_8002b9ec();
      FUN_800378c4(uVar2,0x7000a,puVar1,iVar6 + 0x88);
      *(byte *)(iVar6 + 0x97) = *(byte *)(iVar6 + 0x97) & 0x7f;
      *(byte *)(iVar6 + 0x97) = *(byte *)(iVar6 + 0x97) & 0xbf | 0x40;
    }
    else {
      if (*(int *)(iVar6 + 0x90) == 0) {
        uVar2 = FUN_80036e58(9,puVar1,local_28);
        *(undefined4 *)(iVar6 + 0x90) = uVar2;
        iVar3 = *(int *)(iVar6 + 0x90);
        if (iVar3 != 0) {
          iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,*(undefined *)(iVar7 + 0x19))
          ;
          if ((iVar3 == 0) ||
             (iVar3 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x2c))
                                (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19)), iVar3 != 0))
          {
            *(byte *)(iVar6 + 0x97) = *(byte *)(iVar6 + 0x97) & 0xbf | 0x40;
            puVar1[3] = puVar1[3] | 0x4000;
            puVar1[0x58] = puVar1[0x58] | 0x8000;
            *(byte *)((int)puVar1 + 0xaf) = *(byte *)((int)puVar1 + 0xaf) | 8;
          }
          uVar5 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x3c))
                            (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19));
          *(undefined2 *)(iVar6 + 0x94) = uVar5;
        }
      }
      else {
        if ((*(byte *)((int)puVar1 + 0xaf) & 4) != 0) {
          FUN_8011f3e0(0x12);
          FUN_8012ef30((int)*(short *)(iVar6 + 0x94));
        }
        if ((*(byte *)((int)puVar1 + 0xaf) & 1) != 0) {
          iVar3 = FUN_8029689c(uVar2);
          iVar4 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x38))
                            (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19));
          (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x40))
                    (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19));
          if (puVar1[0x23] == 0x467) {
            *(float *)(puVar1 + 8) = FLOAT_803e5a68 + *(float *)(*(int *)(puVar1 + 0x26) + 0xc);
          }
          if (iVar3 < iVar4) {
            (**(code **)(*DAT_803dca54 + 0x48))(1,puVar1,0xffffffff);
          }
          else {
            FUN_8011f38c(3);
            (**(code **)(*DAT_803dca54 + 0x48))(0,puVar1,0xffffffff);
          }
          FUN_80014b3c(0,0x100);
        }
        if (puVar1[0x23] == 0x467) {
          if (FLOAT_803e5a30 < *(float *)(iVar6 + 0x40)) {
            *(float *)(iVar6 + 0x40) = *(float *)(iVar6 + 0x40) - FLOAT_803e5a30;
            if (*(byte *)(iVar6 + 0x68) < 4) {
              FUN_801f4d54(puVar1,iVar6);
            }
            else {
              *(byte *)(iVar6 + 0x68) = *(byte *)(iVar6 + 0x68) + 1;
            }
            FUN_801f4ecc(puVar1,iVar6);
          }
          dVar8 = (double)FUN_80010ee0((double)*(float *)(iVar6 + 0x40),iVar6 + 4,0);
          *(float *)(puVar1 + 6) = (float)dVar8;
          dVar8 = (double)FUN_80010ee0((double)*(float *)(iVar6 + 0x40),iVar6 + 0x14,0);
          *(float *)(puVar1 + 8) = (float)dVar8;
          dVar8 = (double)FUN_80010ee0((double)*(float *)(iVar6 + 0x40),iVar6 + 0x24,0);
          *(float *)(puVar1 + 10) = (float)dVar8;
          *(float *)(iVar6 + 0x40) =
               *(float *)(iVar6 + 0x44) * FLOAT_803db414 + *(float *)(iVar6 + 0x40);
          uVar5 = FUN_800217c0((double)(*(float *)(puVar1 + 6) - *(float *)(puVar1 + 0x40)),
                               (double)(*(float *)(puVar1 + 10) - *(float *)(puVar1 + 0x44)));
          *puVar1 = uVar5;
          (**(code **)(*DAT_803dca88 + 8))(puVar1,0x19f,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(puVar1,0x1a0,0,1,0xffffffff,0);
        }
      }
      if ((puVar1[0x23] != 0x464) && (puVar1[0x23] != 0x467)) {
        FUN_8002fa48((double)FLOAT_803e5a60,(double)FLOAT_803db414,puVar1,0);
      }
      if ((*(byte *)((int)puVar1 + 0xaf) & 8) == 0) {
        FUN_80041018(puVar1);
      }
    }
  }
  else {
    puVar1[3] = puVar1[3] | 0x4000;
    puVar1[0x58] = puVar1[0x58] | 0x8000;
    *(byte *)((int)puVar1 + 0xaf) = *(byte *)((int)puVar1 + 0xaf) | 8;
  }
  FUN_80286128();
  return;
}

