// Function: FUN_801814d0
// Entry: 801814d0
// Size: 552 bytes

void FUN_801814d0(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  int local_48;
  undefined auStack68 [4];
  undefined auStack64 [4];
  undefined4 local_3c;
  undefined auStack56 [12];
  float local_2c;
  undefined auStack40 [4];
  float local_24 [9];
  
  uVar7 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  iVar3 = FUN_80036770(iVar2,&local_3c,auStack64,auStack68,&local_2c,auStack40,local_24);
  if (iVar3 != 0) {
    if (iVar3 == 0x10) {
      FUN_8002b050(iVar2,300);
    }
    else {
      local_2c = local_2c + FLOAT_803dcdd8;
      local_24[0] = local_24[0] + FLOAT_803dcddc;
      if (*(char *)(param_3 + 0x20) != '\0') {
        if (iVar3 != 5) {
          FUN_8009a1dc((double)FLOAT_803e3934,iVar2,auStack56,4,0);
          iVar3 = FUN_8000b5d0(0,0x37e);
          if (iVar3 == 0) {
            FUN_8000bb18(iVar2,0x37e);
          }
          goto LAB_801816e0;
        }
        piVar4 = (int *)FUN_80036f50(0x10,&local_48);
        for (iVar3 = 0; iVar3 < local_48; iVar3 = iVar3 + 1) {
          iVar5 = FUN_80035f7c(*piVar4);
          if (iVar5 != 0) {
            fVar1 = *(float *)(*piVar4 + 0x10);
            if (((*(float *)(iVar2 + 0x10) < fVar1) &&
                (fVar1 < *(float *)(iVar2 + 0x10) + FLOAT_803dbda8)) &&
               (dVar6 = (double)FUN_80021690(*piVar4 + 0x18,iVar2 + 0x18),
               dVar6 < (double)FLOAT_803dbda4)) {
              FUN_80036450(*piVar4,local_3c,5,1,0);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      FUN_8009a1dc((double)FLOAT_803e3934,iVar2,auStack56,1,0);
      FUN_8002ac30(iVar2,0xf,200,0,0,1);
      iVar3 = FUN_8000b5d0(0,*(undefined2 *)(param_3 + 0x10));
      if (iVar3 == 0) {
        FUN_8000bb18(iVar2,*(undefined2 *)(param_3 + 0x10));
      }
      *(undefined2 *)(param_3 + 10) = 0x32;
      *(undefined *)(param_3 + 9) = 0;
      FUN_801816f8(iVar2,(int)uVar7,param_3);
      *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
      fVar1 = FLOAT_803e3938;
      *(float *)(iVar2 + 0x24) = FLOAT_803e3938;
      *(float *)(iVar2 + 0x2c) = fVar1;
      FUN_80035dac(iVar2);
      if (DAT_803dbda0 != 0) {
        FUN_80035f00(iVar2);
      }
    }
  }
LAB_801816e0:
  FUN_80286128();
  return;
}

