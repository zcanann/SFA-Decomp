// Function: FUN_801a9cc4
// Entry: 801a9cc4
// Size: 1388 bytes

/* WARNING: Removing unreachable block (ram,0x801a9da4) */

void FUN_801a9cc4(uint param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  byte *pbVar6;
  double dVar7;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((pbVar6[1] & 1) != 0) {
    *pbVar6 = 2;
    FUN_800201ac((int)*(short *)(pbVar6 + 8),1);
    pbVar6[1] = pbVar6[1] & 0xfe;
    *(undefined *)(param_1 + 0x36) = 0xff;
  }
  if (((*(byte *)(param_1 + 0xaf) & 4) != 0) && ((*(byte *)(param_1 + 0xaf) & 8) == 0)) {
    uVar2 = FUN_80020078(0x86a);
    if (uVar2 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
  }
  pbVar6[1] = pbVar6[1] | 2;
  bVar1 = *pbVar6;
  if (bVar1 == 2) {
    iVar3 = FUN_8002ba84();
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    if ((pbVar6[1] & 2) != 0) {
      if ((pbVar6[1] & 4) != 0) {
        uVar2 = FUN_80022264(0xffffffff,1);
        *(float *)(param_1 + 0x10) =
             *(float *)(iVar4 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5280);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x70f,0,2,0xffffffff,0);
      }
      *(float *)(pbVar6 + 0x14) = *(float *)(pbVar6 + 0x14) - FLOAT_803dc074;
      if (*(float *)(pbVar6 + 0x14) <= FLOAT_803e528c) {
        uVar2 = FUN_80022264(0,1);
        if (uVar2 == 0) {
          uVar2 = FUN_80022264(0x32,200);
          *(float *)(pbVar6 + 0x14) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5280);
          pbVar6[1] = pbVar6[1] & 0xfb;
        }
        else {
          *(float *)(pbVar6 + 0x14) = FLOAT_803e5290;
          pbVar6[1] = pbVar6[1] | 4;
          FUN_8000bb38(param_1,0x438);
        }
      }
      iVar4 = FUN_8002bac4();
      if ((iVar4 == 0) ||
         (dVar7 = FUN_80021730((float *)(iVar4 + 0x18),(float *)(param_1 + 0x18)),
         (double)FLOAT_803e5294 < dVar7)) {
        FUN_80097568((double)FLOAT_803e5274,(double)FLOAT_803e529c,param_1,5,6,1,0x28,0,0);
      }
      else {
        FUN_80097568((double)FLOAT_803e5274,(double)FLOAT_803e5298,param_1,5,5,1,0x28,0,0);
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
      }
      iVar4 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar4 == 0x1a) {
        *pbVar6 = 3;
        pbVar6[0xc] = 0;
        pbVar6[0xd] = 0;
        *(float *)(pbVar6 + 0x10) = FLOAT_803e52a0;
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      *pbVar6 = 1;
      *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc) - FLOAT_803e5288;
      uVar2 = FUN_80020078((int)*(short *)(pbVar6 + 8));
      if (uVar2 != 0) {
        *pbVar6 = 2;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
        *(undefined *)(param_1 + 0x36) = 0xff;
      }
      uVar2 = FUN_80020078((int)*(short *)(pbVar6 + 10));
      if (uVar2 != 0) {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        iVar4 = *(int *)(param_1 + 0x4c);
        uVar2 = FUN_80020078((int)*(short *)(puVar5 + 8));
        if (uVar2 != 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
          FUN_800201ac((int)*(short *)(puVar5 + 10),1);
          *puVar5 = 4;
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
        }
      }
    }
    else if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
             (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x86a), iVar3 != 0)) &&
            (uVar2 = FUN_80020078(0x86a), uVar2 != 0)) {
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined *)(param_1 + 0x36) = 0;
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      FUN_800201ac(0x86a,uVar2 - 1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  else if (bVar1 < 4) {
    iVar3 = FUN_8002ba84();
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
    dVar7 = FUN_80021730((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18));
    if ((double)FLOAT_803e5294 < dVar7) {
      FUN_80097568((double)FLOAT_803e5274,(double)FLOAT_803e529c,param_1,5,6,1,0x28,0,0);
    }
    else {
      FUN_80097568((double)FLOAT_803e5274,(double)FLOAT_803e5298,param_1,5,5,1,0x28,0,0);
    }
    if (((*(float *)(pbVar6 + 0x10) <= FLOAT_803e528c) &&
        (uVar2 = FUN_80020078((int)*(short *)(pbVar6 + 8)), uVar2 != 0)) &&
       (uVar2 = FUN_80020078((int)*(short *)(pbVar6 + 10)), uVar2 == 0)) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      iVar4 = *(int *)(param_1 + 0x4c);
      uVar2 = FUN_80020078((int)*(short *)(puVar5 + 8));
      if (uVar2 != 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        FUN_800201ac((int)*(short *)(puVar5 + 10),1);
        *puVar5 = 4;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      }
    }
    *(float *)(pbVar6 + 0x10) = *(float *)(pbVar6 + 0x10) - FLOAT_803dc074;
    if (*(float *)(pbVar6 + 0x10) < FLOAT_803e528c) {
      *(float *)(pbVar6 + 0x10) = FLOAT_803e528c;
    }
  }
  return;
}

