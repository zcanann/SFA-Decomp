// Function: FUN_8017fa4c
// Entry: 8017fa4c
// Size: 708 bytes

/* WARNING: Removing unreachable block (ram,0x8017fce8) */
/* WARNING: Removing unreachable block (ram,0x8017fa5c) */

void FUN_8017fa4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,int param_11)

{
  short sVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  bool bVar5;
  uint *puVar6;
  float *pfVar7;
  undefined4 *puVar8;
  float *pfVar9;
  undefined4 in_r10;
  double dVar10;
  undefined4 uStack_58;
  int iStack_54;
  uint local_50;
  undefined auStack_4c [12];
  float local_40;
  undefined4 uStack_3c;
  float local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  
  iVar2 = FUN_8002bac4();
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  puVar6 = &local_50;
  pfVar7 = &local_40;
  puVar8 = &uStack_3c;
  pfVar9 = local_38;
  iVar3 = FUN_80036868((int)param_9,&uStack_58,&iStack_54,puVar6,pfVar7,puVar8,pfVar9);
  if ((iVar3 != 0) && (local_50 != 0)) {
    if (iVar3 == 0x10) {
      FUN_8002b128(param_9,300);
    }
    else if ((0xf < iVar3) || (iVar3 != 0)) {
      FUN_8000bb38((uint)param_9,0x5c);
      *(undefined *)(param_11 + 0xf) = 4;
      *(float *)(param_11 + 8) = FLOAT_803e451c;
      FUN_8003042c((double)FLOAT_803e44f4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,3,0,puVar6,pfVar7,puVar8,pfVar9,in_r10);
      iVar3 = 0x14;
      do {
        pfVar9 = (float *)*DAT_803dd708;
        (*(code *)pfVar9[2])(param_9,0x34e,0,2,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      local_40 = local_40 + FLOAT_803dda58;
      local_38[0] = local_38[0] + FLOAT_803dda5c;
      FUN_8009a468(param_9,auStack_4c,1,(int *)0x0);
      puVar6 = (uint *)0x0;
      pfVar7 = (float *)0x0;
      puVar8 = (undefined4 *)0x1;
      FUN_8002ad08(param_9,0xf,200,0,0,1);
    }
  }
  if (*(char *)(param_11 + 0xf) == '\x01') {
    if (param_9[0x50] == 1) {
      if (*(float *)(param_9 + 0x4c) < FLOAT_803e44f0) {
        *(float *)(param_11 + 8) = FLOAT_803e4528;
      }
      else {
        *(float *)(param_11 + 8) = FLOAT_803e4524;
        FUN_8003042c((double)FLOAT_803e44f4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,4,0,puVar6,pfVar7,puVar8,pfVar9,in_r10);
      }
    }
    else {
      sVar1 = *(short *)(param_11 + 0xc) - (ushort)DAT_803dc070;
      *(short *)(param_11 + 0xc) = sVar1;
      if (sVar1 < 1) {
        uVar4 = FUN_80022264(300,600);
        *(short *)(param_11 + 0xc) = (short)uVar4;
      }
      else if (param_9[0x50] != 4) {
        *(float *)(param_11 + 8) = FLOAT_803e4524;
        uStack_2c = FUN_80022264(0,99);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        FUN_8003042c((double)(FLOAT_803e4528 *
                             (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e44f8)),
                     param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,4,0,puVar6,
                     pfVar7,puVar8,pfVar9,in_r10);
      }
    }
  }
  dVar10 = (double)FUN_800217c8((float *)(param_9 + 0xc),(float *)(iVar2 + 0x18));
  bVar5 = FUN_8000b598((int)param_9,0x40);
  if (bVar5) {
    if ((double)FLOAT_803e4530 < dVar10) {
      FUN_8000b7dc((int)param_9,0x40);
    }
  }
  else if (dVar10 < (double)FLOAT_803e452c) {
    FUN_8000bb38((uint)param_9,0x5d);
  }
  return;
}

