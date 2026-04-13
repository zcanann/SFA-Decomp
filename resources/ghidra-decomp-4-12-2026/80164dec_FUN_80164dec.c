// Function: FUN_80164dec
// Entry: 80164dec
// Size: 772 bytes

/* WARNING: Removing unreachable block (ram,0x801650d0) */
/* WARNING: Removing unreachable block (ram,0x801650c8) */
/* WARNING: Removing unreachable block (ram,0x80164e04) */
/* WARNING: Removing unreachable block (ram,0x80164dfc) */

void FUN_80164dec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined auStack_58 [4];
  undefined4 uStack_54;
  uint uStack_50;
  int iStack_4c;
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  longlong local_30;
  
  iVar5 = *(int *)(param_9 + 0x5c);
  cVar1 = *(char *)(iVar5 + 0x278);
  if (cVar1 == '\0') {
    iVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_58);
    if (iVar4 != 0) {
      if (*(float *)(iVar5 + 0x26c) <= *(float *)(param_9 + 4)) {
        *(undefined *)(iVar5 + 0x278) = 1;
      }
      else {
        *(float *)(param_9 + 4) =
             *(float *)(iVar5 + 0x270) * FLOAT_803dc074 + *(float *)(param_9 + 4);
      }
    }
  }
  else if (cVar1 == '\x01') {
    iVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_58);
    if (iVar4 != 0) {
      iVar4 = *(int *)(iVar5 + 0x284);
      if (iVar4 == 0) {
        iVar4 = FUN_8002bac4();
      }
      fVar2 = *(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc);
      fVar3 = *(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14);
      dVar6 = FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
      local_48 = (double)(longlong)(int)dVar6;
      *(short *)(iVar5 + 0x268) = (short)(int)dVar6;
      if (*(ushort *)(iVar5 + 0x268) < *(ushort *)(iVar5 + 0x26a)) {
        *(undefined *)(iVar5 + 0x278) = 2;
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
        FUN_80036018((int)param_9);
      }
    }
  }
  else if (cVar1 == '\x02') {
    iVar4 = *(int *)(iVar5 + 0x284);
    if (iVar4 == 0) {
      iVar4 = FUN_8002bac4();
    }
    dVar8 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc));
    dVar7 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14));
    dVar6 = FUN_80293900((double)(float)(dVar8 * dVar8 + (double)(float)(dVar7 * dVar7)));
    local_48 = (double)(longlong)(int)dVar6;
    *(short *)(iVar5 + 0x268) = (short)(int)dVar6;
    fVar3 = FLOAT_803e3c5c;
    dVar6 = DOUBLE_803e3c28;
    fVar2 = FLOAT_803e3c1c;
    uStack_3c = (uint)*(ushort *)(iVar5 + 0x268);
    if ((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3c28) <= FLOAT_803e3c5c) {
      *(float *)(param_9 + 0x12) = -(FLOAT_803e3c1c * *(float *)(param_9 + 0x12));
      *(float *)(param_9 + 0x16) = -(fVar2 * *(float *)(param_9 + 0x16));
    }
    else {
      *(float *)(param_9 + 0x12) =
           *(float *)(param_9 + 0x12) -
           (float)(dVar8 / (double)(FLOAT_803e3c5c *
                                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3c28)
                                   ));
      local_48 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x268));
      *(float *)(param_9 + 0x16) =
           *(float *)(param_9 + 0x16) - (float)(dVar7 / (double)(fVar3 * (float)(local_48 - dVar6)))
      ;
      fVar2 = FLOAT_803e3c44;
      local_38 = (longlong)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      *(short *)(iVar5 + 0x27c) = (short)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      local_30 = (longlong)(int)(fVar2 * *(float *)(param_9 + 0x16));
      *(short *)(iVar5 + 0x27e) = (short)(int)(fVar2 * *(float *)(param_9 + 0x16));
    }
    local_40 = 0x43300000;
    FUN_80164068(param_9,iVar5);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar5);
    iVar4 = FUN_80036974((int)param_9,&uStack_54,&iStack_4c,&uStack_50);
    if (iVar4 != 0) {
      FUN_800201ac(0x642,1);
      *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 7;
    }
  }
  else {
    dVar6 = (double)*(float *)(iVar5 + 0x270);
    if ((double)FLOAT_803e3c00 < dVar6) {
      *(float *)(iVar5 + 0x270) = (float)(dVar6 - (double)FLOAT_803dc074);
    }
    else {
      FUN_8002cc9c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

