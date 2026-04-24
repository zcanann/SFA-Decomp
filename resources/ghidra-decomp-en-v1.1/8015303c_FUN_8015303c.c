// Function: FUN_8015303c
// Entry: 8015303c
// Size: 816 bytes

/* WARNING: Removing unreachable block (ram,0x8015334c) */
/* WARNING: Removing unreachable block (ram,0x8015304c) */

void FUN_8015303c(ushort *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  undefined2 *puVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar9;
  float local_38;
  float local_34;
  undefined8 local_30;
  undefined8 local_28;
  
  dVar8 = (double)FLOAT_803e3514;
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x338));
  iVar4 = (int)(dVar8 * (double)FLOAT_803dc074 + (double)(float)(local_30 - DOUBLE_803e3530));
  local_28 = (double)(longlong)iVar4;
  *(short *)(param_2 + 0x338) = (short)iVar4;
  FUN_80293778((uint)*(ushort *)(param_2 + 0x338),&local_34,&local_38);
  local_34 = local_34 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x324);
  local_38 = local_38 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x32c);
  if (*(char *)(param_2 + 0x33a) == '\0') {
    dVar9 = (double)*(float *)(param_1 + 8);
    fVar1 = *(float *)(param_2 + 0x324) - *(float *)(*(int *)(param_2 + 0x29c) + 0xc);
    fVar2 = *(float *)(param_2 + 0x32c) - *(float *)(*(int *)(param_2 + 0x29c) + 0x14);
    dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar8 <= (double)(FLOAT_803e3518 * *(float *)(param_2 + 0x2a8))) {
      *(undefined *)(param_2 + 0x33a) = 1;
      *(undefined *)(param_2 + 0x33b) = 0;
    }
  }
  else if (*(char *)(param_2 + 0x33a) == '\x01') {
    dVar7 = (double)FLOAT_803dc074;
    dVar9 = -(double)(float)((double)FLOAT_803e351c * dVar7 - (double)*(float *)(param_1 + 8));
    if ((double)(*(float *)(param_2 + 0x328) - FLOAT_803e3520) < dVar9) {
      local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x33b));
      iVar4 = (int)((double)(float)(local_28 - DOUBLE_803e3530) + dVar7);
      local_30 = (double)(longlong)iVar4;
      *(char *)(param_2 + 0x33b) = (char)iVar4;
      if (100 < *(byte *)(param_2 + 0x33b)) {
        *(undefined *)(param_2 + 0x33b) = 0;
        uVar5 = FUN_8002e144();
        if ((uVar5 & 0xff) != 0) {
          puVar3 = FUN_8002becc(0x24,0x6b5);
          *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_1 + 6);
          dVar6 = (double)FLOAT_803e3510;
          *(float *)(puVar3 + 6) = (float)(dVar6 + (double)*(float *)(param_1 + 8));
          *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_1 + 10);
          *(undefined *)(puVar3 + 2) = 1;
          *(undefined *)((int)puVar3 + 5) = 1;
          *(undefined *)(puVar3 + 3) = 0xff;
          *(undefined *)((int)puVar3 + 7) = 0xff;
          iVar4 = FUN_8002b678(dVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,puVar3);
          if (iVar4 != 0) {
            *(ushort **)(iVar4 + 0xc4) = param_1;
            FUN_8000bb38((uint)param_1,0x249);
          }
        }
      }
    }
    else {
      *(undefined *)(param_2 + 0x33a) = 2;
    }
  }
  else {
    dVar9 = (double)(FLOAT_803e3524 * FLOAT_803dc074 + *(float *)(param_1 + 8));
    if ((double)*(float *)(param_2 + 0x328) <= dVar9) {
      *(undefined *)(param_2 + 0x33a) = 0;
    }
  }
  *(float *)(param_1 + 0x12) = FLOAT_803dc078 * (local_34 - *(float *)(param_1 + 6));
  *(float *)(param_1 + 0x14) = FLOAT_803dc078 * (float)(dVar9 - (double)*(float *)(param_1 + 8));
  *(float *)(param_1 + 0x16) = FLOAT_803dc078 * (local_38 - *(float *)(param_1 + 10));
  FUN_8014d194((double)FLOAT_803e3528,(double)FLOAT_803e352c,param_1,param_2,0xf,'\0');
  *(float *)(param_2 + 0x334) = *(float *)(param_2 + 0x334) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x334) <= FLOAT_803e3500) {
    uVar5 = FUN_80022264(0x3c,0x78);
    local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(param_2 + 0x334) = (float)(local_28 - DOUBLE_803e3508);
    FUN_8000bb38((uint)param_1,0x31);
  }
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x330) <= FLOAT_803e3500) {
    *(float *)(param_2 + 0x330) = FLOAT_803e3504;
    FUN_8000bb38((uint)param_1,0x24a);
  }
  return;
}

