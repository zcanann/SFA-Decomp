// Function: FUN_8017ff68
// Entry: 8017ff68
// Size: 884 bytes

void FUN_8017ff68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  char cVar2;
  float fVar3;
  byte bVar6;
  int iVar4;
  uint uVar5;
  int iVar7;
  int *piVar8;
  undefined8 extraout_f1;
  double dVar9;
  int iStack_48;
  uint uStack_44;
  undefined4 uStack_40;
  undefined auStack_3c [12];
  float local_30;
  undefined4 uStack_2c;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar7 = *(int *)(param_9 + 0x26);
  piVar8 = *(int **)(param_9 + 0x5c);
  if ((*piVar8 == 0) || (*(char *)((int)param_9 + 0xeb) != '\0')) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    bVar6 = FUN_8002b11c((int)param_9);
    if (bVar6 == 0) {
      cVar2 = *(char *)((int)piVar8 + 0xf);
      if (cVar2 == '\x02') {
        if (FLOAT_803e44f0 <= *(float *)(param_9 + 0x4c)) {
          iVar7 = (uint)*(byte *)(param_9 + 0x1b) + (uint)DAT_803dc070 * -2;
          if (iVar7 < 0) {
            iVar7 = 0;
            *(undefined *)((int)piVar8 + 0xf) = 3;
            fVar1 = FLOAT_803e44f4;
            dVar9 = (double)FLOAT_803e44f4;
            piVar8[1] = (int)FLOAT_803e44f4;
            piVar8[2] = (int)fVar1;
            FUN_8003042c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,
                         param_12,param_13,param_14,param_15,param_16);
            FUN_800303fc((double)FLOAT_803e44f4,(int)param_9);
          }
          *(char *)(param_9 + 0x1b) = (char)iVar7;
        }
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      }
      else if (cVar2 < '\x02') {
        if (cVar2 == '\0') {
          iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar7 + 0x14));
          if (iVar4 == 0) {
            dVar9 = (double)(**(code **)(*DAT_803dd72c + 0x6c))(*(undefined4 *)(iVar7 + 0x14));
            param_2 = DOUBLE_803e44f8;
            uStack_1c = (uint)*(ushort *)(iVar7 + 0x18);
            if (uStack_1c < 100) {
              uStack_1c = 100;
            }
            uStack_1c = uStack_1c ^ 0x80000000;
            local_20 = 0x43300000;
            fVar1 = (float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,uStack_1c) -
                                                   DOUBLE_803e44f8));
            fVar3 = FLOAT_803e44f0;
            if ((fVar1 <= FLOAT_803e44f0) && (fVar3 = fVar1, fVar1 < FLOAT_803e44f4)) {
              fVar3 = FLOAT_803e44f4;
            }
            piVar8[1] = (int)(FLOAT_803e44f0 - fVar3);
          }
          else {
            FUN_8017fd10(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,
                         *(undefined2 *)(&DAT_803dca00 + (*(byte *)(iVar7 + 0x1b) & 3) * 2));
            *(undefined *)((int)piVar8 + 0xf) = 1;
            uVar5 = FUN_80022264(300,600);
            *(short *)(piVar8 + 3) = (short)uVar5;
          }
          if (param_9[0x50] != 0) {
            FUN_8003042c((double)(float)piVar8[1],param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
          }
          FUN_800303fc((double)(float)piVar8[1],(int)param_9);
        }
        else if (-1 < cVar2) {
          FUN_8017fa4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar7
                       ,(int)piVar8);
        }
      }
      else if (cVar2 == '\x04') {
        FUN_8017f88c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     iVar7,piVar8,param_12,param_13,param_14,param_15,param_16);
      }
      else if (cVar2 < '\x04') {
        uVar5 = (uint)*(byte *)(param_9 + 0x1b) + (uint)DAT_803dc070;
        if (0xfe < uVar5) {
          uVar5 = 0xff;
          *(undefined *)((int)piVar8 + 0xf) = 0;
          uStack_1c = (uint)*(ushort *)(iVar7 + 0x18);
          local_20 = 0x43300000;
          (**(code **)(*DAT_803dd72c + 100))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4500),
                     *(undefined4 *)(iVar7 + 0x14));
        }
        *(char *)(param_9 + 0x1b) = (char)uVar5;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
      }
      FUN_8002fb40((double)(float)piVar8[2],(double)FLOAT_803dc074);
    }
    else {
      iVar7 = FUN_80036868((int)param_9,&uStack_40,&iStack_48,&uStack_44,&local_30,&uStack_2c,
                           local_28);
      if ((iVar7 != 0) && (iVar7 != 0x10)) {
        local_30 = local_30 + FLOAT_803dda58;
        local_28[0] = local_28[0] + FLOAT_803dda5c;
        FUN_8009a468(param_9,auStack_3c,1,(int *)0x0);
        FUN_8000bb38((uint)param_9,0x47b);
        FUN_8002b070((int)param_9);
      }
    }
  }
  else {
    *piVar8 = 0;
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

