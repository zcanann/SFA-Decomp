// Function: FUN_80236090
// Entry: 80236090
// Size: 1220 bytes

void FUN_80236090(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  double dVar8;
  double dVar9;
  uint uStack_58;
  int iStack_54;
  undefined4 uStack_50;
  undefined auStack_4c [12];
  float local_40;
  float local_3c;
  float local_38 [8];
  longlong local_18;
  
  piVar6 = *(int **)(param_9 + 0x5c);
  dVar9 = (double)FLOAT_803dc074;
  FUN_8002fb40((double)(float)piVar6[0x11],dVar9);
  if (*(short *)(piVar6 + 0x16) != 0) {
    if (FLOAT_803e7f90 < (float)piVar6[0xf]) {
      piVar6[0xf] = (int)((float)piVar6[0xf] - FLOAT_803dc074);
    }
    dVar8 = (double)(float)piVar6[0x11];
    if ((double)FLOAT_803e7fa4 < dVar8) {
      piVar6[0x11] = (int)(float)(dVar8 - (double)FLOAT_803e7fa8);
    }
    if ((*(ushort *)(piVar6 + 0x16) & 0x80) != 0) {
      FUN_80235eac(dVar8,dVar9,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    if ((*(ushort *)(piVar6 + 0x16) & 0x20) != 0) {
      if ((*(ushort *)(piVar6 + 0x16) & 0xc0) == 0) {
        iVar4 = FUN_80037c38(param_9,8,0xff,0xff,0x78,0x129,(float *)(piVar6 + 0x14));
      }
      else {
        iVar4 = FUN_80036868((int)param_9,&uStack_50,&iStack_54,&uStack_58,&local_40,&local_3c,
                             local_38);
      }
      if (FLOAT_803e7f90 <= (float)piVar6[0x13]) {
        piVar6[0x13] = (int)((float)piVar6[0x13] - FLOAT_803dc074);
      }
      if (((iVar4 != 0) && (iVar4 != 0x11)) && ((float)piVar6[0x13] <= FLOAT_803e7f90)) {
        if ((*(ushort *)(piVar6 + 0x16) & 0xc0) != 0) {
          local_40 = local_40 + FLOAT_803dda58;
          local_38[0] = local_38[0] + FLOAT_803dda5c;
          FUN_8009a468(param_9,auStack_4c,1,(int *)0x0);
          FUN_8002ad08(param_9,0xf,200,0,0,1);
        }
        if ((*(ushort *)(piVar6 + 0x16) & 0xf) != 0) {
          local_38[0] = (float)piVar6[0x12];
          iVar5 = (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10;
          local_40 = local_38[0] * *(float *)(&DAT_8032c838 + iVar5);
          local_3c = local_38[0] * *(float *)(&DAT_8032c83c + iVar5);
          local_38[0] = local_38[0] * *(float *)(&DAT_8032c840 + iVar5);
          FUN_80021b8c(param_9,&local_40);
          FUN_80096f20(param_9,*(ushort *)(piVar6 + 0x16) & 0xf,0x14,(int)auStack_4c,0);
        }
        piVar6[0x11] = (int)FLOAT_803e7fb0;
        piVar6[0x13] = (int)FLOAT_803e7fb4;
        if (((*(ushort *)(piVar6 + 0x16) & 0x80) != 0) && (iVar4 != 0)) {
          iVar4 = 0;
          piVar7 = piVar6;
          do {
            if ((*piVar7 != 0) &&
               (iVar5 = (**(code **)(**(int **)(*piVar7 + 0x68) + 0x28))(), 1 < iVar5)) {
              FUN_80036548(piVar6[iVar4],(int)param_9,'\x0e',1,0);
              break;
            }
            piVar7 = piVar7 + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 < 3);
        }
      }
    }
    iVar4 = FUN_8002bac4();
    if (((iVar4 != 0) && ((*(ushort *)(piVar6 + 0x16) & 0x100) == 0)) &&
       ((*(ushort *)(piVar6 + 0x16) & 0xf) != 0)) {
      fVar2 = *(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc);
      fVar3 = *(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14);
      dVar9 = FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
      uVar1 = (uint)dVar9;
      local_18 = (longlong)(int)uVar1;
      if ((uVar1 & 0xffff) < (uint)*(ushort *)(piVar6 + 0x15)) {
        if ((((*(ushort *)(piVar6 + 0x16) & 0x10) != 0) &&
            ((uint)*(ushort *)(piVar6 + 0x15) <= (uint)*(ushort *)((int)piVar6 + 0x56))) &&
           ((float)piVar6[0xf] <= FLOAT_803e7f90)) {
          local_38[0] = (float)piVar6[0x12];
          iVar4 = (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10;
          local_40 = local_38[0] * *(float *)(&DAT_8032c838 + iVar4);
          local_3c = local_38[0] * *(float *)(&DAT_8032c83c + iVar4);
          local_38[0] = local_38[0] * *(float *)(&DAT_8032c840 + iVar4);
          FUN_80021b8c(param_9,&local_40);
          FUN_80096f20(param_9,*(ushort *)(piVar6 + 0x16) & 0xf,0x14,(int)auStack_4c,1);
          piVar6[0xf] = (int)FLOAT_803e7fb8;
        }
        piVar6[0x10] = (int)((float)piVar6[0x10] - FLOAT_803dc074);
        if ((float)piVar6[0x10] <= FLOAT_803e7f90) {
          local_38[0] = (float)piVar6[0x12];
          iVar4 = (uint)*(ushort *)((int)piVar6 + 0x5a) * 0x10;
          local_40 = local_38[0] * *(float *)(&DAT_8032c838 + iVar4);
          local_3c = local_38[0] * *(float *)(&DAT_8032c83c + iVar4);
          local_38[0] = local_38[0] * *(float *)(&DAT_8032c840 + iVar4);
          FUN_80021b8c(param_9,&local_40);
          FUN_80096f20(param_9,*(ushort *)(piVar6 + 0x16) & 0xf,1,(int)auStack_4c,0);
          piVar6[0x10] = (int)((float)piVar6[0x10] + FLOAT_803e7fbc);
        }
      }
      *(short *)((int)piVar6 + 0x56) = (short)uVar1;
    }
  }
  return;
}

